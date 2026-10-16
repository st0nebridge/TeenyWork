use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use compute_to_access_core::stratum::client::StratumClient;
use compute_to_access_core::stratum::job::StratumJob;
use compute_to_access_core::stratum::pool_share_target;
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio_rustls::rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

trait AsyncIo: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncIo for T {}

/// Stands in for the payout address until `/admin/config` saves one. It is not
/// a Bitcoin address: saving it, or a saved setting that turns the pool on with
/// it, is refused, and the pool client will not connect with it.
pub const UNSET_PAYOUT_ADDRESS: &str = "UNSET-PAYOUT-ADDRESS";
/// The error for any attempt to mine with `UNSET_PAYOUT_ADDRESS`.
pub const UNSET_PAYOUT_ADDRESS_ERROR: &str =
    "No payout address is set: save one through /admin/config";
pub const WORKER_NAME: &str = "C2A-Pool";
/// Most access-proof header hashes remembered at once, across the blocks live
/// jobs build on: 50,000 proofs of 16 solutions, about 35 MB at most. A proof
/// that would pass it is refused until a new block lets the old ones go.
pub const MAX_SPENT_ACCESS_PROOFS: usize = 800_000;
/// Extranonce2 widths under this many bytes are logged as a warning.
const NARROW_EXTRANONCE2_BYTES: usize = 4;

/// What `spend_access_proofs` did with a proof's qualifying hashes.
#[derive(Debug, PartialEq, Eq)]
pub enum AccessProofSpend {
    /// Enough were new; the number the proof needs are now remembered.
    Spent,
    /// Fewer than the proof needs are new: the rest have earned a token.
    AlreadyRewarded,
    /// Remembering them would pass the capacity; nothing was recorded.
    Full,
}

/// A warning for a pool whose extranonce2 width gives few work leases per
/// job: every lease takes the next value, and leases stop until the pool's
/// next job once they run out.
pub fn narrow_extranonce2_warning(size: usize) -> Option<String> {
    if size >= NARROW_EXTRANONCE2_BYTES {
        return None;
    }
    let leases = 1u64 << (8 * size);
    Some(format!(
        "The pool's extranonce2 is {size} byte(s), so each pool job has {leases} work leases; \
         a client that leases repeatedly can use them up until the next job, so rate-limit \
         the challenges the site mints"
    ))
}

#[derive(Clone)]
pub struct PoolJob {
    pub job: StratumJob,
    pub generation: u64,
    pub extranonce_1: String,
    pub extranonce_2_size: usize,
    pub difficulty: f64,
    pub share_target: [u8; 32],
    pub worker_name: String,
}

pub struct ShareSubmission {
    pub job_id: String,
    pub extranonce_2: String,
    pub n_time: u32,
    pub nonce: u32,
    pub worker_name: String,
    pub response: oneshot::Sender<Result<bool, String>>,
}

pub struct PoolClient {
    pub current_job: Option<PoolJob>,
    pub extranonce_1: String,
    pub extranonce_2_size: usize,
    pub difficulty: f64,
    pub connected: bool,
    pub authorized: bool,
    pub jobs: HashMap<String, PoolJob>,
    pub next_extranonce_2: Option<u128>,
    pub submit_sender: Option<mpsc::Sender<ShareSubmission>>,
    next_generation: u64,
    /// Header hashes that accepted access proofs used, by the previous-block
    /// hash they build on. Kept across reconnects and extranonce resets;
    /// dropped once no live job builds on that block.
    spent_access_proofs: HashMap<String, HashSet<[u8; 32]>>,
    /// Most header hashes `spent_access_proofs` holds, over all its blocks.
    pub spent_access_proof_capacity: usize,
}

impl PoolClient {
    pub fn new() -> Self {
        Self {
            current_job: None,
            extranonce_1: String::new(),
            extranonce_2_size: 0,
            difficulty: 0.0,
            connected: false,
            authorized: false,
            jobs: HashMap::new(),
            next_extranonce_2: Some(0),
            submit_sender: None,
            next_generation: 0,
            spent_access_proofs: HashMap::new(),
            spent_access_proof_capacity: MAX_SPENT_ACCESS_PROOFS,
        }
    }

    /// Installs a job from `mining.notify` once the share difficulty and
    /// extranonce1 are known; returns whether it became the current job. A new
    /// current job starts a fresh extranonce2 space and forgets spent access
    /// proofs for previous blocks no live job builds on.
    pub fn install_job(&mut self, job: StratumJob, worker_name: &str) -> Result<bool, String> {
        if job.clean_jobs {
            self.jobs.clear();
        }
        self.next_generation = self.next_generation.wrapping_add(1);
        if self.difficulty <= 0.0 || self.extranonce_1.is_empty() {
            return Ok(false);
        }
        let descriptor = PoolJob {
            job,
            generation: self.next_generation,
            extranonce_1: self.extranonce_1.clone(),
            extranonce_2_size: self.extranonce_2_size,
            difficulty: self.difficulty,
            share_target: pool_share_target(self.difficulty)?,
            worker_name: worker_name.to_string(),
        };
        self.jobs
            .insert(descriptor.job.job_id.clone(), descriptor.clone());
        self.current_job = Some(descriptor);
        self.next_extranonce_2 = Some(0);
        let live_blocks: HashSet<&str> = self
            .jobs
            .values()
            .map(|job| job.job.prev_block_hash.as_str())
            .collect();
        self.spent_access_proofs
            .retain(|block, _| live_blocks.contains(block.as_str()));
        Ok(true)
    }

    /// Remembers `required` (and always at least one) different access-proof
    /// header hashes built on `prev_block_hash` that have not been used
    /// before, the first such in `hashes`. The proof's other hashes earned
    /// nothing and are not remembered. Records nothing when fewer are new, or
    /// when the set would then hold more than its capacity.
    /// A header hash commits to the job, both extranonces, nTime and nonce, so
    /// a repeat is the same work presented again, however the lease was issued.
    pub fn spend_access_proofs(
        &mut self,
        prev_block_hash: &str,
        hashes: &[[u8; 32]],
        required: usize,
    ) -> AccessProofSpend {
        let needed = required.max(1);
        let held: usize = self.spent_access_proofs.values().map(HashSet::len).sum();
        let spent = self
            .spent_access_proofs
            .entry(prev_block_hash.to_string())
            .or_default();
        let mut fresh: Vec<[u8; 32]> = Vec::new();
        for hash in hashes {
            if fresh.len() == needed {
                break;
            }
            if !spent.contains(hash) && !fresh.contains(hash) {
                fresh.push(*hash);
            }
        }
        if fresh.len() < needed {
            return AccessProofSpend::AlreadyRewarded;
        }
        if held + needed > self.spent_access_proof_capacity {
            return AccessProofSpend::Full;
        }
        spent.extend(fresh);
        AccessProofSpend::Spent
    }

    pub fn allocate_job(&mut self) -> Result<(PoolJob, String), String> {
        let job = self
            .current_job
            .clone()
            .ok_or_else(|| "The pool has not supplied a live job".to_string())?;
        if !self.authorized {
            return Err("The pool worker is not authorized".to_string());
        }
        if !(1..=16).contains(&self.extranonce_2_size) {
            return Err("The pool supplied an unsupported extranonce2 size".to_string());
        }
        let exhausted = || {
            "Every extranonce2 value for the current pool job has been leased; \
             new work leases resume when the pool sends a new job"
                .to_string()
        };
        let value = self.next_extranonce_2.ok_or_else(exhausted)?;
        // 256^size values fit the negotiated width; a 16-byte width spans all of u128.
        let space = 1u128.checked_shl(8 * self.extranonce_2_size as u32);
        if space.is_some_and(|space| value >= space) {
            return Err(exhausted());
        }
        self.next_extranonce_2 = value.checked_add(1);
        let encoded = value.to_be_bytes();
        let extranonce_2 = hex::encode(&encoded[16 - self.extranonce_2_size..]);
        Ok((job, extranonce_2))
    }
}

/// Limits applied to one pool connection.
#[derive(Clone, Copy)]
pub struct PoolConnectionLimits {
    /// Time allowed for the subscribe and authorize exchange.
    pub handshake_timeout: Duration,
    /// Longest line accepted from the pool, newline included.
    pub max_line_bytes: usize,
}

impl Default for PoolConnectionLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(30),
            max_line_bytes: 64 * 1024,
        }
    }
}

pub async fn start_pool_connection(
    pool_state: Arc<Mutex<PoolClient>>,
    pool_host: &str,
    username_updates: &mut watch::Receiver<Option<String>>,
    pool_tls: bool,
) -> Result<(), String> {
    start_pool_connection_with(
        pool_state,
        pool_host,
        username_updates,
        pool_tls,
        PoolConnectionLimits::default(),
    )
    .await
}

pub async fn start_pool_connection_with(
    pool_state: Arc<Mutex<PoolClient>>,
    pool_host: &str,
    username_updates: &mut watch::Receiver<Option<String>>,
    pool_tls: bool,
    limits: PoolConnectionLimits,
) -> Result<(), String> {
    let username = username_updates.borrow().clone().ok_or_else(|| {
        "Pool connection is disabled until a payout address is configured".to_string()
    })?;
    if username == UNSET_PAYOUT_ADDRESS {
        return Err(UNSET_PAYOUT_ADDRESS_ERROR.to_string());
    }
    println!("Connecting to Stratum pool {pool_host}");
    // Connecting, TLS, subscribe and authorize must all finish by this deadline.
    let handshake_deadline = tokio::time::Instant::now() + limits.handshake_timeout;
    let handshake_expired = || {
        format!(
            "Stratum subscribe/authorize did not complete within {:?}",
            limits.handshake_timeout
        )
    };
    let tcp_stream = tokio::time::timeout_at(handshake_deadline, TcpStream::connect(pool_host))
        .await
        .map_err(|_| handshake_expired())?
        .map_err(|e| format!("Failed to connect to {pool_host}: {e}"))?;
    let stream: Box<dyn AsyncIo + Send + Unpin> = if pool_tls {
        let hostname = pool_host
            .rsplit_once(':')
            .map(|(hostname, _)| hostname)
            .unwrap_or(pool_host);
        let server_name = ServerName::try_from(hostname.to_string())
            .map_err(|error| format!("Invalid TLS server name: {error}"))?;
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let tls_stream = tokio::time::timeout_at(
            handshake_deadline,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| handshake_expired())?
        .map_err(|error| format!("Pool TLS handshake failed: {error}"))?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp_stream)
    };
    let (read_half, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let client = StratumClient::new();
    let worker_name = format!("{username}.{WORKER_NAME}");
    let (submit_sender, mut submit_receiver) = mpsc::channel::<ShareSubmission>(64);
    send_message(&mut writer, &client.subscribe_request()).await?;
    {
        let mut state = pool_state.lock().await;
        state.connected = true;
        state.authorized = false;
        state.extranonce_1.clear();
        state.extranonce_2_size = 0;
        state.difficulty = 0.0;
        state.jobs.clear();
        state.current_job = None;
        state.next_extranonce_2 = Some(0);
        state.submit_sender = Some(submit_sender);
    }

    let mut pending: HashMap<u64, oneshot::Sender<Result<bool, String>>> = HashMap::new();
    let mut next_request_id = 3u64;
    let mut line = Vec::new();
    let mut handshake_complete = false;
    loop {
        tokio::select! {
            changed = username_updates.changed() => {
                changed.map_err(|error| format!("Pool username update channel closed: {error}"))?;
                return Err("Pool payout address changed; reconnecting with new worker name".to_string());
            }
            _ = tokio::time::sleep_until(handshake_deadline), if !handshake_complete => {
                return Err(handshake_expired());
            }
            incoming = read_pool_line(&mut reader, &mut line, limits.max_line_bytes) => {
                incoming?;
                let message: Value = serde_json::from_slice(&line)
                    .map_err(|error| format!("Invalid Stratum JSON message: {error}"))?;
                line.clear();

                if let Some(id) = message.get("id").and_then(Value::as_u64) {
                    if let Some(response) = pending.remove(&id) {
                        let result = match message.get("error") {
                            Some(error) if !error.is_null() => Err(format!("Pool rejected share: {error}")),
                            _ => Ok(message.get("result").and_then(Value::as_bool).unwrap_or(false)),
                        };
                        let _ = response.send(result);
                        continue;
                    }
                    match id {
                        1 => {
                            if let Some(error) = message.get("error").filter(|value| !value.is_null()) {
                                return Err(format!("Stratum subscribe rejected: {error}"));
                            }
                            let result = message.get("result").and_then(Value::as_array)
                                .ok_or_else(|| "Stratum subscribe result is not an array".to_string())?;
                            if result.len() < 3 {
                                return Err("Stratum subscribe response omitted extranonce fields".to_string());
                            }
                            let extranonce_1 = result[1].as_str()
                                .ok_or_else(|| "Invalid Stratum extranonce1".to_string())?;
                            let extranonce_2_size = result[2].as_u64()
                                .ok_or_else(|| "Invalid Stratum extranonce2 size".to_string())? as usize;
                            if extranonce_1.len() % 2 != 0 || hex::decode(extranonce_1).is_err()
                                || !(1..=16).contains(&extranonce_2_size) {
                                return Err("Pool returned invalid extranonce parameters".to_string());
                            }
                            {
                                let mut state = pool_state.lock().await;
                                state.extranonce_1 = extranonce_1.to_string();
                                state.extranonce_2_size = extranonce_2_size;
                                state.next_extranonce_2 = Some(0);
                            }
                            if let Some(warning) = narrow_extranonce2_warning(extranonce_2_size) {
                                eprintln!("{warning}");
                            }
                            send_message(&mut writer, &client.authorize_request(&worker_name)).await?;
                            println!("Subscribed; authorizing worker {worker_name}");
                        }
                        2 => {
                            if let Some(error) = message.get("error").filter(|value| !value.is_null()) {
                                return Err(format!("Stratum authorization rejected: {error}"));
                            }
                            let authorized = message.get("result").and_then(Value::as_bool).unwrap_or(false);
                            pool_state.lock().await.authorized = authorized;
                            if !authorized {
                                return Err("Stratum pool did not authorize the worker".to_string());
                            }
                            handshake_complete = true;
                            println!("Stratum worker authorized");
                        }
                        _ => println!("Ignoring unknown Stratum response id {id}"),
                    }
                    continue;
                }

                match message.get("method").and_then(Value::as_str) {
                    Some("mining.set_difficulty") => {
                        let difficulty = message["params"][0].as_f64()
                            .ok_or_else(|| "Invalid Stratum share difficulty".to_string())?;
                        if !difficulty.is_finite() || difficulty <= 0.0 {
                            return Err("Stratum share difficulty must be positive".to_string());
                        }
                        pool_state.lock().await.difficulty = difficulty;
                        println!("Pool share difficulty set to {difficulty}");
                    }
                    Some("mining.set_extranonce") => {
                        let params = message.get("params").and_then(Value::as_array)
                            .ok_or_else(|| "Invalid pool extranonce notification".to_string())?;
                        let extranonce_1 = params.first().and_then(Value::as_str)
                            .ok_or_else(|| "Invalid pool extranonce1".to_string())?;
                        let extranonce_2_size = params.get(1).and_then(Value::as_u64)
                            .ok_or_else(|| "Invalid pool extranonce size".to_string())? as usize;
                        if extranonce_1.len() % 2 != 0 || hex::decode(extranonce_1).is_err()
                            || !(1..=16).contains(&extranonce_2_size) {
                            return Err("Pool sent invalid extranonce parameters".to_string());
                        }
                        let mut state = pool_state.lock().await;
                        state.extranonce_1 = extranonce_1.to_string();
                        state.extranonce_2_size = extranonce_2_size;
                        state.next_extranonce_2 = Some(0);
                        state.jobs.clear();
                        state.current_job = None;
                        drop(state);
                        if let Some(warning) = narrow_extranonce2_warning(extranonce_2_size) {
                            eprintln!("{warning}");
                        }
                    }
                    Some("mining.notify") => {
                        let job = client.parse_job_notification(&message)
                            .map_err(|error| format!("Invalid pool job notification: {error}"))?;
                        let (job_id, clean) = (job.job_id.clone(), job.is_clean());
                        if pool_state.lock().await.install_job(job, &worker_name)? {
                            println!("Received real pool job {job_id} (clean={clean})");
                        }
                    }
                    Some(method) => println!("Ignoring Stratum notification {method}"),
                    None => println!("Ignoring Stratum message without method or request id"),
                }
            }
            submission = submit_receiver.recv() => {
                let Some(submission) = submission else {
                    return Err("Stratum share-submission channel closed".to_string());
                };
                let state = pool_state.lock().await;
                let Some(job) = state.jobs.get(&submission.job_id) else {
                    let _ = submission.response.send(Err("Pool job is no longer active".to_string()));
                    continue;
                };
                if !state.authorized {
                    let _ = submission.response.send(Err("Pool worker is not authorized".to_string()));
                    continue;
                }
                if job.worker_name != submission.worker_name {
                    let _ = submission.response.send(Err("Worker name does not match pool session".to_string()));
                    continue;
                }
                let request_id = next_request_id;
                next_request_id = next_request_id.wrapping_add(1).max(3);
                let request = json!({
                    "id": request_id,
                    "method": "mining.submit",
                    "params": [
                        submission.worker_name,
                        submission.job_id,
                        submission.extranonce_2,
                        format!("{:08x}", submission.n_time),
                        format!("{:08x}", submission.nonce)
                    ]
                });
                drop(state);
                if let Err(error) = send_message(&mut writer, &request).await {
                    let _ = submission.response.send(Err(error.clone()));
                    return Err(error);
                }
                pending.insert(request_id, submission.response);
            }
        }
    }
}

/// Reads the next newline-terminated message from the pool into `line`.
///
/// Refuses a message longer than `max_line_bytes`. Cancel-safe for use in
/// `select!`: bytes move from the reader's buffer into `line` only after
/// `fill_buf` completes, with no await in between, so a cancelled read loses
/// nothing and the next call resumes where it stopped.
async fn read_pool_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max_line_bytes: usize,
) -> Result<(), String> {
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|error| format!("Failed reading from Stratum pool: {error}"))?;
        if available.is_empty() {
            return Err("Stratum pool closed the connection".to_string());
        }
        let (length, complete) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => (index + 1, true),
            None => (available.len(), false),
        };
        if line.len() + length > max_line_bytes {
            return Err(format!(
                "Stratum message exceeds the {max_line_bytes}-byte line limit"
            ));
        }
        line.extend_from_slice(&available[..length]);
        reader.consume(length);
        if complete {
            return Ok(());
        }
    }
}

async fn send_message(
    writer: &mut (impl AsyncWriteExt + Unpin),
    message: &Value,
) -> Result<(), String> {
    let mut encoded = serde_json::to_vec(message)
        .map_err(|error| format!("Failed to encode Stratum request: {error}"))?;
    encoded.push(b'\n');
    writer
        .write_all(&encoded)
        .await
        .map_err(|error| format!("Failed to send Stratum request: {error}"))
}

pub async fn maintain_pool_connection(
    pool_state: Arc<Mutex<PoolClient>>,
    pool_host: String,
    mut username_updates: watch::Receiver<Option<String>>,
    pool_tls: bool,
) {
    loop {
        let username = username_updates.borrow_and_update().clone();
        if username.is_none() {
            let mut state = pool_state.lock().await;
            state.connected = false;
            state.authorized = false;
            state.current_job = None;
            state.jobs.clear();
            state.submit_sender = None;
            drop(state);
            if username_updates.changed().await.is_err() {
                return;
            }
            continue;
        }
        if let Err(error) = start_pool_connection(
            pool_state.clone(),
            &pool_host,
            &mut username_updates,
            pool_tls,
        )
        .await
        {
            eprintln!("Stratum connection ended: {error}");
            let mut state = pool_state.lock().await;
            state.connected = false;
            state.authorized = false;
            state.current_job = None;
            state.jobs.clear();
            state.submit_sender = None;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = username_updates.changed() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compute_to_access_core::stratum::client::parse_hex_u32;
    use serde_json::json;
    use tokio::net::TcpListener;

    async fn read_message(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> Value {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }

    async fn write_message(writer: &mut tokio::io::WriteHalf<TcpStream>, value: Value) {
        let mut line = serde_json::to_vec(&value).unwrap();
        line.push(b'\n');
        writer.write_all(&line).await.unwrap();
    }

    #[test]
    fn parses_standard_stratum_v1_notify_fields() {
        let client = StratumClient::new();
        let message = json!({
            "method": "mining.notify",
            "params": [
                "job-1", "00".repeat(32), "01000000", "ffffffff",
                ["11".repeat(32)], "20000000", "170fffff", "65000000", true
            ]
        });
        let job = client.parse_job_notification(&message).unwrap();
        assert_eq!(job.job_id, "job-1");
        assert_eq!(job.coinbase_version, 0x20000000);
        assert_eq!(job.n_bits, parse_hex_u32("170fffff").unwrap());
        assert_eq!(job.n_time, parse_hex_u32("65000000").unwrap());
        assert_eq!(job.coinbase_prefix, "01000000");
        assert_eq!(job.coinbase_suffix, "ffffffff");
        assert_eq!(job.merkle_branches, vec!["11".repeat(32)]);
        assert!(job.clean_jobs);
    }

    #[tokio::test]
    async fn leases_unique_extranonce2_values() {
        let mut state = PoolClient::new();
        let job = StratumClient::new()
            .parse_job_notification(&json!({
                "method": "mining.notify",
                "params": ["job", "00".repeat(32), "aa", "bb", [], "20000000",
                    "170fffff", "65000000", true]
            }))
            .unwrap();
        state.extranonce_1 = "abcd".into();
        state.extranonce_2_size = 4;
        state.authorized = true;
        state.difficulty = 1.0;
        state.current_job = Some(PoolJob {
            job,
            generation: 1,
            extranonce_1: "abcd".into(),
            extranonce_2_size: 4,
            difficulty: 1.0,
            share_target: pool_share_target(1.0).unwrap(),
            worker_name: "address.worker".into(),
        });
        assert_eq!(state.allocate_job().unwrap().1, "00000000");
        assert_eq!(state.allocate_job().unwrap().1, "00000001");
    }

    #[tokio::test]
    async fn negotiates_job_and_correlates_pool_share_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(PoolClient::new()));
        let actor_state = state.clone();
        let (_username_sender, mut username_updates) =
            watch::channel(Some("test-address".to_string()));
        let actor = tokio::spawn(async move {
            start_pool_connection(
                actor_state,
                &address.to_string(),
                &mut username_updates,
                false,
            )
            .await
        });

        let (socket, _) = listener.accept().await.unwrap();
        let (read, mut write) = tokio::io::split(socket);
        let mut reader = BufReader::new(read);

        let subscribe = read_message(&mut reader).await;
        assert_eq!(subscribe["method"], "mining.subscribe");
        write_message(
            &mut write,
            json!({"id": 1, "result": [[], "aabb", 4], "error": null}),
        )
        .await;
        let authorize = read_message(&mut reader).await;
        assert_eq!(authorize["method"], "mining.authorize");
        assert_eq!(authorize["params"][0], "test-address.C2A-Pool");
        write_message(&mut write, json!({"id": 2, "result": true, "error": null})).await;
        write_message(
            &mut write,
            json!({"id": null, "method": "mining.set_difficulty", "params": [100000]}),
        )
        .await;
        write_message(
            &mut write,
            json!({
                "id": null,
                "method": "mining.notify",
                "params": [
                    "job-1", "00".repeat(32), "01000000", "ffffffff", [],
                    "20000000", "170fffff", "65000000", true
                ]
            }),
        )
        .await;

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.lock().await.current_job.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let sender = state.lock().await.submit_sender.clone().unwrap();
        let (response, result) = oneshot::channel();
        sender
            .send(ShareSubmission {
                job_id: "job-1".into(),
                extranonce_2: "00000001".into(),
                n_time: 0x65000000,
                nonce: 42,
                worker_name: "test-address.C2A-Pool".into(),
                response,
            })
            .await
            .unwrap();
        let submit = read_message(&mut reader).await;
        assert_eq!(submit["id"], 3);
        assert_eq!(submit["method"], "mining.submit");
        assert_eq!(
            submit["params"],
            json!([
                "test-address.C2A-Pool",
                "job-1",
                "00000001",
                "65000000",
                "0000002a"
            ])
        );
        write_message(&mut write, json!({"id": 3, "result": true, "error": null})).await;
        assert!(result.await.unwrap().unwrap());
        actor.abort();
    }

    fn notify(job_id: &str, prev_block_hash: &str, clean: bool) -> StratumJob {
        StratumClient::new()
            .parse_job_notification(&json!({
                "method": "mining.notify",
                "params": [job_id, prev_block_hash, "aa", "bb", [], "20000000",
                    "170fffff", "65000000", clean]
            }))
            .unwrap()
    }

    fn authorized_pool(extranonce_2_size: usize) -> PoolClient {
        let mut state = PoolClient::new();
        state.extranonce_1 = "abcd".into();
        state.extranonce_2_size = extranonce_2_size;
        state.authorized = true;
        state.difficulty = 1.0;
        state
            .install_job(notify("job-1", &"00".repeat(32), true), "address.worker")
            .unwrap();
        state
    }

    #[test]
    fn extranonce2_leases_stop_at_the_negotiated_width() {
        let mut one_byte = authorized_pool(1);
        for value in 0..=255u32 {
            assert_eq!(one_byte.allocate_job().unwrap().1, format!("{value:02x}"));
        }
        let refused = one_byte
            .allocate_job()
            .err()
            .expect("the 257th one-byte lease is refused");
        assert!(refused.contains("extranonce2"), "{refused}");

        let mut two_bytes = authorized_pool(2);
        two_bytes.next_extranonce_2 = Some(0xfffe);
        assert_eq!(two_bytes.allocate_job().unwrap().1, "fffe");
        assert_eq!(two_bytes.allocate_job().unwrap().1, "ffff");
        assert!(
            two_bytes.allocate_job().is_err(),
            "2 bytes must not wrap to 0000"
        );

        let mut sixteen_bytes = authorized_pool(16);
        assert_eq!(sixteen_bytes.allocate_job().unwrap().1, "00".repeat(16));
        sixteen_bytes.next_extranonce_2 = Some(u128::MAX);
        assert_eq!(sixteen_bytes.allocate_job().unwrap().1, "ff".repeat(16));
        assert!(sixteen_bytes.allocate_job().is_err());
    }

    #[test]
    fn a_new_job_restarts_the_extranonce2_space() {
        let mut state = authorized_pool(1);
        state.next_extranonce_2 = Some(256);
        assert!(state.allocate_job().is_err());
        assert!(state
            .install_job(notify("job-2", &"00".repeat(32), false), "address.worker")
            .unwrap());
        assert_eq!(state.allocate_job().unwrap().1, "00");
    }

    #[test]
    fn spent_access_proofs_survive_resets_until_the_chain_moves_on() {
        use AccessProofSpend::{AlreadyRewarded, Spent};
        let block_a = "0a".repeat(32);
        let block_b = "0b".repeat(32);
        let mut state = authorized_pool(4);
        state
            .install_job(notify("job-a", &block_a, true), "address.worker")
            .unwrap();
        let hash = [7u8; 32];
        assert_eq!(state.spend_access_proofs(&block_a, &[hash], 1), Spent);
        assert_eq!(
            state.spend_access_proofs(&block_a, &[hash], 1),
            AlreadyRewarded,
            "a spent proof is refused"
        );
        assert_eq!(
            state.spend_access_proofs(&block_a, &[hash, [8u8; 32]], 1),
            Spent,
            "a proof with enough unspent qualifying hashes is new work"
        );
        assert_eq!(
            state.spend_access_proofs(&block_a, &[hash, [8u8; 32], [9u8; 32]], 2),
            AlreadyRewarded,
            "spent hashes do not make up the number a proof needs"
        );
        assert_eq!(
            state.spend_access_proofs(&block_a, &[[9u8; 32], [10u8; 32]], 2),
            Spent,
            "a refused proof spends nothing"
        );
        assert_eq!(
            state.spend_access_proofs(&block_a, &[[11u8; 32], [11u8; 32]], 2),
            AlreadyRewarded,
            "a hash given twice counts once"
        );

        state.next_extranonce_2 = Some(0);
        state.jobs.clear();
        state.current_job = None;
        state
            .install_job(notify("job-a2", &block_a, true), "address.worker")
            .unwrap();
        assert_eq!(
            state.spend_access_proofs(&block_a, &[hash], 1),
            AlreadyRewarded,
            "a reset with the same previous block keeps the spent set"
        );

        state
            .install_job(notify("job-b", &block_b, true), "address.worker")
            .unwrap();
        assert_eq!(
            state.spend_access_proofs(&block_a, &[hash], 1),
            Spent,
            "work on a replaced previous block is forgotten"
        );
        assert_eq!(
            state.spend_access_proofs(&block_b, &[], 1),
            AlreadyRewarded,
            "no qualifying hash, no token"
        );
        assert_eq!(
            state.spend_access_proofs(&block_b, &[], 0),
            AlreadyRewarded,
            "a proof always needs at least one hash"
        );
    }

    #[test]
    fn a_proof_remembers_only_the_solutions_it_needs() {
        use AccessProofSpend::{AlreadyRewarded, Spent};
        let block = "0a".repeat(32);
        let mut state = authorized_pool(4);
        state
            .install_job(notify("job-a", &block, true), "address.worker")
            .unwrap();
        let hashes: Vec<[u8; 32]> = (0..32u8).map(|byte| [byte; 32]).collect();
        assert_eq!(state.spend_access_proofs(&block, &hashes, 16), Spent);
        assert_eq!(state.spent_access_proofs[&block].len(), 16);
        assert_eq!(
            state.spend_access_proofs(&block, &hashes[..16], 16),
            AlreadyRewarded,
            "the first sixteen earned the token"
        );
        assert_eq!(
            state.spend_access_proofs(&block, &hashes[16..], 16),
            Spent,
            "the other sixteen never earned one"
        );
    }

    #[test]
    fn the_spent_set_is_capped_and_a_refused_proof_records_nothing() {
        use AccessProofSpend::{AlreadyRewarded, Full, Spent};
        assert_eq!(
            PoolClient::new().spent_access_proof_capacity,
            MAX_SPENT_ACCESS_PROOFS
        );
        let block_a = "0a".repeat(32);
        let block_b = "0b".repeat(32);
        let block_c = "0c".repeat(32);
        let mut state = authorized_pool(4);
        state
            .install_job(notify("job-a", &block_a, true), "address.worker")
            .unwrap();
        state.spent_access_proof_capacity = 3;
        assert_eq!(
            state.spend_access_proofs(&block_a, &[[1; 32], [2; 32]], 2),
            Spent
        );
        assert_eq!(
            state.spend_access_proofs(&block_a, &[[3; 32], [4; 32]], 2),
            Full,
            "two more would make four"
        );
        assert_eq!(
            state.spend_access_proofs(&block_a, &[[3; 32]], 1),
            Spent,
            "the refused proof recorded nothing, and a third fits"
        );
        assert_eq!(state.spend_access_proofs(&block_a, &[[4; 32]], 1), Full);
        assert_eq!(
            state.spend_access_proofs(&block_a, &[[1; 32]], 1),
            AlreadyRewarded,
            "a replay is refused as one even when the set is full"
        );

        state
            .install_job(notify("job-b", &block_b, false), "address.worker")
            .unwrap();
        assert_eq!(
            state.spend_access_proofs(&block_b, &[[4; 32]], 1),
            Full,
            "solutions on a block a live job still builds on count"
        );
        state
            .install_job(notify("job-c", &block_c, true), "address.worker")
            .unwrap();
        assert_eq!(
            state.spend_access_proofs(&block_c, &[[4; 32], [5; 32], [6; 32]], 3),
            Spent,
            "a new block lets the old blocks' solutions go"
        );
    }

    #[test]
    fn an_extranonce2_under_four_bytes_is_warned_about() {
        for (size, leases) in [(1, "256"), (2, "65536"), (3, "16777216")] {
            let warning = narrow_extranonce2_warning(size)
                .unwrap_or_else(|| panic!("{size} bytes are warned about"));
            assert!(
                warning.contains(&format!("{leases} work leases")),
                "{warning}"
            );
        }
        for size in 4..=16 {
            assert_eq!(narrow_extranonce2_warning(size), None, "{size} bytes");
        }
    }

    async fn run_against_pool<F, Fut>(
        limits: PoolConnectionLimits,
        pool: F,
    ) -> (Result<(), String>, Arc<Mutex<PoolClient>>)
    where
        F: FnOnce(
                BufReader<tokio::io::ReadHalf<TcpStream>>,
                tokio::io::WriteHalf<TcpStream>,
            ) -> Fut
            + Send
            + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let pool_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (read, write) = tokio::io::split(socket);
            pool(BufReader::new(read), write).await;
        });
        let state = Arc::new(Mutex::new(PoolClient::new()));
        let (username_sender, mut username_updates) =
            watch::channel(Some("test-address".to_string()));
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            start_pool_connection_with(
                state.clone(),
                &address.to_string(),
                &mut username_updates,
                false,
                limits,
            ),
        )
        .await
        .unwrap_or_else(|_| Err("TEST TIMEOUT: the client never gave up".to_string()));
        pool_task.abort();
        drop(username_sender);
        (result, state)
    }

    #[tokio::test]
    async fn the_unset_payout_address_never_reaches_the_pool() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(PoolClient::new()));
        let (_username_sender, mut username_updates) =
            watch::channel(Some(UNSET_PAYOUT_ADDRESS.to_string()));
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            start_pool_connection_with(
                state.clone(),
                &address.to_string(),
                &mut username_updates,
                false,
                PoolConnectionLimits::default(),
            ),
        )
        .await
        .unwrap_or_else(|_| Err("TEST TIMEOUT: the client waited on the pool".to_string()));
        assert_eq!(result.unwrap_err(), UNSET_PAYOUT_ADDRESS_ERROR);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "the client connected to the pool"
        );
        assert!(!state.lock().await.connected);
    }

    #[tokio::test]
    async fn a_subscribe_result_that_is_not_an_array_ends_the_connection() {
        let (result, _) = run_against_pool(
            PoolConnectionLimits::default(),
            |mut reader, mut write| async move {
                read_message(&mut reader).await;
                write_message(&mut write, json!({"id": 1, "result": true, "error": null})).await;
                std::future::pending::<()>().await;
            },
        )
        .await;
        let error = result.unwrap_err();
        assert!(error.contains("subscribe"), "{error}");
    }

    #[tokio::test]
    async fn an_overlong_pool_line_ends_the_connection() {
        let limits = PoolConnectionLimits::default();
        let (result, _) = run_against_pool(limits, move |mut reader, mut write| async move {
            read_message(&mut reader).await;
            write
                .write_all(&vec![b'a'; limits.max_line_bytes + 4096])
                .await
                .unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        let error = result.unwrap_err();
        assert!(error.contains("exceeds"), "{error}");
    }

    #[tokio::test]
    async fn a_pool_that_never_completes_the_handshake_is_dropped() {
        let limits = PoolConnectionLimits {
            handshake_timeout: Duration::from_millis(300),
            ..PoolConnectionLimits::default()
        };
        let (silent, _) = run_against_pool(limits, |mut reader, write| async move {
            read_message(&mut reader).await;
            let _keep_open = write;
            std::future::pending::<()>().await;
        })
        .await;
        let error = silent.unwrap_err();
        assert!(error.contains("did not complete"), "{error}");

        let (subscribed_only, _) = run_against_pool(limits, |mut reader, mut write| async move {
            read_message(&mut reader).await;
            write_message(
                &mut write,
                json!({"id": 1, "result": [[], "aabb", 4], "error": null}),
            )
            .await;
            read_message(&mut reader).await;
            std::future::pending::<()>().await;
        })
        .await;
        let error = subscribed_only.unwrap_err();
        assert!(error.contains("did not complete"), "{error}");
    }

    #[tokio::test]
    async fn the_handshake_timeout_stops_once_the_worker_is_authorized() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(PoolClient::new()));
        let actor_state = state.clone();
        let (_username_sender, mut username_updates) =
            watch::channel(Some("test-address".to_string()));
        let limits = PoolConnectionLimits {
            handshake_timeout: Duration::from_millis(300),
            ..PoolConnectionLimits::default()
        };
        let actor = tokio::spawn(async move {
            start_pool_connection_with(
                actor_state,
                &address.to_string(),
                &mut username_updates,
                false,
                limits,
            )
            .await
        });
        let (socket, _) = listener.accept().await.unwrap();
        let (read, mut write) = tokio::io::split(socket);
        let mut reader = BufReader::new(read);
        read_message(&mut reader).await;
        write_message(
            &mut write,
            json!({"id": 1, "result": [[], "aabb", 4], "error": null}),
        )
        .await;
        read_message(&mut reader).await;
        write_message(&mut write, json!({"id": 2, "result": true, "error": null})).await;

        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(
            !actor.is_finished(),
            "an authorized connection outlives the handshake timeout"
        );
        assert!(state.lock().await.authorized);
        actor.abort();
    }
}

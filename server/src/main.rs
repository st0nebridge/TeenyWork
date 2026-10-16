use actix_web::web::Query;
use actix_web::Error;
use actix_web::{web, App, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use compute_to_access_core::challenge::issue::{issue_challenge, Challenge};
use compute_to_access_core::challenge::verify::verify_challenge;
use compute_to_access_core::proof::bitcoin::sha256d;
use compute_to_access_core::stratum::{
    block_header_for_share, meets_access_bits, meets_difficulty_target, target_hex,
};
use compute_to_access_core::token::access_token::{issue_access_token, AccessToken};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use subtle::ConstantTimeEq;
use tokio::sync::{watch, Mutex, RwLock};
mod activity;
mod expiring;
mod ledger;
mod stratum_client;

use activity::{ActivityKind, ActivityLog, ActivityRecord, Analytics};
use expiring::{Expiring, ExpiringTable};

const WORK_LEASE_SECONDS: i64 = 90;
const MAX_WORK_RUNTIME_SECONDS: u64 = 60;
const HIGH_CONFIDENCE_BOT_DIFFICULTY_BONUS: u64 = 4;
const MAX_CHALLENGER_DIFFICULTY: u64 = 24;
/// A lease asks for 2^4 = 16 solutions of 4 bits fewer than the challenge's
/// work (`access_work_split`).
const ACCESS_SOLUTION_SHIFT: u64 = 4;
/// An access token authorizes exactly one successful protected call.
const ACCESS_TOKEN_USES: u64 = 1;
/// Most live challenges held at once; each lives 15 minutes.
const MAX_LIVE_CHALLENGES: usize = 50_000;
/// Most live work leases held at once; each lives 90 seconds.
const MAX_LIVE_LEASES: usize = 20_000;
/// Most work leases one challenge is given. Each takes an extranonce2, so the
/// cap ties a client's use of a job's range to the challenges the site mints.
const MAX_LEASES_PER_CHALLENGE: usize = 8;
/// Most unused access-token grants held at once; each lives an hour.
const MAX_LIVE_ACCESS_TOKENS: usize = 50_000;
/// Largest JSON request body accepted. A proof with 32 candidates is under 8 KiB.
const MAX_JSON_BODY_BYTES: usize = 64 * 1024;
const AT_CAPACITY: &str = "The Challenger is at capacity; try again shortly";
/// The demo page's pool search proves work for this resource. Its proofs are
/// checked, recorded and forwarded like any other, but earn no token, which
/// nothing would redeem.
const POOL_SEARCH_RESOURCE: &str = "/pool/share-search";

#[derive(Clone, Deserialize, Serialize)]
pub struct PoolRuntimeConfig {
    payout_address: String,
    required_work_units: u64,
    #[serde(default)]
    pool_enabled: bool,
}

impl PoolRuntimeConfig {
    fn validate(&self) -> Result<(), String> {
        if self.payout_address == stratum_client::UNSET_PAYOUT_ADDRESS {
            // The placeholder stands in only while the pool is off.
            if self.pool_enabled {
                return Err(stratum_client::UNSET_PAYOUT_ADDRESS_ERROR.into());
            }
        } else if !valid_payout_address(&self.payout_address) {
            return Err("Payout address must be a 26-90 character Bitcoin mainnet address".into());
        }
        if !(8..=24).contains(&self.required_work_units) {
            return Err("Challenger difficulty must be between 8 and 24 bits".into());
        }
        Ok(())
    }
}

fn valid_payout_address(address: &str) -> bool {
    let is_base58 = (address.starts_with('1') || address.starts_with('3'))
        && (26..=35).contains(&address.len())
        && address.bytes().all(|byte| {
            b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&byte)
        });
    let is_bech32 = address
        .get(..3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bc1"))
        && (14..=90).contains(&address.len())
        && (address == address.to_ascii_lowercase() || address == address.to_ascii_uppercase())
        && address.bytes().all(|byte| {
            b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".contains(&byte)
        });

    is_base58 || is_bech32
}

fn challenge_work_units(configured: u64, high_confidence_bot: bool) -> u64 {
    if high_confidence_bot {
        configured
            .saturating_add(HIGH_CONFIDENCE_BOT_DIFFICULTY_BONUS)
            .min(MAX_CHALLENGER_DIFFICULTY)
    } else {
        configured
    }
}

/// Splits a challenge's work of `work_bits` into (bits per solution, number
/// of solutions). Sixteen solutions of `work_bits - 4` bits cost the same
/// hashes on average as one of `work_bits`, but the time a solve takes varies
/// far less: with one solution, 1 search in 20 takes three times the average;
/// with sixteen, almost none. Work under 5 bits keeps at least one bit per
/// solution.
fn access_work_split(work_bits: u64) -> (u64, usize) {
    let shift = ACCESS_SOLUTION_SHIFT.min(work_bits.saturating_sub(1));
    (work_bits - shift, 1 << shift)
}

fn access_difficulty_for_resource(resource: &str, configured: u64) -> Option<u64> {
    match resource.split('?').next().unwrap_or(resource) {
        "/" => None,
        path if path.starts_with("/search") => Some(configured.max(14)),
        path if path.starts_with("/report") => Some(configured.max(16)),
        path if path.starts_with("/bulk") => Some(configured.max(18)),
        _ => Some(configured),
    }
}

/// Whether a proof for `resource` earns an access token: every resource but
/// the demo's pool search, with or without a query string, does.
fn earns_access_token(resource: &str) -> bool {
    resource.split('?').next() != Some(POOL_SEARCH_RESOURCE)
}

fn load_pool_runtime_config(
    path: &PathBuf,
    default_address: String,
) -> io::Result<PoolRuntimeConfig> {
    let config = if path.exists() {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str::<PoolRuntimeConfig>(&content).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid Challenger configuration {}: {error}",
                    path.display()
                ),
            )
        })?
    } else {
        PoolRuntimeConfig {
            payout_address: default_address,
            required_work_units: 12,
            pool_enabled: false,
        }
    };
    config
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(config)
}

fn persist_pool_runtime_config(path: &PathBuf, config: &PoolRuntimeConfig) -> io::Result<()> {
    let temporary_path = path.with_extension("json.tmp");
    let encoded = serde_json::to_vec(config).map_err(io::Error::other)?;
    let mut file = std::fs::File::create(&temporary_path)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    std::fs::rename(temporary_path, path)
}

#[derive(Deserialize, Serialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub resource: String,
    pub issued_at: String,
    pub expires_at: String,
    pub required_work_units: u64,
    pub algorithm: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct ProofRequest {
    pub challenge_id: String,
    pub lease_id: String,
    pub worker_id: String,
    pub candidates: Vec<ProofCandidate>,
    pub hashes_attempted: u64,
    pub elapsed_ms: u64,
}

#[derive(Deserialize)]
pub struct ProofCandidate {
    pub header_hash: String,
    pub extranonce_2: String,
    pub n_time: u32,
    pub nonce: u32,
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub resource: String,
    #[serde(default)]
    pub high_confidence_bot: bool,
}

#[derive(Deserialize)]
pub struct AdminConfigRequest {
    pub payout_address: String,
    pub required_work_units: u64,
}

#[derive(Deserialize)]
pub struct LeaseRequest {
    pub challenge_id: String,
    pub worker_id: String,
}

#[derive(Deserialize)]
pub struct ContactFormRequest {
    pub name: String,
    pub email: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct ProtectedQuery {
    pub token: Option<String>,
    pub resource: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct TokenResponse {
    /// The access token and its expiry; `None` for a pool-search proof,
    /// which earns no token.
    pub token: Option<String>,
    pub credits_remaining: u64,
    pub expiry: Option<String>,
    pub pool_share: String,
}

/// A live challenge and the number of work leases it has been given.
#[derive(Clone)]
pub struct HeldChallenge {
    pub challenge: Challenge,
    pub leases_issued: usize,
}

#[derive(Clone)]
pub struct WorkLease {
    pub lease_id: String,
    pub challenge_id: String,
    pub worker_id: String,
    pub expires_at: DateTime<Utc>,
    pub pool_job: stratum_client::PoolJob,
    pub extranonce_2: String,
    /// The challenge's whole work, in bits; recorded with the lease's activity.
    pub work_units: u64,
    /// Each solution's leading zero bits, and how many different solutions a
    /// proof must carry (`access_work_split`).
    pub solution_bits: u64,
    pub solutions: usize,
}

/// A single-use grant: the first successful use for its resource removes it.
/// The challenge it was earned on is kept so the verification can be recorded.
#[derive(Clone)]
pub struct AccessGrant {
    pub resource: String,
    pub expires_at: DateTime<Utc>,
    pub challenge_id: String,
    pub work_units: u64,
}

impl Expiring for HeldChallenge {
    fn expires_at(&self) -> DateTime<Utc> {
        self.challenge.expires_at
    }
}

impl Expiring for WorkLease {
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl Expiring for AccessGrant {
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

async fn record_activity(
    app: &AppState,
    event: ActivityKind,
    challenge_id: Option<&str>,
    work_units: Option<u64>,
) -> io::Result<()> {
    app.activity_log
        .append(ActivityRecord {
            occurred_at: Utc::now(),
            event,
            challenge_id: challenge_id.map(str::to_string),
            work_units,
        })
        .await?;
    app.analytics.record(event);
    Ok(())
}

pub struct AppState {
    pub server_secret: Arc<Vec<u8>>,
    pub stratum_pool: Arc<Mutex<stratum_client::PoolClient>>,
    pub challenges: Arc<Mutex<ExpiringTable<HeldChallenge>>>,
    /// Live work leases by challenge ID: a challenge has at most one.
    pub leases: Arc<Mutex<ExpiringTable<WorkLease>>>,
    pub access_tokens: Arc<Mutex<ExpiringTable<AccessGrant>>>,
    pub analytics: Arc<Analytics>,
    activity_log: Arc<ActivityLog>,
    pub api_key: Option<Arc<String>>,
    pub submitted_shares: Arc<Mutex<HashSet<String>>>,
    pub share_ledger: Arc<StdMutex<ledger::LedgerFile>>,
    pub pool_runtime_config: Arc<RwLock<PoolRuntimeConfig>>,
    pub pool_username_updates: watch::Sender<Option<String>>,
    pub pool_config_path: Arc<PathBuf>,
    /// Directory the allowed browser assets are served from.
    pub browser_dir: Arc<PathBuf>,
}

/// The secrets the server starts with, and any warnings about them.
struct StartupSecrets {
    server_secret: Vec<u8>,
    api_key: Option<String>,
    warnings: Vec<String>,
}

/// The placeholder values `.env.example` ships; the server refuses to start
/// with either.
const PLACEHOLDER_SERVER_SECRET: &str = "replace-with-an-independent-random-secret";
const PLACEHOLDER_API_KEY: &str = "replace-with-a-separate-random-token";
const MIN_SERVER_SECRET_BYTES: usize = 32;
/// Shorter API keys are accepted with a warning, never refused.
const RECOMMENDED_API_KEY_CHARS: usize = 32;

/// Checks the configured secrets. The server secret must be at least 32 bytes
/// and not the `.env.example` placeholder. The API key is optional; if set it
/// must not be empty or the placeholder, and a key shorter than 32 characters
/// only produces a warning so a production restart never fails over its length.
fn validate_startup_secrets(
    server_secret: Option<&str>,
    api_key: Option<&str>,
) -> Result<StartupSecrets, String> {
    let server_secret = server_secret
        .filter(|secret| secret.len() >= MIN_SERVER_SECRET_BYTES)
        .ok_or("C2A_SERVER_SECRET must be configured with at least 32 bytes")?;
    if server_secret == PLACEHOLDER_SERVER_SECRET {
        return Err(
            "C2A_SERVER_SECRET is still the .env.example placeholder; set an independent random secret"
                .to_string(),
        );
    }
    let mut warnings = Vec::new();
    if let Some(key) = api_key {
        if key.trim().is_empty() {
            return Err(
                "C2A_API_KEY is set but empty; set a random key, or unset it to disable the admin API"
                    .to_string(),
            );
        }
        if key == PLACEHOLDER_API_KEY {
            return Err(
                "C2A_API_KEY is still the .env.example placeholder; set a separate random key"
                    .to_string(),
            );
        }
        if key.chars().count() < RECOMMENDED_API_KEY_CHARS {
            warnings.push(format!(
                "C2A_API_KEY is shorter than {RECOMMENDED_API_KEY_CHARS} characters; \
                 use a longer random key"
            ));
        }
    }
    Ok(StartupSecrets {
        server_secret: server_secret.as_bytes().to_vec(),
        api_key: api_key.map(str::to_string),
        warnings,
    })
}

/// `C2A_POOL_TLS`: TLS unless it is set to `false`. Only `true` and `false`
/// (in any case) are accepted, so a typo, `0` or `no` cannot silently connect
/// to the pool in plaintext, where anyone on the path could swap the jobs.
fn pool_tls_setting(value: Option<&str>) -> Result<bool, String> {
    match value.map(str::trim) {
        None => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(value) => Err(format!("C2A_POOL_TLS must be true or false, not {value:?}")),
    }
}

/// An environment variable as text: `None` when unset, an error when it is
/// not valid Unicode.
fn env_text(name: &str) -> io::Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be valid Unicode"),
        )),
    }
}

#[derive(Serialize, Deserialize)]
struct ShareLedgerRecord {
    share_id: String,
    challenge_id: String,
    lease_id: String,
    job_id: String,
    nonce: u32,
    extranonce_2: String,
    header_hash: String,
    status: String,
    recorded_at: DateTime<Utc>,
}

fn record_share(ledger: &mut ledger::LedgerFile, record: ShareLedgerRecord) -> io::Result<()> {
    ledger.append(&record, || Ok(None))
}

/// Records a share on the blocking thread pool, so its disk sync never stalls
/// the async runtime.
async fn record_share_off_runtime(
    ledger: &Arc<StdMutex<ledger::LedgerFile>>,
    record: ShareLedgerRecord,
) -> io::Result<()> {
    let ledger = ledger.clone();
    tokio::task::spawn_blocking(move || {
        record_share(
            &mut ledger.lock().unwrap_or_else(PoisonError::into_inner),
            record,
        )
    })
    .await
    .map_err(io::Error::other)?
}

/// Opens the share ledger and rebuilds the set of shares already forwarded from
/// the live file and its retained rotated files, skipping malformed lines. A
/// share old enough to have been rotated out refers to a pool job that is no
/// longer live, which `/api/proof` already refuses before forwarding.
fn load_share_ledger(
    path: &Path,
    max_bytes: u64,
) -> io::Result<(ledger::LedgerFile, HashSet<String>, u64)> {
    let mut submitted_shares = HashSet::new();
    let mut skipped_lines = 0;
    for file in ledger::retained_paths(path) {
        skipped_lines += ledger::replay_file(&file, |line| {
            let record: ShareLedgerRecord =
                serde_json::from_slice(line).map_err(|error| error.to_string())?;
            submitted_shares.insert(record.share_id);
            Ok(())
        })?;
    }
    let share_ledger = ledger::LedgerFile::open(path, max_bytes)?;
    Ok((share_ledger, submitted_shares, skipped_lines))
}

fn report_skipped_ledger_lines(name: &str, path: &Path, skipped_lines: u64) {
    if skipped_lines > 0 {
        eprintln!(
            "warning: {name} ledger {}: skipped {skipped_lines} malformed line(s) at startup",
            path.display()
        );
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let secrets = validate_startup_secrets(
        env_text("C2A_SERVER_SECRET")?.as_deref(),
        env_text("C2A_API_KEY")?.as_deref(),
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    for warning in &secrets.warnings {
        eprintln!("warning: {warning}");
    }
    let server_secret = Arc::new(secrets.server_secret);
    let pool_host =
        std::env::var("C2A_POOL_HOST").unwrap_or_else(|_| "public-pool.io:14333".to_string());
    let pool_tls = pool_tls_setting(env_text("C2A_POOL_TLS")?.as_deref())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let default_pool_username = std::env::var("C2A_POOL_USERNAME")
        .unwrap_or_else(|_| stratum_client::UNSET_PAYOUT_ADDRESS.to_string());
    let api_key = secrets.api_key.map(Arc::new);
    let browser_dir = Arc::new(PathBuf::from("browser"));
    let pool_config_path = PathBuf::from(
        std::env::var("C2A_CONFIG_FILE").unwrap_or_else(|_| "c2a-config.json".to_string()),
    );
    let loaded_pool_config = load_pool_runtime_config(&pool_config_path, default_pool_username)?;
    let initial_pool_username = loaded_pool_config
        .pool_enabled
        .then(|| loaded_pool_config.payout_address.clone());
    let (pool_username_updates, pool_username_receiver) = watch::channel(initial_pool_username);
    let runtime_config = Arc::new(RwLock::new(loaded_pool_config));
    let ledger_max_bytes = ledger::max_bytes_from_env()?;
    let ledger_path = PathBuf::from(
        std::env::var("C2A_SHARE_LEDGER").unwrap_or_else(|_| "c2a-share-ledger.jsonl".to_string()),
    );
    let (share_ledger, submitted_shares, share_lines_skipped) =
        load_share_ledger(&ledger_path, ledger_max_bytes)?;
    report_skipped_ledger_lines("share", &ledger_path, share_lines_skipped);
    let submitted_shares = Arc::new(Mutex::new(submitted_shares));
    let share_ledger = Arc::new(StdMutex::new(share_ledger));
    let activity_path = PathBuf::from(
        std::env::var("C2A_ACTIVITY_LEDGER").unwrap_or_else(|_| "c2a-activity.jsonl".to_string()),
    );
    let (activity_log, analytics) =
        ActivityLog::load_with_max_bytes(&activity_path, ledger_max_bytes)?;
    report_skipped_ledger_lines("activity", &activity_path, activity_log.skipped_lines);
    let activity_log = Arc::new(activity_log);
    let analytics = Arc::new(analytics);

    let pool_client = Arc::new(Mutex::new(stratum_client::PoolClient::new()));
    {
        let pool = pool_client.clone();
        let host = pool_host.clone();
        let username_updates = pool_username_receiver.clone();
        let tls = pool_tls;
        tokio::spawn(async move {
            stratum_client::maintain_pool_connection(pool, host, username_updates, tls).await;
        });
    }
    let challenges = Arc::new(Mutex::new(ExpiringTable::new(MAX_LIVE_CHALLENGES)));
    let leases = Arc::new(Mutex::new(ExpiringTable::new(MAX_LIVE_LEASES)));
    let access_tokens = Arc::new(Mutex::new(ExpiringTable::new(MAX_LIVE_ACCESS_TOKENS)));

    let app = move || {
        let server_secret = Arc::clone(&server_secret);
        let pool = pool_client.clone();
        let challenges = challenges.clone();
        let leases = leases.clone();
        let access_tokens = access_tokens.clone();
        let analytics = analytics.clone();
        let activity_log = activity_log.clone();
        let api_key = api_key.clone();
        let submitted_shares = submitted_shares.clone();
        let share_ledger = share_ledger.clone();
        let pool_runtime_config = runtime_config.clone();
        let pool_username_updates = pool_username_updates.clone();
        let pool_config_path = Arc::new(pool_config_path.clone());
        let browser_dir = browser_dir.clone();
        App::new()
            .app_data(web::Data::new(AppState {
                server_secret,
                stratum_pool: pool,
                challenges,
                leases,
                access_tokens,
                analytics,
                activity_log,
                api_key,
                submitted_shares,
                share_ledger,
                pool_runtime_config,
                pool_username_updates,
                pool_config_path,
                browser_dir,
            }))
            .configure(configure_routes)
    };

    let bind_address =
        std::env::var("C2A_BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
    println!("Starting server on http://{bind_address}");
    actix_web::HttpServer::new(app)
        .bind(bind_address)?
        .run()
        .await
}

/// The HTTP API: its routes, and a request-body cap for every JSON endpoint.
fn configure_routes(config: &mut web::ServiceConfig) {
    config
        .app_data(web::JsonConfig::default().limit(MAX_JSON_BODY_BYTES))
        .route("/api/challenge", web::post().to(challenge_endpoint))
        .route("/admin/config", web::post().to(admin_config_endpoint))
        .route("/admin/activity", web::get().to(admin_activity_endpoint))
        .route("/api/proof", web::post().to(proof_endpoint))
        .route("/api/lease", web::post().to(lease_endpoint))
        .route("/api/forms/contact", web::get().to(contact_form_offer))
        .route("/api/forms/contact", web::post().to(contact_form_endpoint))
        .route("/protected", web::get().to(protected_endpoint))
        .route("/challenge-ui", web::get().to(challenge_ui_endpoint))
        .route("/api/job", web::get().to(job_endpoint))
        .route("/api/pool", web::get().to(pool_status_endpoint))
        .route("/metrics", web::get().to(metrics_endpoint))
        .route("/browser/{file}", web::get().to(static_file_handler));
}

async fn challenge_endpoint(
    app: web::Data<AppState>,
    request: HttpRequest,
    req: web::Json<ChallengeRequest>,
) -> Result<HttpResponse, Error> {
    if req.resource.is_empty() || req.resource.len() > 2048 {
        return Ok(HttpResponse::BadRequest().body("Resource must be between 1 and 2048 bytes"));
    }
    if req.high_confidence_bot
        && !has_valid_api_key(&request, app.api_key.as_ref().map(|key| key.as_str()))
    {
        return Ok(HttpResponse::Unauthorized()
            .body("High-confidence bot scoring requires an authenticated site integration"));
    }
    let configured_work_units = app.pool_runtime_config.read().await.required_work_units;
    let Some(configured_work_units) =
        access_difficulty_for_resource(&req.resource, configured_work_units)
    else {
        return Ok(HttpResponse::BadRequest()
            .body("This resource does not require a proof-of-work challenge"));
    };
    let work_units = challenge_work_units(configured_work_units, req.high_confidence_bot);
    let challenge = match issue_challenge(&app.server_secret, &req.resource, work_units) {
        Ok(c) => c,
        Err(e) => return Err(Error::from(io::Error::other(e))),
    };

    let response = ChallengeResponse {
        challenge_id: challenge.challenge_id.clone(),
        resource: challenge.resource.clone(),
        issued_at: challenge.issued_at.to_rfc3339(),
        expires_at: challenge.expires_at.to_rfc3339(),
        required_work_units: challenge.required_work_units,
        algorithm: challenge.algorithm.clone(),
        nonce: hex::encode(&challenge.nonce),
        signature: hex::encode(&challenge.signature),
    };
    if app
        .challenges
        .lock()
        .await
        .insert(
            challenge.challenge_id.clone(),
            HeldChallenge {
                challenge,
                leases_issued: 0,
            },
            Utc::now(),
        )
        .is_err()
    {
        return Ok(HttpResponse::ServiceUnavailable().body(AT_CAPACITY));
    }
    if let Err(error) = record_activity(
        &app,
        ActivityKind::ChallengeIssued,
        Some(&response.challenge_id),
        Some(response.required_work_units),
    )
    .await
    {
        app.challenges.lock().await.remove(&response.challenge_id);
        return Err(Error::from(io::Error::other(format!(
            "Could not record issued challenge: {error}"
        ))));
    }

    Ok(HttpResponse::Ok().json(&response))
}

async fn admin_config_endpoint(
    request: HttpRequest,
    app: web::Data<AppState>,
    req: web::Json<AdminConfigRequest>,
) -> Result<HttpResponse, Error> {
    if !has_valid_api_key(&request, app.api_key.as_ref().map(|key| key.as_str())) {
        return Ok(HttpResponse::Unauthorized().body("Invalid Challenger API key"));
    }

    let config = PoolRuntimeConfig {
        payout_address: req.payout_address.trim().to_string(),
        required_work_units: req.required_work_units,
        pool_enabled: true,
    };
    if let Err(error) = config.validate() {
        return Ok(HttpResponse::BadRequest().body(error));
    }

    let mut current_config = app.pool_runtime_config.write().await;
    if let Err(error) = persist_pool_runtime_config(&app.pool_config_path, &config) {
        eprintln!("Failed to persist Challenger settings: {error}");
        return Ok(
            HttpResponse::InternalServerError().body("Could not persist Challenger settings")
        );
    }
    *current_config = config.clone();
    app.pool_username_updates
        .send_replace(Some(config.payout_address.clone()));

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "payout_address": config.payout_address,
        "required_work_units": config.required_work_units,
        "pool_reconnecting": true
    })))
}

async fn lease_endpoint(
    app: web::Data<AppState>,
    req: web::Json<LeaseRequest>,
) -> Result<HttpResponse, Error> {
    if req.worker_id.is_empty() || req.worker_id.len() > 128 {
        return Ok(HttpResponse::BadRequest().body("Invalid worker id"));
    }
    let held = match app.challenges.lock().await.get(&req.challenge_id).cloned() {
        Some(held) => held,
        None => return Ok(HttpResponse::BadRequest().body("Unknown or expired challenge")),
    };
    let challenge = held.challenge;
    if let Err(error) = verify_challenge(&app.server_secret, &challenge) {
        return Ok(HttpResponse::BadRequest().body(error));
    }
    // Refuse before taking an extranonce2, so refused requests cannot use up
    // the job's extranonce2 space.
    if held.leases_issued >= MAX_LEASES_PER_CHALLENGE {
        return Ok(HttpResponse::BadRequest().body(format!(
            "This challenge has had its {MAX_LEASES_PER_CHALLENGE} work leases; \
             request a new challenge"
        )));
    }
    {
        let mut leases = app.leases.lock().await;
        let now = Utc::now();
        if has_live_lease(&leases, &challenge.challenge_id, now) {
            return Ok(HttpResponse::Conflict().body("Work lease has already been issued"));
        }
        if !leases.has_room(now) {
            return Ok(HttpResponse::ServiceUnavailable().body(AT_CAPACITY));
        }
    }
    let (pool_job, extranonce_2) = match app.stratum_pool.lock().await.allocate_job() {
        Ok(assignment) => assignment,
        Err(error) => return Ok(HttpResponse::ServiceUnavailable().body(error)),
    };
    let lease_id = format!(
        "{}-{}-{}",
        challenge.challenge_id, pool_job.generation, extranonce_2
    );
    let expires_at = Utc::now() + chrono::TimeDelta::seconds(WORK_LEASE_SECONDS);
    let (solution_bits, solutions) = access_work_split(challenge.required_work_units);
    let lease = WorkLease {
        lease_id: lease_id.clone(),
        challenge_id: challenge.challenge_id.clone(),
        worker_id: req.worker_id.clone(),
        expires_at,
        pool_job: pool_job.clone(),
        extranonce_2: extranonce_2.clone(),
        work_units: challenge.required_work_units,
        solution_bits,
        solutions,
    };
    {
        let mut leases = app.leases.lock().await;
        let now = Utc::now();
        // A concurrent request for the same challenge may have won the race.
        if has_live_lease(&leases, &challenge.challenge_id, now) {
            return Ok(HttpResponse::Conflict().body("Work lease has already been issued"));
        }
        if leases
            .insert(challenge.challenge_id.clone(), lease, now)
            .is_err()
        {
            return Ok(HttpResponse::ServiceUnavailable().body(AT_CAPACITY));
        }
    }
    // Counted once issued: the extranonce2 is the lease's from here on.
    if let Some(held) = app.challenges.lock().await.get_mut(&challenge.challenge_id) {
        held.leases_issued += 1;
    }
    if let Err(error) = record_activity(
        &app,
        ActivityKind::LeaseIssued,
        Some(&challenge.challenge_id),
        Some(challenge.required_work_units),
    )
    .await
    {
        app.leases.lock().await.remove(&challenge.challenge_id);
        return Err(Error::from(io::Error::other(format!(
            "Could not record issued work lease: {error}"
        ))));
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "protocol": "c2a-work/2",
        "lease_id": lease_id,
        "challenge_id": challenge.challenge_id,
        "worker_id": req.worker_id,
        "expires_at": expires_at.to_rfc3339(),
        "maximum_runtime_seconds": MAX_WORK_RUNTIME_SECONDS,
        "algorithm": "bitcoin-sha256d-header",
        "access_difficulty_bits": solution_bits,
        "access_solutions": solutions,
        "access_work_bits": challenge.required_work_units,
        "pool_difficulty": pool_job.difficulty,
        "pool_target": target_hex(&pool_job.share_target),
        "job_id": pool_job.job.job_id,
        "job_generation": pool_job.generation,
        "prev_block_hash": pool_job.job.prev_block_hash,
        "coinbase_version": pool_job.job.coinbase_version,
        "coinbase_prefix": pool_job.job.coinbase_prefix,
        "coinbase_suffix": pool_job.job.coinbase_suffix,
        "merkle_branches": pool_job.job.merkle_branches,
        "extranonce_1": pool_job.extranonce_1,
        "extranonce_2": extranonce_2,
        "n_time": pool_job.job.n_time,
        "n_bits": pool_job.job.n_bits
    })))
}

fn has_live_lease(
    leases: &ExpiringTable<WorkLease>,
    challenge_id: &str,
    now: DateTime<Utc>,
) -> bool {
    leases
        .get(challenge_id)
        .is_some_and(|lease| lease.expires_at > now)
}

/// Takes the lease a proof names, if it is the live lease of the proof's own
/// challenge and worker. A proof that names another lease leaves the
/// challenge's lease in place, so nobody can spend a lease they were not given.
fn take_proof_lease(
    leases: &mut ExpiringTable<WorkLease>,
    proof: &ProofRequest,
    now: DateTime<Utc>,
) -> Result<WorkLease, &'static str> {
    let Some(lease) = leases.get(&proof.challenge_id) else {
        return Err("Unknown or already-used work lease");
    };
    if lease.lease_id != proof.lease_id || lease.worker_id != proof.worker_id {
        return Err("Invalid, expired, or mismatched work lease");
    }
    // The lease is the proof's to spend; an expired one is dropped either way.
    leases
        .remove(&proof.challenge_id)
        .filter(|lease| lease.expires_at > now)
        .ok_or("Invalid, expired, or mismatched work lease")
}

async fn proof_endpoint(
    app: web::Data<AppState>,
    req: web::Json<ProofRequest>,
) -> Result<HttpResponse, Error> {
    let proof = req.into_inner();
    let challenge = match app
        .challenges
        .lock()
        .await
        .get(&proof.challenge_id)
        .map(|held| held.challenge.clone())
    {
        Some(challenge) => challenge,
        None => return Ok(HttpResponse::BadRequest().body("Unknown or already-used challenge")),
    };
    if let Err(error) = verify_challenge(&app.server_secret, &challenge) {
        return Ok(HttpResponse::BadRequest().body(error));
    }
    // Checked before the lease is taken, so a malformed proof cannot use up
    // a lease, and with it an extranonce2, without a record.
    if proof.candidates.is_empty() || proof.candidates.len() > 32 {
        return Ok(HttpResponse::BadRequest().body("Provide between 1 and 32 verified candidates"));
    }
    let lease = match take_proof_lease(&mut *app.leases.lock().await, &proof, Utc::now()) {
        Ok(lease) => lease,
        Err(error) => return Ok(HttpResponse::BadRequest().body(error)),
    };
    if app
        .stratum_pool
        .lock()
        .await
        .jobs
        .get(&lease.pool_job.job.job_id)
        .map(|job| job.generation)
        != Some(lease.pool_job.generation)
    {
        return Ok(
            HttpResponse::Conflict().body("Pool job was invalidated before proof submission")
        );
    }
    let mut verified_candidates = Vec::new();
    for candidate in proof.candidates {
        if candidate.extranonce_2 != lease.extranonce_2 {
            record_activity(
                &app,
                ActivityKind::ProofRejected,
                Some(&proof.challenge_id),
                Some(lease.work_units),
            )
            .await
            .map_err(|error| {
                Error::from(io::Error::other(format!(
                    "Could not record rejected proof: {error}"
                )))
            })?;
            return Ok(
                HttpResponse::BadRequest().body("Candidate extranonce does not match its lease")
            );
        }
        let provided_hash = match hex::decode(&candidate.header_hash) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => return Ok(HttpResponse::BadRequest().body("header_hash must be 32-byte hex")),
        };
        let header = match block_header_for_share(
            &lease.pool_job.job,
            &lease.pool_job.extranonce_1,
            &lease.extranonce_2,
            candidate.n_time,
            candidate.nonce,
        ) {
            Ok(header) => header,
            Err(error) => return Ok(HttpResponse::BadRequest().body(error)),
        };
        let expected_hash = sha256d(&header.to_bytes());
        if expected_hash.as_slice() != provided_hash {
            record_activity(
                &app,
                ActivityKind::ProofRejected,
                Some(&proof.challenge_id),
                Some(lease.work_units),
            )
            .await
            .map_err(|error| {
                Error::from(io::Error::other(format!(
                    "Could not record rejected proof: {error}"
                )))
            })?;
            return Ok(HttpResponse::BadRequest().body("Candidate header hash is invalid"));
        }
        verified_candidates.push((candidate, expected_hash));
    }
    // Each different header that meets the bits is one solution; the same
    // candidate sent again is the same work and counts once.
    let mut access_hashes: Vec<[u8; 32]> = Vec::new();
    for (_, hash) in &verified_candidates {
        if meets_access_bits(hash, lease.solution_bits) && !access_hashes.contains(hash) {
            access_hashes.push(*hash);
        }
    }
    if access_hashes.len() < lease.solutions {
        record_activity(
            &app,
            ActivityKind::ProofRejected,
            Some(&proof.challenge_id),
            Some(lease.work_units),
        )
        .await
        .map_err(|error| {
            Error::from(io::Error::other(format!(
                "Could not record rejected proof: {error}"
            )))
        })?;
        return Ok(HttpResponse::BadRequest().body("Invalid proof of work"));
    }
    // The token's slot is taken before the work is spent and kept until the
    // proof is settled, so a proof is never refused for room once its
    // challenge and solutions are used. The demo's pool search earns no token.
    let grant = if earns_access_token(&challenge.resource) {
        let Some(token) = store_access_grant(
            &app,
            &proof.challenge_id,
            &challenge.resource,
            challenge.required_work_units,
        )
        .await?
        else {
            return Ok(HttpResponse::ServiceUnavailable().body(AT_CAPACITY));
        };
        Some(token)
    } else {
        None
    };
    let settled = settle_access_proof(
        &app,
        &proof.challenge_id,
        &lease,
        &access_hashes,
        &verified_candidates,
    )
    .await;
    if !matches!(settled, Ok(Ok(_))) {
        if let Some(token) = &grant {
            app.access_tokens.lock().await.remove(&token.token_id);
        }
    }
    let pool_share = match settled? {
        Ok(pool_share) => pool_share,
        Err(refusal) => return Ok(refusal),
    };
    Ok(HttpResponse::Ok().json(TokenResponse {
        credits_remaining: if grant.is_some() {
            ACCESS_TOKEN_USES
        } else {
            0
        },
        expiry: grant.as_ref().map(|token| token.expires_at.to_rfc3339()),
        token: grant.map(|token| token.token_id),
        pool_share,
    }))
}

/// Spends a checked proof's solutions, uses up its challenge, records the
/// accepted proof and forwards each candidate that meets the pool's share
/// target. Returns the pool share status, or the refusal to send when the
/// solutions have already earned a token, too many solutions are already
/// remembered, or the challenge was used meanwhile.
async fn settle_access_proof(
    app: &AppState,
    challenge_id: &str,
    lease: &WorkLease,
    access_hashes: &[[u8; 32]],
    verified_candidates: &[(ProofCandidate, [u8; 32])],
) -> Result<Result<String, HttpResponse>, Error> {
    // The same header presented again (after an extranonce2 reset, a reconnect
    // or a set_extranonce) is old work and earns no second token, so the
    // solutions the lease asks for must all be ones that have not earned one.
    let spend = app.stratum_pool.lock().await.spend_access_proofs(
        &lease.pool_job.job.prev_block_hash,
        access_hashes,
        lease.solutions,
    );
    match spend {
        stratum_client::AccessProofSpend::Spent => {}
        stratum_client::AccessProofSpend::Full => {
            return Ok(Err(HttpResponse::ServiceUnavailable().body(AT_CAPACITY)));
        }
        stratum_client::AccessProofSpend::AlreadyRewarded => {
            record_activity(
                app,
                ActivityKind::ProofRejected,
                Some(challenge_id),
                Some(lease.work_units),
            )
            .await
            .map_err(|error| {
                Error::from(io::Error::other(format!(
                    "Could not record rejected proof: {error}"
                )))
            })?;
            return Ok(Err(HttpResponse::BadRequest()
                .body("This proof of work has already earned an access token")));
        }
    }
    if app.challenges.lock().await.remove(challenge_id).is_none() {
        return Ok(Err(
            HttpResponse::BadRequest().body("Challenge has already been used")
        ));
    }
    record_activity(
        app,
        ActivityKind::ProofAccepted,
        Some(challenge_id),
        Some(lease.work_units),
    )
    .await
    .map_err(|error| {
        Error::from(io::Error::other(format!(
            "Could not record accepted proof: {error}"
        )))
    })?;
    let mut pool_share_status = "not_pool_qualified".to_string();
    for (candidate, hash) in verified_candidates {
        if meets_difficulty_target(hash, &lease.pool_job.share_target) {
            record_activity(
                app,
                ActivityKind::PoolShareCandidate,
                Some(challenge_id),
                None,
            )
            .await
            .map_err(|error| {
                Error::from(io::Error::other(format!(
                    "Could not record pool share candidate: {error}"
                )))
            })?;
            let share_id = format!(
                "{}:{}:{}:{}:{:08x}:{:08x}:{}",
                lease.pool_job.generation,
                lease.pool_job.job.job_id,
                lease.pool_job.extranonce_1,
                lease.extranonce_2,
                candidate.n_time,
                candidate.nonce,
                hex::encode(hash),
            );
            if !app.submitted_shares.lock().await.insert(share_id.clone()) {
                pool_share_status = "duplicate_not_forwarded".to_string();
                continue;
            }
            let pending_record = ShareLedgerRecord {
                share_id: share_id.clone(),
                challenge_id: challenge_id.to_string(),
                lease_id: lease.lease_id.clone(),
                job_id: lease.pool_job.job.job_id.clone(),
                nonce: candidate.nonce,
                extranonce_2: lease.extranonce_2.clone(),
                header_hash: hex::encode(hash),
                status: "submission_pending".to_string(),
                recorded_at: Utc::now(),
            };
            if let Err(error) = record_share_off_runtime(&app.share_ledger, pending_record).await {
                return Err(Error::from(io::Error::other(format!(
                    "Failed to record pool share before submission: {error}"
                ))));
            }
            let sender = app.stratum_pool.lock().await.submit_sender.clone();
            if let Some(sender) = sender {
                let (response_sender, response_receiver) = tokio::sync::oneshot::channel();
                let submission = stratum_client::ShareSubmission {
                    job_id: lease.pool_job.job.job_id.clone(),
                    extranonce_2: lease.extranonce_2.clone(),
                    n_time: candidate.n_time,
                    nonce: candidate.nonce,
                    worker_name: lease.pool_job.worker_name.clone(),
                    response: response_sender,
                };
                match sender.send(submission).await {
                    Ok(()) => match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        response_receiver,
                    )
                    .await
                    {
                        Ok(Ok(Ok(true))) => {
                            pool_share_status = "pool_accepted".to_string();
                            record_activity(
                                app,
                                ActivityKind::PoolShareAccepted,
                                Some(challenge_id),
                                None,
                            )
                            .await
                            .map_err(|error| {
                                Error::from(io::Error::other(format!(
                                    "Could not record accepted pool share: {error}"
                                )))
                            })?;
                        }
                        Ok(Ok(Ok(false))) => {
                            pool_share_status = "pool_rejected".to_string();
                            record_activity(
                                app,
                                ActivityKind::PoolShareRejected,
                                Some(challenge_id),
                                None,
                            )
                            .await
                            .map_err(|error| {
                                Error::from(io::Error::other(format!(
                                    "Could not record rejected pool share: {error}"
                                )))
                            })?;
                        }
                        Ok(Ok(Err(error))) => {
                            pool_share_status = format!("submission_error: {error}")
                        }
                        _ => pool_share_status = "submission_timeout".to_string(),
                    },
                    Err(error) => pool_share_status = format!("submission_error: {error}"),
                }
            } else {
                pool_share_status = "pool_disconnected".to_string();
            }
            record_share_off_runtime(
                &app.share_ledger,
                ShareLedgerRecord {
                    share_id,
                    challenge_id: challenge_id.to_string(),
                    lease_id: lease.lease_id.clone(),
                    job_id: lease.pool_job.job.job_id.clone(),
                    nonce: candidate.nonce,
                    extranonce_2: lease.extranonce_2.clone(),
                    header_hash: hex::encode(hash),
                    status: pool_share_status.clone(),
                    recorded_at: Utc::now(),
                },
            )
            .await
            .map_err(|error| {
                Error::from(io::Error::other(format!(
                    "Share forwarded but failed to record its outcome: {error}"
                )))
            })?;
        }
    }
    Ok(Ok(pool_share_status))
}

/// Stores a grant for a new random token, valid for an hour on `resource`,
/// and returns the token; `None` when the grant table is full of live grants.
async fn store_access_grant(
    app: &AppState,
    challenge_id: &str,
    resource: &str,
    work_units: u64,
) -> Result<Option<AccessToken>, Error> {
    let token = issue_access_token().map_err(|error| Error::from(io::Error::other(error)))?;
    let stored = app.access_tokens.lock().await.insert(
        token.token_id.clone(),
        AccessGrant {
            resource: resource.to_string(),
            expires_at: token.expires_at,
            challenge_id: challenge_id.to_string(),
            work_units,
        },
        Utc::now(),
    );
    Ok(stored.ok().map(|()| token))
}

async fn protected_endpoint(
    _req: HttpRequest,
    app: web::Data<AppState>,
    query: Query<ProtectedQuery>,
) -> Result<HttpResponse, Error> {
    // Access is decided by the token alone: the User-Agent, the Authorization
    // header and the API key play no part.
    let resource = query
        .resource
        .as_deref()
        .filter(|resource| !resource.is_empty());
    let Some(token) = query.token.as_deref().filter(|token| !token.is_empty()) else {
        return Ok(token_required_response(resource));
    };
    let Some(resource) = resource else {
        return Ok(HttpResponse::BadRequest().body("The resource parameter is required"));
    };
    if let Err(refusal) = redeem_access_token(&app, token, resource).await? {
        return Ok(refusal);
    }
    Ok(HttpResponse::Ok().body(format!("Protected content for {resource}")))
}

/// Spends `token`'s grant for `resource` and records the verified form. The
/// grant leaves the table before its record is written, so the table is not
/// held while the ledger syncs and a token presented twice at once succeeds
/// once. If the record cannot be written, the grant goes back for a retry.
/// The inner `Err` is the refusal to send for an unknown, expired or
/// misdirected token.
async fn redeem_access_token(
    app: &AppState,
    token: &str,
    resource: &str,
) -> Result<Result<(), HttpResponse>, Error> {
    let grant = {
        let mut grants = app.access_tokens.lock().await;
        let Some(grant) = grants.get(token) else {
            return Ok(Err(
                HttpResponse::Unauthorized().body("Invalid or already-used access token")
            ));
        };
        if grant.expires_at <= Utc::now() {
            grants.remove(token);
            return Ok(Err(
                HttpResponse::Unauthorized().body("Expired access token")
            ));
        }
        if grant.resource != resource {
            return Ok(Err(
                HttpResponse::Forbidden().body("Access token is scoped to a different resource")
            ));
        }
        grants
            .remove(token)
            .expect("the grant was found under the same lock")
    };
    // For the site, a successful token check is a verified form submission.
    if let Err(error) = record_activity(
        app,
        ActivityKind::FormSubmissionVerified,
        Some(&grant.challenge_id),
        Some(grant.work_units),
    )
    .await
    {
        // Dropped instead if the table filled up meanwhile.
        let _ = app
            .access_tokens
            .lock()
            .await
            .insert(token.to_string(), grant, Utc::now());
        return Err(Error::from(io::Error::other(format!(
            "Could not record verified form submission: {error}"
        ))));
    }
    Ok(Ok(()))
}

fn token_required_response(resource: Option<&str>) -> HttpResponse {
    HttpResponse::PaymentRequired().json(serde_json::json!({
        "protocol": "c2a/1",
        "error": "A proof-of-work token is required: solve a challenge from /api/challenge \
                  and pass the token it earns",
        "resource": resource,
        "methods": [{
            "id": "bitcoin-sha256d",
            "endpoint": "/api/challenge"
        }]
    }))
}

async fn contact_form_offer() -> HttpResponse {
    HttpResponse::PaymentRequired().json(serde_json::json!({
        "protocol": "c2a/1",
        "resource": "/forms/contact",
        "methods": [{
            "id": "bitcoin-sha256d",
            "challenge_endpoint": "/api/challenge"
        }]
    }))
}

async fn contact_form_endpoint(
    req: HttpRequest,
    app: web::Data<AppState>,
    form: web::Json<ContactFormRequest>,
) -> Result<HttpResponse, Error> {
    if form.name.trim().is_empty()
        || form.name.len() > 120
        || form.email.trim().is_empty()
        || form.email.len() > 254
        || form.message.trim().is_empty()
        || form.message.len() > 5000
    {
        return Ok(HttpResponse::BadRequest().body("Invalid contact form fields"));
    }
    let authorization = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let Some(token) = authorization.strip_prefix("Bearer ") else {
        return Ok(HttpResponse::PaymentRequired().json(serde_json::json!({
            "protocol": "c2a/1",
            "resource": "/forms/contact",
            "methods": [{
                "id": "bitcoin-sha256d",
                "challenge_endpoint": "/api/challenge"
            }]
        })));
    };
    if token.len() > 4096 {
        return Ok(HttpResponse::Unauthorized().body("Invalid access token"));
    }
    if let Err(refusal) = redeem_access_token(&app, token, "/forms/contact").await? {
        return Ok(refusal);
    }
    Ok(HttpResponse::Accepted().json(serde_json::json!({
        "validated": true,
        "message": "Demo form validated; this prototype does not store submissions."
    })))
}

fn has_valid_api_key(req: &HttpRequest, configured_key: Option<&str>) -> bool {
    // An empty configured key would match `Authorization: Bearer `.
    let Some(configured_key) = configured_key.filter(|key| !key.is_empty()) else {
        return false;
    };
    let authorization = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let Some(supplied_key) = authorization.strip_prefix("Bearer ") else {
        return false;
    };
    supplied_key.len() <= 4096
        && supplied_key
            .as_bytes()
            .ct_eq(configured_key.as_bytes())
            .unwrap_u8()
            == 1
}

async fn challenge_ui_endpoint() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Found()
        .append_header(("Location", "/browser/index.html"))
        .finish())
}

async fn static_file_handler(
    app: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let file_name = path.as_ref();

    // Only allow specific known files (prevent path traversal)
    let allowed_files = [
        "index.html",
        "challenger.js",
        "controller.js",
        "wasm-challenger.wasm",
        "wasm-challenger-simd.wasm",
    ];
    if !allowed_files.contains(&file_name.as_str()) {
        return Ok(HttpResponse::NotFound().finish());
    }

    let file = match std::fs::read(app.browser_dir.join(file_name)) {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(HttpResponse::NotFound().finish())
        }
        Err(error) => return Err(Error::from(error)),
    };

    let mime: &str = match file_name.as_str() {
        "index.html" => "text/html",
        "challenger.js" | "controller.js" => "application/javascript",
        "wasm-challenger.wasm" | "wasm-challenger-simd.wasm" => "application/wasm",
        _ => "application/octet-stream",
    };

    Ok(HttpResponse::Ok().content_type(mime).body(file))
}

async fn job_endpoint(app: web::Data<AppState>) -> Result<HttpResponse, Error> {
    let pool = &app.stratum_pool;
    let lock = pool.lock().await;

    let job = match lock.current_job.as_ref() {
        Some(job) => job,
        None => {
            return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "No live Stratum job is available",
                "connected": lock.connected,
                "authorized": lock.authorized
            })))
        }
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "job_id": job.job.job_id,
        "prev_block_hash": job.job.prev_block_hash,
        "coinbase_version": job.job.coinbase_version,
        "coinbase_data": job.job.coinbase_data,
        "coinbase_prefix": job.job.coinbase_prefix,
        "coinbase_suffix": job.job.coinbase_suffix,
        "merkle_branches": job.job.merkle_branches,
        "merkle_root": job.job.merkle_root,
        "n_time": job.job.n_time,
        "n_bits": job.job.n_bits,
        "clean_jobs": job.job.clean_jobs,
        "synthetic": false
    })))
}

async fn pool_status_endpoint(app: web::Data<AppState>) -> HttpResponse {
    let pool = app.stratum_pool.lock().await;
    HttpResponse::Ok().json(serde_json::json!({
        "connected": pool.connected,
        "authorized": pool.authorized,
        "difficulty": pool.difficulty,
        "has_job": pool.current_job.is_some(),
        "job_id": pool.current_job.as_ref().map(|job| job.job.job_id.as_str()),
        "extra_nonce_1": pool.extranonce_1,
        "extra_nonce_2_size": pool.extranonce_2_size
    }))
}

async fn admin_activity_endpoint(request: HttpRequest, app: web::Data<AppState>) -> HttpResponse {
    if !has_valid_api_key(&request, app.api_key.as_ref().map(|key| key.as_str())) {
        return HttpResponse::Unauthorized().body("Invalid Challenger API key");
    }
    let analytics = &app.analytics;
    HttpResponse::Ok().json(serde_json::json!({
        "totals": {
            "challenges_distributed": analytics.challenges_issued.load(Ordering::Relaxed),
            "leases_issued": analytics.leases_issued.load(Ordering::Relaxed),
            "proofs_solved": analytics.proofs_accepted.load(Ordering::Relaxed),
            "proofs_rejected": analytics.proofs_rejected.load(Ordering::Relaxed),
            "pool_share_candidates": analytics.pool_candidates.load(Ordering::Relaxed),
            "pool_shares_accepted": analytics.pool_shares_accepted.load(Ordering::Relaxed),
            "pool_shares_rejected": analytics.pool_shares_rejected.load(Ordering::Relaxed),
            "forms_verified": analytics.form_submissions_verified.load(Ordering::Relaxed),
        },
        "recent_activity": app.activity_log.recent()
    }))
}

async fn metrics_endpoint(app: web::Data<AppState>) -> HttpResponse {
    let analytics = &app.analytics;
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(format!(
            "c2a_challenges_issued {}\nc2a_leases_issued {}\nc2a_access_proofs_accepted {}\nc2a_access_proofs_rejected {}\nc2a_pool_share_candidates {}\nc2a_pool_shares_accepted {}\nc2a_pool_shares_rejected {}\nc2a_form_submissions_verified {}\n",
            analytics.challenges_issued.load(Ordering::Relaxed),
            analytics.leases_issued.load(Ordering::Relaxed),
            analytics.proofs_accepted.load(Ordering::Relaxed),
            analytics.proofs_rejected.load(Ordering::Relaxed),
            analytics.pool_candidates.load(Ordering::Relaxed),
            analytics.pool_shares_accepted.load(Ordering::Relaxed),
            analytics.pool_shares_rejected.load(Ordering::Relaxed),
            analytics.form_submissions_verified.load(Ordering::Relaxed),
        ))
}

#[cfg(test)]
mod pool_runtime_config_tests {
    use super::*;
    use crate::test_support::{test_state, ScratchDir, TEST_PAYOUT_ADDRESS};
    use actix_web::test as actix_test;

    #[actix_web::test]
    async fn static_asset_handler_does_not_serve_test_assets_or_paths() {
        // Assets come from the state's browser directory, not the working
        // directory the tests happen to run in.
        let dir = crate::test_support::ScratchDir::new("static-assets");
        let state = crate::test_support::test_state(&dir, None);
        let browser_dir = dir.join("browser");
        std::fs::create_dir_all(&browser_dir).unwrap();
        std::fs::write(browser_dir.join("test-wasm.html"), "test page").unwrap();
        std::fs::write(dir.join("Cargo.toml"), "[package]").unwrap();
        for path in ["test-wasm.html", "../Cargo.toml", "index.html"] {
            let response = static_file_handler(state.clone(), web::Path::from(path.to_string()))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                actix_web::http::StatusCode::NOT_FOUND,
                "{path}"
            );
        }

        std::fs::write(browser_dir.join("index.html"), "<!doctype html>").unwrap();
        let response = static_file_handler(state, web::Path::from("index.html".to_string()))
            .await
            .unwrap();
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
    }

    #[test]
    fn validates_mainnet_payout_address_shape_and_difficulty_range() {
        let valid = PoolRuntimeConfig {
            payout_address: TEST_PAYOUT_ADDRESS.to_string(),
            required_work_units: 12,
            pool_enabled: false,
        };
        assert!(valid.validate().is_ok());
        assert!(PoolRuntimeConfig {
            payout_address: valid.payout_address.clone(),
            required_work_units: 24,
            pool_enabled: false,
        }
        .validate()
        .is_ok());
        assert!(!valid_payout_address("not-a-bitcoin-address"));
        assert!(PoolRuntimeConfig {
            payout_address: valid.payout_address.clone(),
            required_work_units: 25,
            pool_enabled: false,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn the_unset_placeholder_stands_in_only_while_the_pool_is_off() {
        assert!(!valid_payout_address(stratum_client::UNSET_PAYOUT_ADDRESS));
        let off = PoolRuntimeConfig {
            payout_address: stratum_client::UNSET_PAYOUT_ADDRESS.to_string(),
            required_work_units: 12,
            pool_enabled: false,
        };
        assert!(off.validate().is_ok());
        let on = PoolRuntimeConfig {
            pool_enabled: true,
            ..off
        };
        assert_eq!(
            on.validate().unwrap_err(),
            stratum_client::UNSET_PAYOUT_ADDRESS_ERROR
        );
    }

    #[test]
    fn a_fresh_start_holds_the_placeholder_with_the_pool_off() {
        let dir = ScratchDir::new("fresh-start-config");
        let loaded = load_pool_runtime_config(
            &dir.join("config.json"),
            stratum_client::UNSET_PAYOUT_ADDRESS.to_string(),
        )
        .unwrap();
        assert_eq!(loaded.payout_address, stratum_client::UNSET_PAYOUT_ADDRESS);
        assert!(!loaded.pool_enabled);
    }

    #[test]
    fn a_saved_config_that_turns_the_pool_on_with_the_placeholder_stops_startup() {
        let dir = ScratchDir::new("placeholder-config");
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "payout_address": stratum_client::UNSET_PAYOUT_ADDRESS,
                "required_work_units": 12,
                "pool_enabled": true,
            })
            .to_string(),
        )
        .unwrap();
        let error = load_pool_runtime_config(&path, TEST_PAYOUT_ADDRESS.to_string())
            .err()
            .expect("a pool turned on with the placeholder must not load");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error
            .to_string()
            .contains(stratum_client::UNSET_PAYOUT_ADDRESS_ERROR));
    }

    #[actix_web::test]
    async fn saving_the_placeholder_through_admin_config_is_refused() {
        let dir = ScratchDir::new("admin-placeholder");
        let state = test_state(&dir, Some("test-api-key"));
        let request = actix_test::TestRequest::post()
            .insert_header(("Authorization", "Bearer test-api-key"))
            .to_http_request();
        let response = admin_config_endpoint(
            request,
            state.clone(),
            web::Json(AdminConfigRequest {
                payout_address: stratum_client::UNSET_PAYOUT_ADDRESS.to_string(),
                required_work_units: 16,
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let config = state.pool_runtime_config.read().await;
        assert!(!config.pool_enabled);
        assert_eq!(config.required_work_units, 12);
        assert!(!dir.join("config.json").exists());
    }

    #[test]
    fn high_confidence_bot_gets_a_heavier_bounded_challenge() {
        assert_eq!(challenge_work_units(12, false), 12);
        assert_eq!(challenge_work_units(12, true), 16);
        assert_eq!(challenge_work_units(20, true), MAX_CHALLENGER_DIFFICULTY);
        assert_eq!(challenge_work_units(24, false), 24);
        assert_eq!(challenge_work_units(24, true), MAX_CHALLENGER_DIFFICULTY);
    }

    #[test]
    fn configured_form_difficulty_preserves_stronger_resource_defaults() {
        assert_eq!(
            access_difficulty_for_resource("/forms/contact", 16),
            Some(16)
        );
        assert_eq!(access_difficulty_for_resource("/search", 12), Some(14));
        assert_eq!(access_difficulty_for_resource("/report", 12), Some(16));
        assert_eq!(access_difficulty_for_resource("/bulk", 12), Some(18));
        assert_eq!(access_difficulty_for_resource("/", 12), None);
    }

    #[test]
    fn pool_configuration_survives_restart() {
        let path = std::env::temp_dir().join(format!(
            "c2a-config-test-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let config = PoolRuntimeConfig {
            payout_address: TEST_PAYOUT_ADDRESS.to_string(),
            required_work_units: 17,
            pool_enabled: false,
        };

        persist_pool_runtime_config(&path, &config).unwrap();
        let updated_config = PoolRuntimeConfig {
            payout_address: config.payout_address.clone(),
            required_work_units: 18,
            pool_enabled: true,
        };
        persist_pool_runtime_config(&path, &updated_config).unwrap();
        let loaded = load_pool_runtime_config(&path, "unused".to_string()).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(loaded.payout_address, config.payout_address);
        assert_eq!(loaded.required_work_units, 18);
        assert!(loaded.pool_enabled);
    }

    #[actix_web::test]
    async fn authenticated_admin_update_persists_and_applies_the_pool_address() {
        let config_path = std::env::temp_dir().join(format!(
            "c2a-admin-config-test-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let ledger_path = config_path.with_extension("ledger");
        let activity_path = config_path.with_extension("activity.jsonl");
        let share_ledger =
            ledger::LedgerFile::open(&ledger_path, ledger::DEFAULT_MAX_BYTES).unwrap();
        let initial_config = PoolRuntimeConfig {
            payout_address: stratum_client::UNSET_PAYOUT_ADDRESS.to_string(),
            required_work_units: 12,
            pool_enabled: false,
        };
        let (pool_username_updates, mut pool_username_receiver) = watch::channel(None);
        let (activity_log, analytics) = ActivityLog::load(&activity_path).unwrap();
        let state = web::Data::new(AppState {
            server_secret: Arc::new(vec![b's'; 32]),
            stratum_pool: Arc::new(Mutex::new(stratum_client::PoolClient::new())),
            challenges: Arc::new(Mutex::new(ExpiringTable::new(MAX_LIVE_CHALLENGES))),
            leases: Arc::new(Mutex::new(ExpiringTable::new(MAX_LIVE_LEASES))),
            access_tokens: Arc::new(Mutex::new(ExpiringTable::new(MAX_LIVE_ACCESS_TOKENS))),
            analytics: Arc::new(analytics),
            activity_log: Arc::new(activity_log),
            api_key: Some(Arc::new("test-api-key".to_string())),
            submitted_shares: Arc::new(Mutex::new(HashSet::new())),
            share_ledger: Arc::new(StdMutex::new(share_ledger)),
            pool_runtime_config: Arc::new(RwLock::new(initial_config)),
            pool_username_updates,
            pool_config_path: Arc::new(config_path.clone()),
            browser_dir: Arc::new(PathBuf::from("browser")),
        });

        let unauthenticated = actix_test::TestRequest::post().to_http_request();
        let rejected = admin_config_endpoint(
            unauthenticated,
            state.clone(),
            web::Json(AdminConfigRequest {
                payout_address: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT".to_string(),
                required_work_units: 16,
            }),
        )
        .await
        .unwrap();
        assert_eq!(rejected.status(), actix_web::http::StatusCode::UNAUTHORIZED);

        let authenticated = actix_test::TestRequest::post()
            .insert_header(("Authorization", "Bearer test-api-key"))
            .to_http_request();
        let accepted = admin_config_endpoint(
            authenticated,
            state.clone(),
            web::Json(AdminConfigRequest {
                payout_address: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT".to_string(),
                required_work_units: 16,
            }),
        )
        .await
        .unwrap();

        assert_eq!(accepted.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            pool_username_receiver.borrow_and_update().as_deref(),
            Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
        );
        let persisted = load_pool_runtime_config(&config_path, "unused".to_string()).unwrap();
        assert_eq!(
            persisted.payout_address,
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
        );
        assert_eq!(persisted.required_work_units, 16);
        assert!(persisted.pool_enabled);

        record_activity(
            state.get_ref(),
            ActivityKind::ChallengeIssued,
            Some("challenge-test"),
            Some(16),
        )
        .await
        .unwrap();
        let unauthenticated_activity = admin_activity_endpoint(
            actix_test::TestRequest::get().to_http_request(),
            state.clone(),
        )
        .await;
        assert_eq!(
            unauthenticated_activity.status(),
            actix_web::http::StatusCode::UNAUTHORIZED
        );
        let authenticated_activity = actix_test::TestRequest::get()
            .insert_header(("Authorization", "Bearer test-api-key"))
            .to_http_request();
        let activity_response =
            admin_activity_endpoint(authenticated_activity, state.clone()).await;
        assert_eq!(activity_response.status(), actix_web::http::StatusCode::OK);
        let activity_body = actix_web::body::to_bytes(activity_response.into_body())
            .await
            .unwrap();
        let activity: serde_json::Value = serde_json::from_slice(&activity_body).unwrap();
        assert_eq!(activity["totals"]["challenges_distributed"], 1);
        assert_eq!(
            activity["recent_activity"][0]["challenge_id"],
            "challenge-test"
        );

        drop(state);
        drop(pool_username_receiver);
        let (restored_activity_log, restored_analytics) =
            ActivityLog::load(&activity_path).unwrap();
        assert_eq!(
            restored_analytics.challenges_issued.load(Ordering::Relaxed),
            1
        );
        drop(restored_activity_log);
        std::fs::remove_file(config_path).unwrap();
        std::fs::remove_file(ledger_path).unwrap();
        std::fs::remove_file(activity_path).unwrap();
    }
}

#[cfg(test)]
mod startup_secret_tests {
    use super::*;
    use actix_web::test as actix_test;

    const GOOD_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
    const GOOD_API_KEY: &str = "fedcba9876543210fedcba9876543210";

    /// The value `.env.example` ships for `name`.
    fn env_example_value(name: &str) -> String {
        let example =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.env.example"))
                .unwrap();
        example
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{name} is not set in .env.example"))
            .to_string()
    }

    #[test]
    fn startup_refuses_the_env_example_placeholders() {
        let secret = env_example_value("C2A_SERVER_SECRET");
        let api_key = env_example_value("C2A_API_KEY");
        assert!(
            validate_startup_secrets(Some(&secret), Some(GOOD_API_KEY)).is_err(),
            "the C2A_SERVER_SECRET placeholder must not start the server"
        );
        assert!(
            validate_startup_secrets(Some(GOOD_SECRET), Some(&api_key)).is_err(),
            "the C2A_API_KEY placeholder must not start the server"
        );
    }

    #[test]
    fn startup_refuses_an_empty_api_key() {
        for empty in ["", "   "] {
            assert!(
                validate_startup_secrets(Some(GOOD_SECRET), Some(empty)).is_err(),
                "{empty:?}"
            );
        }
    }

    #[test]
    fn startup_warns_about_but_accepts_a_short_api_key() {
        let secrets = validate_startup_secrets(Some(GOOD_SECRET), Some("short-key"))
            .expect("a short API key must not stop the server");
        assert_eq!(secrets.api_key.as_deref(), Some("short-key"));
        assert_eq!(secrets.warnings.len(), 1, "{:?}", secrets.warnings);
        assert!(secrets.warnings[0].contains("32"), "{:?}", secrets.warnings);
        let long = validate_startup_secrets(Some(GOOD_SECRET), Some(GOOD_API_KEY)).unwrap();
        assert!(long.warnings.is_empty(), "{:?}", long.warnings);
    }

    #[test]
    fn startup_requires_a_32_byte_server_secret_and_allows_no_api_key() {
        assert!(validate_startup_secrets(None, None).is_err());
        assert!(validate_startup_secrets(Some(&"s".repeat(31)), None).is_err());
        let secrets = validate_startup_secrets(Some(&"s".repeat(32)), None).unwrap();
        assert_eq!(secrets.server_secret, vec![b's'; 32]);
        assert!(secrets.api_key.is_none());
        assert!(secrets.warnings.is_empty());
    }

    #[test]
    fn an_empty_configured_api_key_never_authenticates() {
        let empty_bearer = actix_test::TestRequest::get()
            .insert_header(("Authorization", "Bearer "))
            .to_http_request();
        assert!(!has_valid_api_key(&empty_bearer, Some("")));
        let real = actix_test::TestRequest::get()
            .insert_header(("Authorization", format!("Bearer {GOOD_API_KEY}")))
            .to_http_request();
        assert!(has_valid_api_key(&real, Some(GOOD_API_KEY)));
        assert!(!has_valid_api_key(&real, None));
    }
}

#[cfg(test)]
mod test_support {
    use super::*;
    pub use crate::activity::ActivityGate;
    use std::sync::atomic::AtomicU64;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    /// A well-formed mainnet address for tests that need one; no test connects
    /// to a pool with it.
    pub const TEST_PAYOUT_ADDRESS: &str = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";

    /// A unique directory under the system temp dir, removed when dropped.
    pub struct ScratchDir(PathBuf);

    impl ScratchDir {
        pub fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "c2a-{label}-{}-{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Application state with empty in-memory tables and ledgers in `dir`.
    pub fn test_state(dir: &ScratchDir, api_key: Option<&str>) -> web::Data<AppState> {
        let (activity_log, analytics) = ActivityLog::load(&dir.join("activity.jsonl")).unwrap();
        state_with_activity_log(dir, api_key, activity_log, analytics)
    }

    /// Like [`test_state`] with no API key, but the activity ledger's writer
    /// waits for the returned gate before each group of records. Dropping the
    /// gate lets it run freely.
    pub fn gated_test_state(dir: &ScratchDir) -> (web::Data<AppState>, ActivityGate) {
        let (activity_log, analytics, gate) =
            ActivityLog::load_gated(&dir.join("activity.jsonl"), ledger::DEFAULT_MAX_BYTES)
                .unwrap();
        (
            state_with_activity_log(dir, None, activity_log, analytics),
            gate,
        )
    }

    fn state_with_activity_log(
        dir: &ScratchDir,
        api_key: Option<&str>,
        activity_log: ActivityLog,
        analytics: Analytics,
    ) -> web::Data<AppState> {
        let (share_ledger, submitted_shares, _) =
            load_share_ledger(&dir.join("shares.jsonl"), ledger::DEFAULT_MAX_BYTES).unwrap();
        let (pool_username_updates, _) = watch::channel(None);
        web::Data::new(AppState {
            server_secret: Arc::new(vec![b's'; 32]),
            stratum_pool: Arc::new(Mutex::new(stratum_client::PoolClient::new())),
            challenges: Arc::new(Mutex::new(ExpiringTable::new(MAX_LIVE_CHALLENGES))),
            leases: Arc::new(Mutex::new(ExpiringTable::new(MAX_LIVE_LEASES))),
            access_tokens: Arc::new(Mutex::new(ExpiringTable::new(MAX_LIVE_ACCESS_TOKENS))),
            analytics: Arc::new(analytics),
            activity_log: Arc::new(activity_log),
            api_key: api_key.map(|key| Arc::new(key.to_string())),
            submitted_shares: Arc::new(Mutex::new(submitted_shares)),
            share_ledger: Arc::new(StdMutex::new(share_ledger)),
            pool_runtime_config: Arc::new(RwLock::new(PoolRuntimeConfig {
                payout_address: stratum_client::UNSET_PAYOUT_ADDRESS.to_string(),
                required_work_units: 12,
                pool_enabled: false,
            })),
            pool_username_updates,
            pool_config_path: Arc::new(dir.join("config.json")),
            browser_dir: Arc::new(dir.join("browser")),
        })
    }
}

#[cfg(test)]
mod protected_access_tests {
    use super::*;
    use crate::test_support::{gated_test_state, test_state, ScratchDir};
    use actix_web::http::StatusCode;
    use actix_web::test as actix_test;

    const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
        AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36";
    const CONTACT: &str = "resource=%2Fforms%2Fcontact";

    async fn issue(state: &web::Data<AppState>, challenge_id: &str, resource: &str) -> String {
        store_access_grant(state.get_ref(), challenge_id, resource, 12)
            .await
            .unwrap()
            .expect("room for the grant")
            .token_id
    }

    async fn protected(
        state: &web::Data<AppState>,
        query: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, String) {
        let mut request = actix_test::TestRequest::get().uri(&format!("/protected?{query}"));
        for (name, value) in headers {
            request = request.insert_header((*name, *value));
        }
        let query = Query::<ProtectedQuery>::from_query(query).unwrap();
        let response = protected_endpoint(request.to_http_request(), state.clone(), query)
            .await
            .unwrap();
        let status = response.status();
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn assert_token_required(status: StatusCode, body: &str, context: &str) {
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{context}: {body}");
        let json: serde_json::Value = serde_json::from_str(body)
            .unwrap_or_else(|error| panic!("{context}: 402 body must be JSON ({error}): {body}"));
        assert!(
            json["error"]
                .as_str()
                .is_some_and(|error| error.contains("proof-of-work token is required")),
            "{context}: {body}"
        );
    }

    async fn submit_contact_form(state: &web::Data<AppState>, token: &str) -> StatusCode {
        let request = actix_test::TestRequest::post()
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_http_request();
        contact_form_endpoint(
            request,
            state.clone(),
            web::Json(ContactFormRequest {
                name: "Ada".to_string(),
                email: "ada@example.test".to_string(),
                message: "Hello".to_string(),
            }),
        )
        .await
        .unwrap()
        .status()
    }

    #[actix_web::test]
    async fn missing_token_is_payment_required_for_a_browser_user_agent() {
        let dir = ScratchDir::new("protected-browser");
        let state = test_state(&dir, None);
        let browser = [("User-Agent", BROWSER_USER_AGENT)];
        for (query, headers, context) in [
            (CONTACT, &browser[..], "browser UA"),
            (CONTACT, &[][..], "no User-Agent header"),
            ("", &browser[..], "browser UA, no resource either"),
        ] {
            let (status, body) = protected(&state, query, headers).await;
            assert_token_required(status, &body, context);
        }
    }

    #[actix_web::test]
    async fn missing_or_empty_token_is_payment_required_for_a_curl_user_agent() {
        let dir = ScratchDir::new("protected-curl");
        let state = test_state(&dir, None);
        let curl = [("User-Agent", "curl/8.4.0")];
        for query in [CONTACT.to_string(), format!("token=&{CONTACT}")] {
            let (status, body) = protected(&state, &query, &curl).await;
            assert_token_required(status, &body, &query);
        }
    }

    #[actix_web::test]
    async fn missing_or_empty_resource_is_a_bad_request_and_keeps_the_token() {
        let dir = ScratchDir::new("protected-resource");
        let state = test_state(&dir, None);
        let token = issue(&state, "challenge-resource", "/article/test").await;
        for query in [format!("token={token}"), format!("token={token}&resource=")] {
            let (status, body) = protected(&state, &query, &[]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
        }
        let (status, _) = protected(
            &state,
            &format!("token={token}&resource=%2Farticle%2Ftest"),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "a 400 must not consume the token");
    }

    #[actix_web::test]
    async fn a_token_authorizes_exactly_one_protected_call() {
        let dir = ScratchDir::new("protected-once");
        let state = test_state(&dir, None);
        let token = issue(&state, "challenge-once", "/forms/contact").await;
        let query = format!("token={token}&{CONTACT}");

        let (status, body) = protected(&state, &query, &[]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, "Protected content for /forms/contact");
        for attempt in 2..=4 {
            let (status, _) = protected(&state, &query, &[]).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "use {attempt} of a spent token"
            );
        }
        assert!(
            !state.access_tokens.lock().await.contains_key(&token),
            "a used token's record is removed"
        );
    }

    #[actix_web::test]
    async fn wrong_resource_is_forbidden_and_does_not_consume_the_token() {
        let dir = ScratchDir::new("protected-scope");
        let state = test_state(&dir, None);
        let token = issue(&state, "challenge-scope", "/forms/contact").await;
        for _ in 0..2 {
            let (status, _) = protected(
                &state,
                &format!("token={token}&resource=%2Fforms%2Fnewsletter"),
                &[],
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
        let query = format!("token={token}&{CONTACT}");
        assert_eq!(protected(&state, &query, &[]).await.0, StatusCode::OK);
        assert_eq!(
            protected(&state, &query, &[]).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[actix_web::test]
    async fn an_invalid_authorization_header_does_not_change_the_token_outcome() {
        let dir = ScratchDir::new("protected-authorization");
        let state = test_state(&dir, Some("test-api-key"));
        for (index, authorization) in ["Bearer wrong-key", "Basic dGVzdDp0ZXN0", "Bearer "]
            .into_iter()
            .enumerate()
        {
            let headers = [
                ("Authorization", authorization),
                ("User-Agent", BROWSER_USER_AGENT),
            ];
            let (status, body) = protected(&state, CONTACT, &headers).await;
            assert_token_required(status, &body, authorization);

            let token = issue(&state, &format!("challenge-auth-{index}"), "/forms/contact").await;
            let query = format!("token={token}&{CONTACT}");
            assert_eq!(protected(&state, &query, &headers).await.0, StatusCode::OK);
            assert_eq!(
                protected(&state, &query, &headers).await.0,
                StatusCode::UNAUTHORIZED,
                "{authorization}"
            );
        }
        let (status, body) =
            protected(&state, CONTACT, &[("Authorization", "Bearer test-api-key")]).await;
        assert_token_required(status, &body, "the configured API key is not a token");
    }

    #[actix_web::test]
    async fn the_api_key_opens_neither_the_protected_route_nor_the_demo_form() {
        let dir = ScratchDir::new("protected-api-key");
        let state = test_state(&dir, Some("test-api-key"));
        let key = [("Authorization", "Bearer test-api-key")];
        for query in ["", CONTACT] {
            let (status, body) = protected(&state, query, &key).await;
            assert_token_required(status, &body, query);
            let methods: serde_json::Value =
                serde_json::from_str::<serde_json::Value>(&body).unwrap()["methods"].clone();
            assert_eq!(
                methods,
                serde_json::json!([{"id": "bitcoin-sha256d", "endpoint": "/api/challenge"}]),
                "proof of work is the only way in: {body}"
            );
        }
        let unknown = format!("token=unknown&{CONTACT}");
        assert_eq!(
            protected(&state, &unknown, &key).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            submit_contact_form(&state, "test-api-key").await,
            StatusCode::UNAUTHORIZED,
            "the demo form treats the key as an unknown token"
        );
        assert_eq!(
            state
                .analytics
                .form_submissions_verified
                .load(Ordering::Relaxed),
            0
        );

        let token = issue(&state, "challenge-with-key", "/forms/contact").await;
        let query = format!("token={token}&{CONTACT}");
        assert_eq!(
            protected(&state, &query, &key).await.0,
            StatusCode::OK,
            "a valid token still works when the key is also sent"
        );
    }

    #[actix_web::test]
    async fn the_demo_form_checks_its_fields_and_token_length_first() {
        let dir = ScratchDir::new("protected-form-fields");
        let state = test_state(&dir, None);
        let submit = |name: String, email: String, message: String, token: String| {
            let state = state.clone();
            async move {
                let request = actix_test::TestRequest::post()
                    .insert_header(("Authorization", format!("Bearer {token}")))
                    .to_http_request();
                let response = contact_form_endpoint(
                    request,
                    state,
                    web::Json(ContactFormRequest {
                        name,
                        email,
                        message,
                    }),
                )
                .await
                .unwrap();
                let status = response.status();
                let body = actix_web::body::to_bytes(response.into_body())
                    .await
                    .unwrap();
                (status, String::from_utf8_lossy(&body).into_owned())
            }
        };
        let ok = |length: usize| "a".repeat(length);
        let invalid = [
            (" ".to_string(), ok(5), ok(5)),
            (ok(121), ok(5), ok(5)),
            (ok(5), " ".to_string(), ok(5)),
            (ok(5), ok(255), ok(5)),
            (ok(5), ok(5), " ".to_string()),
            (ok(5), ok(5), ok(5001)),
        ];
        for (name, email, message) in invalid {
            let lengths = (name.len(), email.len(), message.len());
            let (status, body) = submit(name, email, message, "unknown".to_string()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{lengths:?}: {body}");
        }

        let (status, body) = submit(ok(5), ok(5), ok(5), "t".repeat(4097)).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::UNAUTHORIZED, "Invalid access token")
        );
        let (status, body) = submit(ok(5), ok(5), ok(5), "t".repeat(4096)).await;
        assert_eq!(
            (status, body.as_str()),
            (
                StatusCode::UNAUTHORIZED,
                "Invalid or already-used access token"
            ),
            "a 4096-byte token is looked up"
        );

        let token = issue(&state, "challenge-limits", "/forms/contact").await;
        let (status, _) = submit(ok(120), ok(254), ok(5000), token).await;
        assert_eq!(status, StatusCode::ACCEPTED, "every field at its limit");
    }

    #[actix_web::test]
    async fn a_token_check_does_not_hold_the_grant_table_while_its_record_is_written() {
        let dir = ScratchDir::new("protected-unlocked");
        let (state, gate) = gated_test_state(&dir);
        let token = issue(&state, "challenge-unlocked", "/forms/contact").await;
        let query = format!("token={token}&{CONTACT}");
        let check = protected(&state, &query, &[]);
        tokio::pin!(check);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut check)
                .await
                .is_err(),
            "the check waits for the held ledger writer"
        );

        let grants = state
            .access_tokens
            .try_lock()
            .expect("the grant table must be free while the record is written");
        assert!(!grants.contains_key(&token), "the grant is already spent");
        drop(grants);
        assert_eq!(
            protected(&state, &query, &[]).await.0,
            StatusCode::UNAUTHORIZED,
            "the same token presented meanwhile is refused"
        );

        drop(gate);
        assert_eq!(check.await.0, StatusCode::OK);
        assert_eq!(
            state
                .analytics
                .form_submissions_verified
                .load(Ordering::Relaxed),
            1
        );
    }

    #[actix_web::test]
    async fn a_token_is_single_use_across_the_protected_route_and_the_demo_form() {
        let dir = ScratchDir::new("protected-form");
        let state = test_state(&dir, None);
        let form_token = issue(&state, "challenge-form-a", "/forms/contact").await;
        assert_eq!(
            submit_contact_form(&state, &form_token).await,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            submit_contact_form(&state, &form_token).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            protected(&state, &format!("token={form_token}&{CONTACT}"), &[])
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );

        let token = issue(&state, "challenge-form-b", "/forms/contact").await;
        assert_eq!(
            protected(&state, &format!("token={token}&{CONTACT}"), &[])
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            submit_contact_form(&state, &token).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[actix_web::test]
    async fn issued_tokens_are_random_and_do_not_reveal_the_challenge() {
        let dir = ScratchDir::new("protected-random-token");
        let state = test_state(&dir, None);
        let first = issue(&state, "challenge-visible", "/forms/contact").await;
        let second = issue(&state, "challenge-visible", "/forms/contact").await;
        assert_ne!(first, second, "two tokens for one challenge must differ");
        for token in [&first, &second] {
            assert_eq!(token.len(), 64, "256 random bits as hex: {token}");
            assert!(
                token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "URL-safe lowercase hex: {token}"
            );
            assert!(!token.contains("challenge-visible"), "{token}");
        }
        assert_eq!(state.access_tokens.lock().await.len(), 2);
    }

    #[actix_web::test]
    async fn a_successful_token_check_counts_as_a_verified_form() {
        let dir = ScratchDir::new("protected-counted");
        let state = test_state(&dir, Some("test-api-key"));
        let verified = |state: &web::Data<AppState>| {
            state
                .analytics
                .form_submissions_verified
                .load(Ordering::Relaxed)
        };
        let token = issue(&state, "challenge-counted", "/forms/contact").await;

        for (query, headers) in [
            (CONTACT.to_string(), vec![]),
            (
                format!("token={token}&resource=%2Fforms%2Fnewsletter"),
                vec![],
            ),
            (format!("token={token}"), vec![]),
            (format!("token=unknown&{CONTACT}"), vec![]),
            (
                String::new(),
                vec![("Authorization", "Bearer test-api-key")],
            ),
        ] {
            protected(&state, &query, &headers).await;
            assert_eq!(verified(&state), 0, "{query} is not a verified form");
        }

        let query = format!("token={token}&{CONTACT}");
        assert_eq!(protected(&state, &query, &[]).await.0, StatusCode::OK);
        assert_eq!(verified(&state), 1);
        let recent = state.activity_log.recent();
        let last = recent.last().expect("the verification is recorded");
        assert!(last.event == ActivityKind::FormSubmissionVerified);
        assert_eq!(last.challenge_id.as_deref(), Some("challenge-counted"));

        assert_eq!(
            protected(&state, &query, &[]).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(verified(&state), 1, "a spent token is not counted again");

        drop(state);
        let (_, replayed) = ActivityLog::load(&dir.join("activity.jsonl")).unwrap();
        assert_eq!(
            replayed.form_submissions_verified.load(Ordering::Relaxed),
            1,
            "the count survives a restart"
        );
    }
}

#[cfg(test)]
mod access_proof_replay_tests {
    use super::*;
    use crate::test_support::{test_state, ScratchDir};
    use actix_web::http::StatusCode;
    use actix_web::test as actix_test;
    use compute_to_access_core::stratum::{pool_share_target, StratumClient, StratumJob};

    const EXTRANONCE_1: &str = "aabbccdd";
    const UNREACHABLE_POOL_DIFFICULTY: f64 = 1e15;

    pub(crate) fn pool_job() -> StratumJob {
        StratumClient::new()
            .parse_job_notification(&serde_json::json!({
                "method": "mining.notify",
                "params": [
                    "job-1",
                    "11".repeat(32),
                    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20",
                    "0000000001000000000000000000000000",
                    ["22".repeat(32), "33".repeat(32)],
                    "20000000",
                    "1703a30c",
                    "65000000",
                    true
                ]
            }))
            .unwrap()
    }

    /// A pool session with a one-byte extranonce2 serving `pool_job()` as the
    /// given generation, as after a (re)subscribe and a notify.
    pub(crate) async fn serve_job(
        state: &web::Data<AppState>,
        generation: u64,
        reset_counter: bool,
    ) {
        let mut pool = state.stratum_pool.lock().await;
        pool.extranonce_1 = EXTRANONCE_1.to_string();
        pool.extranonce_2_size = 1;
        pool.connected = true;
        pool.authorized = true;
        pool.difficulty = UNREACHABLE_POOL_DIFFICULTY;
        if reset_counter {
            pool.next_extranonce_2 = Some(0);
        }
        let descriptor = stratum_client::PoolJob {
            job: pool_job(),
            generation,
            extranonce_1: EXTRANONCE_1.to_string(),
            extranonce_2_size: 1,
            difficulty: UNREACHABLE_POOL_DIFFICULTY,
            share_target: pool_share_target(UNREACHABLE_POOL_DIFFICULTY).unwrap(),
            worker_name: "address.worker".to_string(),
        };
        pool.jobs.clear();
        pool.jobs
            .insert(descriptor.job.job_id.clone(), descriptor.clone());
        pool.current_job = Some(descriptor);
    }

    pub(crate) async fn json_body(response: HttpResponse) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&body)
                .unwrap_or_else(|_| serde_json::json!(String::from_utf8_lossy(&body))),
        )
    }

    async fn new_lease(state: &web::Data<AppState>) -> (StatusCode, serde_json::Value) {
        let challenge = challenge_endpoint(
            state.clone(),
            actix_test::TestRequest::post().to_http_request(),
            web::Json(ChallengeRequest {
                resource: "/forms/contact".to_string(),
                high_confidence_bot: false,
            }),
        )
        .await
        .unwrap();
        let (status, challenge) = json_body(challenge).await;
        assert_eq!(status, StatusCode::OK, "{challenge}");
        let lease = lease_endpoint(
            state.clone(),
            web::Json(LeaseRequest {
                challenge_id: challenge["challenge_id"].as_str().unwrap().to_string(),
                worker_id: "replay-worker".to_string(),
            }),
        )
        .await
        .unwrap();
        json_body(lease).await
    }

    /// The first `count` nonces at or after `from` whose headers meet the
    /// lease's bits for one solution.
    pub(crate) fn solutions_from(
        lease: &serde_json::Value,
        from: u32,
        count: usize,
    ) -> Vec<(u32, [u8; 32])> {
        let job = pool_job();
        let bits = lease["access_difficulty_bits"].as_u64().unwrap();
        let extranonce_2 = lease["extranonce_2"].as_str().unwrap();
        (from..)
            .map(|nonce| {
                let header =
                    block_header_for_share(&job, EXTRANONCE_1, extranonce_2, job.n_time, nonce)
                        .unwrap();
                (nonce, sha256d(&header.to_bytes()))
            })
            .filter(|(_, hash)| meets_access_bits(hash, bits))
            .take(count)
            .collect()
    }

    /// The solutions the lease asks for, the first ones from nonce `from`.
    pub(crate) fn solve(lease: &serde_json::Value, from: u32) -> Vec<(u32, [u8; 32])> {
        let count = lease["access_solutions"].as_u64().unwrap() as usize;
        solutions_from(lease, from, count)
    }

    pub(crate) fn candidates(
        lease: &serde_json::Value,
        solutions: &[(u32, [u8; 32])],
    ) -> Vec<ProofCandidate> {
        solutions
            .iter()
            .map(|(nonce, hash)| ProofCandidate {
                header_hash: hex::encode(hash),
                extranonce_2: lease["extranonce_2"].as_str().unwrap().to_string(),
                n_time: pool_job().n_time,
                nonce: *nonce,
            })
            .collect()
    }

    pub(crate) async fn prove(
        state: &web::Data<AppState>,
        lease: &serde_json::Value,
        solutions: &[(u32, [u8; 32])],
    ) -> (StatusCode, serde_json::Value) {
        let response = proof_endpoint(
            state.clone(),
            web::Json(ProofRequest {
                challenge_id: lease["challenge_id"].as_str().unwrap().to_string(),
                lease_id: lease["lease_id"].as_str().unwrap().to_string(),
                worker_id: lease["worker_id"].as_str().unwrap().to_string(),
                candidates: candidates(lease, solutions),
                hashes_attempted: 0,
                elapsed_ms: 0,
            }),
        )
        .await
        .unwrap();
        json_body(response).await
    }

    #[test]
    fn work_is_split_into_sixteen_solutions_of_four_fewer_bits() {
        assert_eq!(access_work_split(24), (20, 16));
        assert_eq!(access_work_split(20), (16, 16));
        assert_eq!(access_work_split(8), (4, 16));
        assert_eq!(access_work_split(5), (1, 16));
        // Below 5 bits each solution keeps at least one bit.
        assert_eq!(access_work_split(3), (1, 4));
        assert_eq!(access_work_split(2), (1, 2));
        assert_eq!(access_work_split(1), (1, 1));
        assert_eq!(access_work_split(0), (0, 1));
    }

    #[actix_web::test]
    async fn a_lease_asks_for_sixteen_solutions_and_names_the_whole_work() {
        let dir = ScratchDir::new("lease-solutions");
        let state = replay_state(&dir).await;
        state.pool_runtime_config.write().await.required_work_units = 20;
        let (status, lease) = new_lease(&state).await;
        assert_eq!(status, StatusCode::OK, "{lease}");
        assert_eq!(lease["protocol"], "c2a-work/2");
        assert_eq!(lease["access_difficulty_bits"], 16);
        assert_eq!(lease["access_solutions"], 16);
        assert_eq!(lease["access_work_bits"], 20);
    }

    #[actix_web::test]
    async fn sixteen_distinct_solutions_earn_a_token() {
        let dir = ScratchDir::new("solutions-enough");
        let state = replay_state(&dir).await;
        let (_, lease) = new_lease(&state).await;
        let solutions = solve(&lease, 0);
        assert_eq!(solutions.len(), 16);
        let (status, body) = prove(&state, &lease, &solutions).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["token"].is_string());
        assert!(body["expiry"].is_string());
        assert_eq!(
            body["credits_remaining"], 1,
            "a token is issued for one use"
        );
    }

    #[actix_web::test]
    async fn fifteen_solutions_are_not_enough() {
        let dir = ScratchDir::new("solutions-short");
        let state = replay_state(&dir).await;
        let (_, lease) = new_lease(&state).await;
        let (status, body) = prove(&state, &lease, &solve(&lease, 0)[..15]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body, serde_json::json!("Invalid proof of work"));
        assert!(body.get("token").is_none());
    }

    #[actix_web::test]
    async fn a_solution_sent_sixteen_times_counts_once() {
        let dir = ScratchDir::new("solutions-repeated");
        let state = replay_state(&dir).await;
        let (_, lease) = new_lease(&state).await;
        let one = solve(&lease, 0)[0];
        let (status, body) = prove(&state, &lease, &[one; 16]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body, serde_json::json!("Invalid proof of work"));
    }

    #[actix_web::test]
    async fn a_proof_whose_hashes_miss_the_bits_is_refused_and_recorded() {
        let dir = ScratchDir::new("solutions-miss");
        let state = replay_state(&dir).await;
        let (_, lease) = new_lease(&state).await;
        // Honest hashes of nonces that are not solutions.
        let solutions: Vec<_> = solve(&lease, 0).iter().map(|(nonce, _)| *nonce).collect();
        let misses: Vec<(u32, [u8; 32])> = (0..)
            .filter(|nonce| !solutions.contains(nonce))
            .map(|nonce| {
                let header = block_header_for_share(
                    &pool_job(),
                    EXTRANONCE_1,
                    lease["extranonce_2"].as_str().unwrap(),
                    pool_job().n_time,
                    nonce,
                )
                .unwrap();
                (nonce, sha256d(&header.to_bytes()))
            })
            .take(16)
            .collect();
        let rejected = || state.analytics.proofs_rejected.load(Ordering::Relaxed);
        let rejected_before = rejected();
        let (status, body) = prove(&state, &lease, &misses).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body, serde_json::json!("Invalid proof of work"));
        assert_eq!(rejected(), rejected_before + 1);
    }

    #[actix_web::test]
    async fn solutions_that_earned_a_token_do_not_count_again_beside_one_new_one() {
        let dir = ScratchDir::new("solutions-reused");
        let state = replay_state(&dir).await;
        let (_, first_lease) = new_lease(&state).await;
        let first = solve(&first_lease, 0);
        assert_eq!(prove(&state, &first_lease, &first).await.0, StatusCode::OK);

        // After a counter reset the same headers are valid for a new lease.
        serve_job(&state, 2, true).await;
        let (_, lease) = new_lease(&state).await;
        assert_eq!(lease["extranonce_2"], first_lease["extranonce_2"]);
        let after = first.last().unwrap().0 + 1;
        let mut mixed = first[1..].to_vec();
        mixed.extend(solutions_from(&lease, after, 1));
        let (status, body) = prove(&state, &lease, &mixed).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.get("token").is_none(), "{body}");

        let (_, retry) = new_lease(&state).await;
        let fresh = solutions_from(&retry, after, 16);
        let (status, body) = prove(&state, &retry, &fresh).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "sixteen new solutions still count: {body}"
        );
    }

    pub(crate) async fn replay_state(dir: &ScratchDir) -> web::Data<AppState> {
        let state = test_state(dir, None);
        state.pool_runtime_config.write().await.required_work_units = 8;
        serve_job(&state, 1, true).await;
        state
    }

    #[actix_web::test]
    async fn each_share_qualifying_solution_is_forwarded_and_the_pool_answer_reported() {
        let dir = ScratchDir::new("shares-forwarded");
        let state = replay_state(&dir).await;
        // A share target every hash meets, so each solution is also a share.
        {
            let mut pool = state.stratum_pool.lock().await;
            let mut job = pool.current_job.clone().unwrap();
            job.share_target = [0xff; 32];
            pool.jobs.insert(job.job.job_id.clone(), job.clone());
            pool.current_job = Some(job);
        }
        let analytics = &state.analytics;
        let count = |counter: &std::sync::atomic::AtomicU64| counter.load(Ordering::Relaxed);
        let answers: [(Result<bool, String>, &str, &std::sync::atomic::AtomicU64); 3] = [
            (Ok(true), "pool_accepted", &analytics.pool_shares_accepted),
            (Ok(false), "pool_rejected", &analytics.pool_shares_rejected),
            (
                Err("stale job".to_string()),
                "submission_error: stale job",
                &analytics.pool_candidates,
            ),
        ];
        for (answer, status_text, counter) in answers {
            let (sender, mut submissions) =
                tokio::sync::mpsc::channel::<stratum_client::ShareSubmission>(64);
            state.stratum_pool.lock().await.submit_sender = Some(sender);
            tokio::spawn(async move {
                while let Some(submission) = submissions.recv().await {
                    let _ = submission.response.send(answer.clone());
                }
            });
            let (_, lease) = new_lease(&state).await;
            let candidates_before = count(&analytics.pool_candidates);
            let counted_before = count(counter);

            let (status, body) = prove(&state, &lease, &solve(&lease, 0)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert!(body["token"].is_string(), "{body}");
            assert_eq!(body["pool_share"], status_text, "{body}");
            assert_eq!(count(&analytics.pool_candidates), candidates_before + 16);
            assert_eq!(count(counter), counted_before + 16, "{status_text}");
        }
    }

    #[actix_web::test]
    async fn a_solution_cannot_earn_a_second_token_after_the_extranonce2_counter_resets() {
        let dir = ScratchDir::new("replay-reset");
        let state = replay_state(&dir).await;
        let (status, first_lease) = new_lease(&state).await;
        assert_eq!(status, StatusCode::OK, "{first_lease}");
        assert_eq!(first_lease["extranonce_2"], "00");
        let solution = solve(&first_lease, 0);
        let (status, first) = prove(&state, &first_lease, &solution).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert!(first["token"].is_string());

        // The pool reconnects (or sends set_extranonce) and re-sends the same job:
        // the counter starts again at 00 under a new generation.
        serve_job(&state, 2, true).await;
        let (status, replay_lease) = new_lease(&state).await;
        assert_eq!(status, StatusCode::OK, "{replay_lease}");
        assert_eq!(replay_lease["extranonce_2"], "00");
        let (status, replay) = prove(&state, &replay_lease, &solution).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{replay}");
        assert!(replay.get("token").is_none(), "{replay}");

        let (status, fresh_lease) = new_lease(&state).await;
        assert_eq!(status, StatusCode::OK, "{fresh_lease}");
        let fresh = solve(&fresh_lease, 0);
        let (status, fresh) = prove(&state, &fresh_lease, &fresh).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "new work still earns a token: {fresh}"
        );
    }

    #[actix_web::test]
    async fn a_one_byte_extranonce2_is_not_reused_once_it_runs_out() {
        let dir = ScratchDir::new("replay-wrap");
        let state = replay_state(&dir).await;
        let (_, first_lease) = new_lease(&state).await;
        assert_eq!(first_lease["extranonce_2"], "00");
        let (status, _) = prove(&state, &first_lease, &solve(&first_lease, 0)).await;
        assert_eq!(status, StatusCode::OK);

        // 254 more leases later the counter reaches the last one-byte value.
        state.stratum_pool.lock().await.next_extranonce_2 = Some(255);
        let (status, last) = new_lease(&state).await;
        assert_eq!(status, StatusCode::OK, "{last}");
        assert_eq!(last["extranonce_2"], "ff");
        let (status, refused) = new_lease(&state).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the 257th lease must not wrap to 00: {refused}"
        );
    }
}

#[cfg(test)]
mod share_ledger_tests {
    use super::*;
    use crate::test_support::ScratchDir;

    fn share(number: u32) -> ShareLedgerRecord {
        ShareLedgerRecord {
            share_id: format!("share-{number:04}"),
            challenge_id: "challenge".to_string(),
            lease_id: "lease".to_string(),
            job_id: "job-1".to_string(),
            nonce: number,
            extranonce_2: "00000001".to_string(),
            header_hash: "00".repeat(32),
            status: "submission_pending".to_string(),
            recorded_at: DateTime::parse_from_rfc3339("2026-10-14T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    fn share_line(number: u32) -> Vec<u8> {
        ledger::encode_line(&share(number)).unwrap()
    }

    #[test]
    fn share_ledger_replay_skips_garbage_and_torn_lines() {
        let dir = ScratchDir::new("shares-replay");
        let path = dir.join("shares.jsonl");
        let mut content = share_line(1);
        content.extend_from_slice(b"garbage\n");
        content.extend_from_slice(&share_line(2));
        let torn = share_line(3);
        content.extend_from_slice(&torn[..torn.len() / 2]);
        std::fs::write(&path, content).unwrap();

        let (share_ledger, submitted, skipped) =
            load_share_ledger(&path, ledger::DEFAULT_MAX_BYTES)
                .expect("malformed share-ledger lines must not stop startup");
        drop(share_ledger);
        assert_eq!(skipped, 2);
        assert_eq!(
            submitted,
            HashSet::from(["share-0001".to_string(), "share-0002".to_string()])
        );
    }

    #[test]
    fn share_deduplication_survives_rotation() {
        let dir = ScratchDir::new("shares-rotation");
        let path = dir.join("shares.jsonl");
        let cap = share_line(0).len() as u64 * 2;
        let (mut share_ledger, _, _) = load_share_ledger(&path, cap).unwrap();
        for number in 0..6 {
            record_share(&mut share_ledger, share(number)).unwrap();
        }
        drop(share_ledger);

        assert!(
            ledger::rotated_path(&path, 2).exists(),
            "two records per file"
        );
        assert!(!ledger::rotated_path(&path, 3).exists());
        let (share_ledger, submitted, skipped) = load_share_ledger(&path, cap).unwrap();
        drop(share_ledger);
        assert_eq!(skipped, 0);
        assert_eq!(
            submitted,
            (0..6)
                .map(|number| format!("share-{number:04}"))
                .collect::<HashSet<_>>(),
            "shares in rotated files still count as already submitted"
        );
    }

    #[actix_web::test]
    async fn a_share_recorded_off_the_runtime_is_in_the_ledger() {
        let dir = ScratchDir::new("shares-off-runtime");
        let path = dir.join("shares.jsonl");
        let (share_ledger, _, _) = load_share_ledger(&path, ledger::DEFAULT_MAX_BYTES).unwrap();
        let share_ledger = Arc::new(StdMutex::new(share_ledger));
        record_share_off_runtime(&share_ledger, share(7))
            .await
            .unwrap();
        drop(share_ledger);
        let (_, submitted, _) = load_share_ledger(&path, ledger::DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(submitted, HashSet::from(["share-0007".to_string()]));
    }
}

#[cfg(test)]
#[path = "hardening_tests.rs"]
mod hardening_tests;

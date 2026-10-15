//! Stratum V1 request builders and the `mining.notify` parser.
//!
//! Purpose: build the subscribe and authorize requests the server sends to the
//! pool, and turn a `mining.notify` notification into a validated
//! [`StratumJob`]. A malformed notification is rejected rather than defaulted,
//! so the server never leases work it cannot reconstruct exactly.
//! Depends on: `serde_json`, `hex`. Used by: `server/src/stratum_client.rs`.

use crate::stratum::job::StratumJob;

/// Longest job identifier accepted from a pool.
pub const MAX_JOB_ID_BYTES: usize = 128;
/// Most merkle branches accepted in one job (a block with 2^32 transactions).
pub const MAX_MERKLE_BRANCHES: usize = 32;

/// Builds Stratum V1 requests and parses pool notifications.
#[derive(Default)]
pub struct StratumClient;

impl StratumClient {
    /// Create a new Stratum client.
    pub fn new() -> Self {
        StratumClient
    }

    /// Construct the Stratum subscription request.
    pub fn subscribe_request(&self) -> serde_json::Value {
        serde_json::json!({
            "method": "mining.subscribe",
            "jsonrpc": "2.0",
            "id": 1,
            "params": [],
        })
    }

    /// Construct the Stratum authorization request.
    pub fn authorize_request(&self, worker_name: &str) -> serde_json::Value {
        serde_json::json!({
            "method": "mining.authorize",
            "jsonrpc": "2.0",
            "id": 2,
            "params": [worker_name, "x"],
        })
    }

    /// Parse and validate a `mining.notify` notification. Every field is
    /// required: the job ID is a non-empty string, hashes are 32 bytes of hex,
    /// coinbase parts are non-empty hex, and version, nBits and nTime are eight
    /// hex digits each.
    pub fn parse_job_notification(
        &self,
        notification: &serde_json::Value,
    ) -> Result<StratumJob, String> {
        let params = notification
            .get("params")
            .ok_or("No params in notification")?
            .as_array()
            .ok_or("Params is not an array")?;
        if params.len() < 9 {
            return Err("Not enough parameters in notify".to_string());
        }

        let job_id = params[0].as_str().ok_or("Job ID must be a string")?;
        if job_id.is_empty()
            || job_id.len() > MAX_JOB_ID_BYTES
            || !job_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(format!(
                "Job ID must be 1-{MAX_JOB_ID_BYTES} printable ASCII characters"
            ));
        }
        let prev_block_hash = hash_hex(&params[1], "previous block hash")?;
        let coinbase_prefix = coinbase_hex(&params[2], "coinbase prefix")?;
        let coinbase_suffix = coinbase_hex(&params[3], "coinbase suffix")?;
        let branches = params[4]
            .as_array()
            .ok_or("Merkle branches must be an array")?;
        if branches.len() > MAX_MERKLE_BRANCHES {
            return Err(format!(
                "At most {MAX_MERKLE_BRANCHES} merkle branches are accepted"
            ));
        }
        let merkle_branches = branches
            .iter()
            .map(|branch| hash_hex(branch, "merkle branch"))
            .collect::<Result<Vec<_>, _>>()?;
        let coinbase_version = parse_hex_u32(params[5].as_str().ok_or("Invalid block version")?)?;
        let n_bits = parse_hex_u32(params[6].as_str().ok_or("Invalid nBits")?)?;
        let n_time = parse_hex_u32(params[7].as_str().ok_or("Invalid nTime")?)?;
        let clean_jobs = params[8].as_bool().ok_or("Invalid clean_jobs flag")?;
        let coinbase_data = format!("{coinbase_prefix}{coinbase_suffix}");

        Ok(StratumJob {
            job_id: job_id.to_string(),
            prev_block_hash,
            coinbase_version,
            coinbase_data,
            coinbase_prefix,
            coinbase_suffix,
            merkle_branches,
            merkle_root: String::new(),
            n_time,
            n_bits,
            clean_jobs,
        })
    }
}

/// A 32-byte value as exactly 64 hex characters.
fn hash_hex(value: &serde_json::Value, field: &str) -> Result<String, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("The {field} must be a string"))?;
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("The {field} must be 64 hex characters"));
    }
    Ok(text.to_string())
}

/// A non-empty, even-length hex string.
fn coinbase_hex(value: &serde_json::Value, field: &str) -> Result<String, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("The {field} must be a string"))?;
    if text.is_empty() || text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("The {field} must be non-empty, even-length hex"));
    }
    Ok(text.to_string())
}

/// Parse a Stratum 32-bit field: exactly eight hex digits.
pub fn parse_hex_u32(hex: &str) -> Result<u32, String> {
    if hex.len() != 8 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("Expected eight hex digits, got {hex:?}"));
    }
    u32::from_str_radix(hex, 16).map_err(|error| format!("Invalid hex value {hex:?}: {error}"))
}

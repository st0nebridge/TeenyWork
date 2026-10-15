/// A Bitcoin proof-of-work job received from the upstream pool via Stratum `mining.notify`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StratumJob {
    /// Job identifier string from pool.
    pub job_id: String,
    /// Previous block hash (hex).
    pub prev_block_hash: String,
    /// Coinbase version (u32).
    pub coinbase_version: u32,
    /// Coinbase data (hex string from pool).
    pub coinbase_data: String,
    /// Coinbase prefix supplied in the pool's `mining.notify` message.
    pub coinbase_prefix: String,
    /// Coinbase suffix supplied in the pool's `mining.notify` message.
    pub coinbase_suffix: String,
    /// Merkle branch hashes supplied in the pool's `mining.notify` message.
    pub merkle_branches: Vec<String>,
    /// Merkle root (hex); unavailable until the extranonce is assembled.
    pub merkle_root: String,
    /// nTime (hex timestamp).
    pub n_time: u32,
    /// nBits (target difficulty bits).
    pub n_bits: u32,
    /// Clean jobs flag — if true, stale work can be discarded.
    pub clean_jobs: bool,
}

impl StratumJob {
    /// Check if this job has the clean work flag set.
    pub fn is_clean(&self) -> bool {
        self.clean_jobs
    }
}

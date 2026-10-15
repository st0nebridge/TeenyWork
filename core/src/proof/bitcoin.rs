//! Bitcoin SHA-256d and the 80-byte block header the server reconstructs.

use sha2::{Digest, Sha256};

/// Double SHA-256 hash (Bitcoin SHA-256d).
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let mut hasher1 = Sha256::new();
    hasher1.update(data);
    let hash1 = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(&hash1);
    let hash2 = hasher2.finalize();

    hash2.as_slice().try_into().unwrap()
}

/// An 80-byte Bitcoin block header.
pub struct BlockHeader {
    /// Version (u32).
    pub version: u32,
    /// Previous block hash (32 bytes).
    pub prev_block_hash: [u8; 32],
    /// Merkle root (32 bytes).
    pub merkle_root: [u8; 32],
    /// Timestamp (u32).
    pub timestamp: u32,
    /// Target bits (u32).
    pub bits: u32,
    /// Nonce (u32).
    pub nonce: u32,
}

impl BlockHeader {
    /// Serialize the header to bytes (little-endian for fields, big-endian for hashes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version (4 bytes, little-endian)
        bytes.extend_from_slice(&self.version.to_le_bytes());

        // Previous block hash (32 bytes, big-endian)
        bytes.extend_from_slice(&self.prev_block_hash);

        // Merkle root (32 bytes, big-endian)
        bytes.extend_from_slice(&self.merkle_root);

        // Timestamp (4 bytes, little-endian)
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());

        // Bits (4 bytes, little-endian)
        bytes.extend_from_slice(&self.bits.to_le_bytes());

        // Nonce (4 bytes, little-endian)
        bytes.extend_from_slice(&self.nonce.to_le_bytes());

        bytes
    }
}

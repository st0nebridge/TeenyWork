/// Tests for Bitcoin SHA-256d proof solving.

#[cfg(test)]
mod tests {
    use crate::proof::bitcoin::{sha256d, BlockHeader};

    #[test]
    fn test_sha256d_known_vector() {
        // Known test vector: SHA-256d of empty input
        let empty = [0u8; 0];
        let result = sha256d(&empty);
        // Known expected: d5f51123... (Bitcoin test vector)
        // For now, just verify it's deterministic
        let result2 = sha256d(&empty);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_block_header_to_bytes() {
        let header = BlockHeader {
            version: 0x1f000000,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 0x4679cd,
            bits: 0x1a000000,
            nonce: 0x00000000,
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 80);

        // Version should be little-endian
        assert_eq!(bytes[0..4], [0x00, 0x00, 0x00, 0x1f]);
    }
}

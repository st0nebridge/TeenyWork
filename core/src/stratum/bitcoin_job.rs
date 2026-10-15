use crate::proof::bitcoin::{sha256d, BlockHeader};
use crate::stratum::job::StratumJob;

const DIFF1_TARGET_HEX: &str = "00000000ffff0000000000000000000000000000000000000000000000000000";

pub fn block_header_for_share(
    job: &StratumJob,
    extranonce_1: &str,
    extranonce_2: &str,
    n_time: u32,
    nonce: u32,
) -> Result<BlockHeader, String> {
    let prefix = decode_hex(&job.coinbase_prefix, "coinbase prefix")?;
    let extra_1 = decode_hex(extranonce_1, "extranonce1")?;
    let extra_2 = decode_hex(extranonce_2, "extranonce2")?;
    let suffix = decode_hex(&job.coinbase_suffix, "coinbase suffix")?;
    let mut coinbase =
        Vec::with_capacity(prefix.len() + extra_1.len() + extra_2.len() + suffix.len());
    coinbase.extend_from_slice(&prefix);
    coinbase.extend_from_slice(&extra_1);
    coinbase.extend_from_slice(&extra_2);
    coinbase.extend_from_slice(&suffix);

    let mut merkle_root = sha256d(&coinbase);
    for branch in &job.merkle_branches {
        let branch_bytes = decode_hex(branch, "merkle branch")?;
        if branch_bytes.len() != 32 {
            return Err("Merkle branch must be 32 bytes".to_string());
        }
        let mut pair = [0; 64];
        pair[..32].copy_from_slice(&merkle_root);
        pair[32..].copy_from_slice(&branch_bytes);
        merkle_root = sha256d(&pair);
    }

    let mut previous_hash = decode_hex(&job.prev_block_hash, "previous block hash")?;
    if previous_hash.len() != 32 {
        return Err("Previous block hash must be 32 bytes".to_string());
    }
    for word in previous_hash.chunks_exact_mut(4) {
        word.reverse();
    }

    let mut prev_block_hash = [0; 32];
    prev_block_hash.copy_from_slice(&previous_hash);
    Ok(BlockHeader {
        version: job.coinbase_version,
        prev_block_hash,
        merkle_root,
        timestamp: n_time,
        bits: job.n_bits,
        nonce,
    })
}

pub fn pool_share_target(difficulty: f64) -> Result<[u8; 32], String> {
    if !difficulty.is_finite() || difficulty <= 0.0 {
        return Err("Pool share difficulty must be finite and positive".to_string());
    }
    let diff1 = decode_hex(DIFF1_TARGET_HEX, "difficulty-1 target")?;
    let mut target = [0u8; 32];
    if difficulty < 1.0 {
        target.copy_from_slice(&diff1);
        return Ok(target);
    }

    let mut remainder = 0.0;
    for (index, byte) in diff1.iter().enumerate() {
        let numerator = remainder * 256.0 + f64::from(*byte);
        let quotient = (numerator / difficulty).floor().clamp(0.0, 255.0);
        target[index] = quotient as u8;
        remainder = numerator - quotient * difficulty;
    }
    Ok(target)
}

pub fn meets_difficulty_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    hash.iter().rev().cmp(target.iter()) != std::cmp::Ordering::Greater
}

pub fn meets_access_bits(hash: &[u8; 32], bits: u64) -> bool {
    if bits > 256 {
        return false;
    }
    let whole_bytes = (bits / 8) as usize;
    let remaining_bits = (bits % 8) as u8;
    let mut hash_be = hash.iter().rev();
    hash_be.clone().take(whole_bytes).all(|byte| *byte == 0)
        && (remaining_bits == 0
            || hash_be
                .nth(whole_bytes)
                .map(|byte| byte >> (8 - remaining_bits) == 0)
                .unwrap_or(false))
}

pub fn target_hex(target: &[u8; 32]) -> String {
    hex::encode(target)
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err(format!("{field} must be even-length hex"));
    }
    hex::decode(value).map_err(|_| format!("{field} must be valid hex"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_bitcoin_header_from_stratum_job() {
        let job = StratumJob {
            job_id: "job".into(),
            prev_block_hash: "01020304".repeat(8),
            coinbase_version: 0x20000000,
            coinbase_data: String::new(),
            coinbase_prefix: "01020304".into(),
            coinbase_suffix: "05060708".into(),
            merkle_branches: vec!["11".repeat(32)],
            merkle_root: String::new(),
            n_time: 0x65000000,
            n_bits: 0x170fffff,
            clean_jobs: true,
        };
        let header = block_header_for_share(&job, "aabb", "ccdd", job.n_time, 7).unwrap();
        assert_eq!(header.to_bytes().len(), 80);
        assert_eq!(&header.to_bytes()[4..8], &[4, 3, 2, 1]);
        assert_eq!(&header.to_bytes()[76..80], &7u32.to_le_bytes());
    }

    #[test]
    fn calculates_and_compares_pool_share_targets() {
        let diff1 = pool_share_target(1.0).unwrap();
        assert_eq!(hex::encode(diff1), DIFF1_TARGET_HEX);
        let target = pool_share_target(100_000.0).unwrap();
        assert_eq!(
            hex::encode(target),
            "000000000000a7c504816f0068db8bac710cb295e9e1b089a027525460aa64c2"
        );
        assert!(meets_difficulty_target(&[0; 32], &target));
        assert!(!meets_difficulty_target(&[0xff; 32], &target));
    }

    #[test]
    fn access_bits_use_bitcoin_hash_display_order() {
        let mut hash = [0xff; 32];
        hash[31] = 0;
        hash[30] = 0;
        hash[29] = 0x0f;
        assert!(meets_access_bits(&hash, 20));
        assert!(!meets_access_bits(&hash, 21));
        assert!(!meets_access_bits(&hash, 24));
        assert!(!meets_access_bits(&[0; 32], 257));
    }

    #[test]
    fn twenty_four_bits_reject_a_hash_that_meets_twenty_bits() {
        let mut hash = [0xff; 32];
        hash[31] = 0;
        hash[30] = 0;
        hash[29] = 0x0f;

        assert!(meets_access_bits(&hash, 20));
        assert!(!meets_access_bits(&hash, 24));
    }
}

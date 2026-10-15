//! @module c2a_challenger tests
//! @description Unit tests for the solver, and a differential test that holds
//! the midstate search to the straightforward `sha2` search it replaced.

use super::search::{
    access_lead_limit, display_lead, meets_access_bits, meets_target, search, HeaderWork,
    SearchResult, HEADER_BYTES, TARGET_BYTES,
};
use super::{challenger_alloc, challenger_dealloc, challenger_search, write_result, RESULT_BYTES};
use sha2::{Digest, Sha256};

fn sha256d(header: &[u8; HEADER_BYTES]) -> [u8; 32] {
    let first_hash = Sha256::digest(header);
    Sha256::digest(first_hash).into()
}

/// The search as it was before the midstate kernel (`sha2`, three
/// compressions per nonce, every hash checked exactly): the oracle.
fn reference_search(
    header: &[u8; HEADER_BYTES],
    target: &[u8; TARGET_BYTES],
    access_bits: u32,
    nonce_start: u32,
    nonce_count: u32,
    continue_after_access: bool,
) -> SearchResult {
    let mut result = SearchResult::default();
    let mut candidate_header = *header;

    for offset in 0..nonce_count {
        let Some(nonce) = nonce_start.checked_add(offset) else {
            break;
        };
        candidate_header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let hash = sha256d(&candidate_header);
        result.hashes_attempted += 1;

        if result.access.is_none() && meets_access_bits(&hash, access_bits) {
            result.access = Some((nonce, hash));
            if !continue_after_access {
                break;
            }
        }
        if result.pool.is_none() && meets_target(&hash, target) {
            result.pool = Some((nonce, hash));
            break;
        }
    }

    result
}

/// SplitMix64: a small deterministic generator, so failures reproduce.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = self.next() as u8;
        }
    }

    fn below(&mut self, bound: u32) -> u32 {
        (self.next() % u64::from(bound)) as u32
    }
}

fn encoded(result: SearchResult) -> [u8; RESULT_BYTES] {
    let mut output = [0xAAu8; RESULT_BYTES];
    write_result(&mut output, result);
    output
}

fn header_with_nonce(header: &[u8; HEADER_BYTES], nonce: u32) -> [u8; HEADER_BYTES] {
    let mut candidate = *header;
    candidate[76..80].copy_from_slice(&nonce.to_le_bytes());
    candidate
}

#[test]
fn batch_finds_access_and_pool_candidates_independently() {
    let header = [0u8; HEADER_BYTES];
    let target = [0xff; TARGET_BYTES];
    let result = search(&header, &target, 0, 7, 5, true);

    assert_eq!(result.hashes_attempted, 1);
    assert_eq!(result.access.as_ref().map(|candidate| candidate.0), Some(7));
    assert_eq!(result.pool.as_ref().map(|candidate| candidate.0), Some(7));
}

#[test]
fn bounded_batch_does_not_claim_a_pool_share_for_a_zero_target() {
    let header = [0u8; HEADER_BYTES];
    let target = [0u8; TARGET_BYTES];
    let result = search(&header, &target, 256, 11, 4, true);

    assert_eq!(result.hashes_attempted, 4);
    assert!(result.access.is_none());
    assert!(result.pool.is_none());
}

#[test]
fn a_harder_access_target_rejects_a_candidate_accepted_at_twenty_bits() {
    let mut header = [0u8; HEADER_BYTES];
    let target = [0u8; TARGET_BYTES];
    let candidate_nonce = (0u32..1_000_000)
        .find(|nonce| {
            header[76..80].copy_from_slice(&nonce.to_le_bytes());
            let hash = sha256d(&header);
            meets_access_bits(&hash, 20) && !meets_access_bits(&hash, 24)
        })
        .expect("a 20-bit candidate should be found within one million hashes");

    let twenty_bit = search(&header, &target, 20, candidate_nonce, 1, false);
    let twenty_four_bit = search(&header, &target, 24, candidate_nonce, 1, false);

    assert!(twenty_bit.access.is_some());
    assert!(twenty_four_bit.access.is_none());
}

#[test]
fn form_search_stops_on_its_first_access_proof() {
    let header = [0u8; HEADER_BYTES];
    let target = [0u8; TARGET_BYTES];
    let result = search(&header, &target, 0, 23, 16, false);

    assert_eq!(result.hashes_attempted, 1);
    assert!(result.access.is_some());
    assert!(result.pool.is_none());
}

#[test]
fn form_search_reports_only_the_access_proof_when_its_nonce_also_meets_the_pool_target() {
    let header = [0u8; HEADER_BYTES];
    let target = [0xff; TARGET_BYTES];
    let result = search(&header, &target, 0, 23, 16, false);

    assert_eq!(result.hashes_attempted, 1);
    assert_eq!(
        result.access.as_ref().map(|candidate| candidate.0),
        Some(23)
    );
    assert!(
        result.pool.is_none(),
        "the form search stops before the pool check"
    );
}

#[test]
fn difficulty_comparison_uses_bitcoin_display_order() {
    let target = [0x80; TARGET_BYTES];
    let mut lower_hash = [0; 32];
    lower_hash[31] = 0x7f;
    assert!(meets_target(&lower_hash, &target));

    let mut higher_hash = [0; 32];
    higher_hash[31] = 0x81;
    assert!(!meets_target(&higher_hash, &target));

    let equal_hash: [u8; 32] = core::array::from_fn(|index| target[31 - index]);
    assert!(
        meets_target(&equal_hash, &target),
        "a hash equal to the target meets it"
    );
}

#[test]
fn midstate_hash_matches_sha256d_of_the_whole_header() {
    let mut rng = Rng(1);
    for _ in 0..200 {
        let mut header = [0u8; HEADER_BYTES];
        rng.fill(&mut header);
        let nonce = rng.next() as u32;
        let work = HeaderWork::new(&header);
        assert_eq!(
            work.hash(nonce),
            sha256d(&header_with_nonce(&header, nonce))
        );
    }
}

#[test]
fn the_last_word_is_the_last_four_digest_bytes() {
    let mut rng = Rng(2);
    for _ in 0..200 {
        let mut header = [0u8; HEADER_BYTES];
        rng.fill(&mut header);
        let nonce = rng.next() as u32;
        let hash = sha256d(&header_with_nonce(&header, nonce));
        let last_word = HeaderWork::new(&header).last_word(nonce.swap_bytes());
        assert_eq!(
            last_word,
            u32::from_be_bytes([hash[28], hash[29], hash[30], hash[31]])
        );
        assert_eq!(
            display_lead(last_word),
            u32::from_be_bytes([hash[31], hash[30], hash[29], hash[28]]),
            "the display lead is the reversed hash's first four bytes"
        );
    }
}

#[test]
fn access_lead_limit_is_the_largest_lead_with_that_many_zero_bits() {
    assert_eq!(access_lead_limit(0), u32::MAX);
    assert_eq!(access_lead_limit(1), 0x7fff_ffff);
    assert_eq!(access_lead_limit(8), 0x00ff_ffff);
    assert_eq!(access_lead_limit(24), 0x0000_00ff);
    assert_eq!(access_lead_limit(31), 1);
    assert_eq!(access_lead_limit(32), 0);
    assert_eq!(access_lead_limit(33), 0);
    assert_eq!(access_lead_limit(256), 0);
    for bits in 0..=32 {
        let limit = access_lead_limit(bits);
        let mut hash = [0xffu8; 32];
        hash[28..32].copy_from_slice(&limit.swap_bytes().to_be_bytes());
        // `limit` is the largest lead whose hash can meet `bits`; one more cannot.
        assert_eq!(
            display_lead(u32::from_be_bytes([hash[28], hash[29], hash[30], hash[31]])),
            limit
        );
        assert!(
            meets_access_bits(&hash, bits),
            "{bits} bits, lead {limit:#x}"
        );
        if let Some(over) = limit.checked_add(1) {
            hash[28..32].copy_from_slice(&over.swap_bytes().to_be_bytes());
            assert!(
                !meets_access_bits(&hash, bits),
                "{bits} bits, lead {over:#x}"
            );
        }
    }
}

#[test]
fn search_stops_before_the_nonce_passes_u32_max() {
    let header = [3u8; HEADER_BYTES];
    let target = [0u8; TARGET_BYTES];
    let result = search(&header, &target, 256, u32::MAX - 5, 20, true);
    assert_eq!(result.hashes_attempted, 6);
    assert_eq!(
        encoded(result),
        encoded(reference_search(
            &header,
            &target,
            256,
            u32::MAX - 5,
            20,
            true
        ))
    );
}

#[test]
fn search_matches_the_reference_search_on_random_work() {
    let mut rng = Rng(0x07ee_11e5);
    let bits_choices = [0, 1, 3, 4, 7, 8, 9, 10, 12, 16, 32, 33, 256];
    for case in 0..400 {
        let mut header = [0u8; HEADER_BYTES];
        rng.fill(&mut header);
        let bits = bits_choices[case % bits_choices.len()];
        let nonce_start = match case % 5 {
            0 => u32::MAX - rng.below(64),
            _ => rng.next() as u32,
        };
        let nonce_count = rng.below(2048);
        let continue_after_access = case % 2 == 0;

        let mut target = [0u8; TARGET_BYTES];
        match case % 4 {
            // No pool target can be met.
            0 => {}
            // Every hash meets the pool target.
            1 => target = [0xff; TARGET_BYTES],
            // A target whose first four bytes equal a hash in range, so the
            // later bytes decide: the exact comparison must run.
            2 => {
                rng.fill(&mut target);
                let nonce = nonce_start.wrapping_add(rng.below(nonce_count.max(1)));
                let hash = sha256d(&header_with_nonce(&header, nonce));
                target[..4].copy_from_slice(&[hash[31], hash[30], hash[29], hash[28]]);
            }
            // A random lead around one in 2^12.
            _ => {
                rng.fill(&mut target);
                target[0] = 0;
                target[1] &= 0x0f;
            }
        }

        let expected = reference_search(
            &header,
            &target,
            bits,
            nonce_start,
            nonce_count,
            continue_after_access,
        );
        let actual = search(
            &header,
            &target,
            bits,
            nonce_start,
            nonce_count,
            continue_after_access,
        );
        assert_eq!(
            encoded(actual),
            encoded(expected),
            "case {case}: bits {bits}, start {nonce_start}, count {nonce_count}, \
             continue {continue_after_access}"
        );
    }
}

#[test]
fn the_export_refuses_null_pointers_and_more_than_256_bits() {
    let header = [0u8; HEADER_BYTES];
    let target = [0u8; TARGET_BYTES];
    let mut output = [0u8; RESULT_BYTES];
    let null = std::ptr::null();
    unsafe {
        let out = output.as_mut_ptr();
        assert_eq!(challenger_search(null, target.as_ptr(), 8, 0, 1, 0, out), 1);
        assert_eq!(challenger_search(header.as_ptr(), null, 8, 0, 1, 0, out), 1);
        assert_eq!(
            challenger_search(
                header.as_ptr(),
                target.as_ptr(),
                8,
                0,
                1,
                0,
                std::ptr::null_mut()
            ),
            1
        );
        assert_eq!(
            challenger_search(header.as_ptr(), target.as_ptr(), 257, 0, 1, 0, out),
            1
        );
        assert_eq!(
            challenger_search(header.as_ptr(), target.as_ptr(), 256, 0, 1, 0, out),
            0
        );
    }
}

#[test]
fn the_export_writes_the_documented_result_layout() {
    let mut rng = Rng(3);
    let mut header = [0u8; HEADER_BYTES];
    rng.fill(&mut header);
    let target = [0xffu8; TARGET_BYTES];
    let mut output = [0xAAu8; RESULT_BYTES];
    let status = unsafe {
        challenger_search(
            header.as_ptr(),
            target.as_ptr(),
            0,
            5,
            3,
            1,
            output.as_mut_ptr(),
        )
    };
    assert_eq!(status, 0);
    let hash = sha256d(&header_with_nonce(&header, 5));
    let word = |offset: usize| u32::from_le_bytes(output[offset..offset + 4].try_into().unwrap());
    assert_eq!(word(0), 1, "nonces hashed");
    assert_eq!((word(4), word(8)), (1, 5), "access flag and nonce");
    assert_eq!(&output[12..44], &hash);
    assert_eq!((word(44), word(48)), (1, 5), "pool flag and nonce");
    assert_eq!(&output[52..84], &hash);
    assert_eq!(output, encoded(search(&header, &target, 0, 5, 3, true)));
}

#[test]
fn memory_comes_and_goes_through_the_exports() {
    let pointer = challenger_alloc(RESULT_BYTES);
    assert!(!pointer.is_null());
    unsafe {
        pointer.write_bytes(7, RESULT_BYTES);
        challenger_dealloc(pointer, RESULT_BYTES);
        challenger_dealloc(std::ptr::null_mut(), RESULT_BYTES);
    }
    assert!(
        challenger_alloc(usize::MAX).is_null(),
        "an impossible size is refused"
    );
}

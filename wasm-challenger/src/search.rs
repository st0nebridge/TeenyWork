//! @module search
//! @description Searches a range of nonces in one 80-byte Bitcoin header for
//! the first hash that meets the access bits and the first that meets the
//! pool target.
//!
//! @input A header, a 32-byte pool target, the access bits, a nonce range and
//! whether to keep searching after an access proof.
//! @output A `SearchResult`: nonces hashed, and each candidate's nonce and hash.
//! @dependencies `sha256` (compression), `lanes4` (SIMD builds only).
//!
//! Per lease, the first 64 header bytes never change, so their SHA-256 state
//! (the midstate) is computed once per call. Each nonce then costs one
//! compression for the rest of the header and one for the second SHA-256,
//! where `sha2::Sha256::digest` twice cost three plus buffering.
//!
//! The second compression is cut short: a nonce is examined in full only
//! when the last word of its hash could meet a target. In display order that
//! word is the hash's first four bytes, so a hash with `bits` leading zero
//! bits has that word at most `u32::MAX >> bits`, and a hash at or under the
//! pool target has it at most the target's first four bytes. Nonces that
//! pass this test are hashed again in full and checked exactly, so the
//! result is the same as checking every hash exactly.

use crate::sha256::{compress, Lane, IV};

pub const HEADER_BYTES: usize = 80;
pub const TARGET_BYTES: usize = 32;

/// SHA-256 padding for the 16-byte tail of an 80-byte header (640 bits).
const HEADER_TAIL_PADDING: u32 = 0x8000_0000;
const HEADER_BITS: u32 = 640;
/// SHA-256 padding for hashing a 32-byte digest again (256 bits).
const DIGEST_PADDING: u32 = 0x8000_0000;
const DIGEST_BITS: u32 = 256;

#[derive(Default)]
pub struct SearchResult {
    pub hashes_attempted: u32,
    pub access: Option<(u32, [u8; 32])>,
    pub pool: Option<(u32, [u8; 32])>,
}

/// The parts of a header that stay the same for every nonce.
#[derive(Clone, Copy)]
pub struct HeaderWork {
    /// SHA-256 state after the first 64 header bytes.
    midstate: [u32; 8],
    /// Header bytes 64..76 (end of the merkle root, nTime, nBits) as words.
    tail: [u32; 3],
}

fn be_word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

impl HeaderWork {
    pub fn new(header: &[u8; HEADER_BYTES]) -> Self {
        let first_block: [u32; 16] = core::array::from_fn(|index| be_word(header, index * 4));
        Self {
            midstate: compress(&IV, &first_block),
            tail: [
                be_word(header, 64),
                be_word(header, 68),
                be_word(header, 72),
            ],
        }
    }

    /// The second header block. `nonce_word` is the nonce as SHA-256 reads
    /// it: the header stores the nonce little-endian, SHA-256 reads big-endian.
    #[inline(always)]
    fn tail_block<L: Lane>(&self, nonce_word: L) -> [L; 16] {
        let zero = L::splat(0);
        [
            L::splat(self.tail[0]),
            L::splat(self.tail[1]),
            L::splat(self.tail[2]),
            nonce_word,
            L::splat(HEADER_TAIL_PADDING),
            zero,
            zero,
            zero,
            zero,
            zero,
            zero,
            zero,
            zero,
            zero,
            zero,
            L::splat(HEADER_BITS),
        ]
    }

    #[inline(always)]
    fn digest_block<L: Lane>(first_hash: &[L; 8]) -> [L; 16] {
        let zero = L::splat(0);
        [
            first_hash[0],
            first_hash[1],
            first_hash[2],
            first_hash[3],
            first_hash[4],
            first_hash[5],
            first_hash[6],
            first_hash[7],
            L::splat(DIGEST_PADDING),
            zero,
            zero,
            zero,
            zero,
            zero,
            zero,
            L::splat(DIGEST_BITS),
        ]
    }

    /// The last state word of SHA-256d. Only this word is read, so the
    /// compiler drops the final rounds that do not contribute to it.
    #[inline(always)]
    pub fn last_word<L: Lane>(&self, nonce_word: L) -> L {
        let first_hash = compress(&self.midstate.map(L::splat), &self.tail_block(nonce_word));
        compress(&IV.map(L::splat), &Self::digest_block(&first_hash))[7]
    }

    /// The full SHA-256d of the header with `nonce`, as SHA-256 outputs it.
    #[inline(never)]
    pub fn hash(&self, nonce: u32) -> [u8; 32] {
        let first_hash = compress(&self.midstate, &self.tail_block(nonce.swap_bytes()));
        let digest = compress(&IV, &Self::digest_block(&first_hash));
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(digest) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        bytes
    }
}

/// The hash's first four bytes in Bitcoin display order (byte-reversed), as
/// a big-endian number, from the last SHA-256 state word.
#[inline(always)]
pub fn display_lead(last_word: u32) -> u32 {
    last_word.swap_bytes()
}

pub fn meets_access_bits(hash: &[u8; 32], bits: u32) -> bool {
    (0..bits / 8).all(|index| hash[31 - index as usize] == 0)
        && (bits.is_multiple_of(8) || hash[31 - (bits / 8) as usize] >> (8 - bits % 8) == 0)
}

pub fn meets_target(hash: &[u8; 32], target: &[u8; TARGET_BYTES]) -> bool {
    for index in (0..32).rev() {
        match hash[index].cmp(&target[31 - index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// The largest display lead a hash with `bits` leading zero bits can have.
pub fn access_lead_limit(bits: u32) -> u32 {
    u32::MAX.checked_shr(bits).unwrap_or(0)
}

/// Search state shared by the scalar and SIMD loops.
pub struct Search<'a> {
    work: HeaderWork,
    target: &'a [u8; TARGET_BYTES],
    access_bits: u32,
    continue_after_access: bool,
    target_lead: u32,
    /// A nonce whose display lead is above this cannot be a candidate.
    pub lead_limit: u32,
    pub result: SearchResult,
}

impl<'a> Search<'a> {
    pub fn new(
        header: &[u8; HEADER_BYTES],
        target: &'a [u8; TARGET_BYTES],
        access_bits: u32,
        continue_after_access: bool,
    ) -> Self {
        let target_lead = be_word(target, 0);
        Self {
            work: HeaderWork::new(header),
            target,
            access_bits,
            continue_after_access,
            target_lead,
            lead_limit: access_lead_limit(access_bits).max(target_lead),
            result: SearchResult::default(),
        }
    }

    /// A copy of the header work for a hot loop, held apart from the state
    /// `examine` mutates.
    #[cfg(target_feature = "simd128")]
    pub fn work(&self) -> HeaderWork {
        self.work
    }

    /// Checks a nonce that passed the lead filter exactly, in the order the
    /// search has always used. Returns true when the search must stop.
    #[inline(never)]
    pub fn examine(&mut self, nonce: u32) -> bool {
        let hash = self.work.hash(nonce);
        if self.result.access.is_none() && meets_access_bits(&hash, self.access_bits) {
            self.result.access = Some((nonce, hash));
            if !self.continue_after_access {
                return true;
            }
            self.lead_limit = self.target_lead;
        }
        if self.result.pool.is_none() && meets_target(&hash, self.target) {
            self.result.pool = Some((nonce, hash));
            return true;
        }
        false
    }

    /// Hashes nonces one at a time from `nonce_start + offset` until `nonce_count`
    /// nonces have been tried, the nonce would pass `u32::MAX`, or a candidate
    /// ends the search.
    pub fn scalar(&mut self, nonce_start: u32, mut offset: u32, nonce_count: u32) {
        let work = self.work;
        while offset < nonce_count {
            let Some(nonce) = nonce_start.checked_add(offset) else {
                return;
            };
            offset += 1;
            self.result.hashes_attempted += 1;
            let lead = display_lead(work.last_word(nonce.swap_bytes()));
            if lead <= self.lead_limit && self.examine(nonce) {
                return;
            }
        }
    }
}

/// Searches `nonce_count` nonces from `nonce_start` (stopping before the nonce
/// would pass `u32::MAX`). Stops at the first access proof unless
/// `continue_after_access`, and always at the first pool-target hash.
pub fn search(
    header: &[u8; HEADER_BYTES],
    target: &[u8; TARGET_BYTES],
    access_bits: u32,
    nonce_start: u32,
    nonce_count: u32,
    continue_after_access: bool,
) -> SearchResult {
    let mut search = Search::new(header, target, access_bits, continue_after_access);
    #[cfg(target_feature = "simd128")]
    let offset = crate::lanes4::search_fours(&mut search, nonce_start, nonce_count);
    #[cfg(not(target_feature = "simd128"))]
    let offset = Some(0);
    if let Some(offset) = offset {
        search.scalar(nonce_start, offset, nonce_count);
    }
    search.result
}

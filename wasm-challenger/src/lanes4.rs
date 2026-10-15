//! @module lanes4
//! @description Four-way WebAssembly SIMD lanes for the SHA-256 compression,
//! and the nonce loop that hashes four consecutive nonces per step.
//!
//! @input The shared `Search` state and a nonce range.
//! @output Nonces hashed into `Search::result`; the offset left for the scalar loop.
//! @dependencies `core::arch::wasm32` (simd128), `sha256::Lane`, `search`.
//!
//! Compiled only with `-C target-feature=+simd128`. Lanes are examined in nonce
//! order with the same filter and exact checks as the scalar loop, so a
//! SIMD build returns exactly what the scalar build returns.

use core::arch::wasm32::{
    i32x4_add, i32x4_shl, i8x16_shuffle, u32x4, u32x4_extract_lane, u32x4_le, u32x4_shr,
    u32x4_splat, v128, v128_any_true, v128_bitselect, v128_or, v128_xor,
};

use crate::search::Search;
use crate::sha256::Lane;

/// Four 32-bit words in one `v128`.
#[derive(Clone, Copy)]
pub struct X4(v128);

impl Lane for X4 {
    #[inline(always)]
    fn splat(value: u32) -> Self {
        X4(u32x4_splat(value))
    }
    #[inline(always)]
    fn add(self, other: Self) -> Self {
        X4(i32x4_add(self.0, other.0))
    }
    #[inline(always)]
    fn xor(self, other: Self) -> Self {
        X4(v128_xor(self.0, other.0))
    }
    #[inline(always)]
    fn rotr(self, bits: u32) -> Self {
        X4(v128_or(
            u32x4_shr(self.0, bits),
            i32x4_shl(self.0, 32 - bits),
        ))
    }
    #[inline(always)]
    fn shr(self, bits: u32) -> Self {
        X4(u32x4_shr(self.0, bits))
    }
    #[inline(always)]
    fn ch(e: Self, f: Self, g: Self) -> Self {
        X4(v128_bitselect(f.0, g.0, e.0))
    }
    #[inline(always)]
    fn maj(a: Self, b: Self, c: Self) -> Self {
        // Where a and c differ, b decides; where they agree, they win.
        X4(v128_bitselect(b.0, a.0, v128_xor(a.0, c.0)))
    }
}

/// Reverses the bytes of each 32-bit lane.
#[inline(always)]
fn swap_lane_bytes(value: v128) -> v128 {
    i8x16_shuffle::<3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12>(value, value)
}

/// Hashes nonces four at a time while four whole nonces remain below both
/// `nonce_count` and `u32::MAX`. Returns the offset the scalar loop should
/// continue from, or `None` when a candidate has ended the search.
pub fn search_fours(search: &mut Search, nonce_start: u32, nonce_count: u32) -> Option<u32> {
    let work = search.work();
    let steps = u32x4(0, 1, 2, 3);
    let mut offset = 0u32;
    while nonce_count - offset >= 4 {
        let Some(first) = nonce_start.checked_add(offset) else {
            break;
        };
        if first.checked_add(3).is_none() {
            break;
        }
        let nonces = i32x4_add(u32x4_splat(first), steps);
        let last_words = work.last_word(X4(swap_lane_bytes(nonces)));
        let leads = swap_lane_bytes(last_words.0);
        if !v128_any_true(u32x4_le(leads, u32x4_splat(search.lead_limit))) {
            search.result.hashes_attempted += 4;
            offset += 4;
            continue;
        }
        let lanes = [
            u32x4_extract_lane::<0>(leads),
            u32x4_extract_lane::<1>(leads),
            u32x4_extract_lane::<2>(leads),
            u32x4_extract_lane::<3>(leads),
        ];
        for (lane, lead) in (0u32..).zip(lanes) {
            search.result.hashes_attempted += 1;
            // The limit only ever falls, so a lane that passed before an access
            // proof is checked again against the lower limit.
            if lead <= search.lead_limit && search.examine(first + lane) {
                return None;
            }
        }
        offset += 4;
    }
    Some(offset)
}

//! @module c2a_challenger
//! @description The browser solver's WebAssembly interface: memory helpers and
//! `challenger_search`, which the TeenyWork worker (`browser/challenger.js`)
//! and a site's own worker call over a prepared 80-byte header.
//!
//! @input Pointers into WebAssembly memory: header (80 bytes), pool target
//! (32 bytes), output (84 bytes); access bits; a nonce range; a continue flag.
//! @output 0 on success with the result written to the output; 1 on bad input.
//! @dependencies `search` (the nonce loop), `sha256`, `lanes4` (SIMD builds).
//!
//! The exports and the 84-byte result layout are a contract with every worker
//! that loads the module, and do not change between the scalar and SIMD builds:
//! `[0..4]` nonces hashed, `[4..8]` access flag, `[8..12]` access nonce,
//! `[12..44]` access hash, `[44..48]` pool flag, `[48..52]` pool nonce,
//! `[52..84]` pool hash; integers little-endian.

use std::alloc::{alloc, dealloc, Layout};
use std::slice;

#[cfg(target_feature = "simd128")]
mod lanes4;
mod search;
mod sha256;

use search::{search, SearchResult, HEADER_BYTES, TARGET_BYTES};

const RESULT_BYTES: usize = 84;

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_result(output: &mut [u8], result: SearchResult) {
    output.fill(0);
    write_u32(output, 0, result.hashes_attempted);
    if let Some((nonce, hash)) = result.access {
        write_u32(output, 4, 1);
        write_u32(output, 8, nonce);
        output[12..44].copy_from_slice(&hash);
    }
    if let Some((nonce, hash)) = result.pool {
        write_u32(output, 44, 1);
        write_u32(output, 48, nonce);
        output[52..84].copy_from_slice(&hash);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn challenger_alloc(length: usize) -> *mut u8 {
    let Ok(layout) = Layout::array::<u8>(length) else {
        return std::ptr::null_mut();
    };
    unsafe { alloc(layout) }
}

/// # Safety
///
/// `pointer` must come from `challenger_alloc(length)` with the same `length`,
/// and must not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn challenger_dealloc(pointer: *mut u8, length: usize) {
    if !pointer.is_null() && length > 0 {
        if let Ok(layout) = Layout::array::<u8>(length) {
            unsafe { dealloc(pointer, layout) };
        }
    }
}

/// # Safety
///
/// `header_pointer` must point to 80 readable bytes, `target_pointer` to 32,
/// and `output_pointer` to 84 writable bytes that overlap neither.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn challenger_search(
    header_pointer: *const u8,
    target_pointer: *const u8,
    access_bits: u32,
    nonce_start: u32,
    nonce_count: u32,
    continue_after_access: u32,
    output_pointer: *mut u8,
) -> u32 {
    if header_pointer.is_null()
        || target_pointer.is_null()
        || output_pointer.is_null()
        || access_bits > 256
    {
        return 1;
    }

    let header: &[u8; HEADER_BYTES] = unsafe { &*(header_pointer.cast::<[u8; HEADER_BYTES]>()) };
    let target: &[u8; TARGET_BYTES] = unsafe { &*(target_pointer.cast::<[u8; TARGET_BYTES]>()) };
    let result = search(
        header,
        target,
        access_bits,
        nonce_start,
        nonce_count,
        continue_after_access != 0,
    );
    let output = unsafe { slice::from_raw_parts_mut(output_pointer, RESULT_BYTES) };
    write_result(output, result);
    0
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

//! @module sha256
//! @description The SHA-256 compression function, written once over a `Lane`
//! so the same code hashes one nonce (`u32`) or four at a time (`X4` in
//! `lanes4.rs`, WebAssembly SIMD builds only).
//!
//! @input A chaining state and one 64-byte block as 16 big-endian words.
//! @output The next chaining state.
//! @dependencies none. Used by `search.rs`.
//!
//! The rounds are written out in full, so when a caller passes block words
//! that are constants (SHA-256 padding, the header fields that stay fixed
//! for a lease) the compiler folds them away, and when a caller reads only
//! one word of the result it drops the rounds that do not feed that word.

/// The SHA-256 initial chaining value.
pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// One 32-bit word, or several processed in lockstep.
pub trait Lane: Copy {
    fn splat(value: u32) -> Self;
    fn add(self, other: Self) -> Self;
    fn xor(self, other: Self) -> Self;
    fn rotr(self, bits: u32) -> Self;
    fn shr(self, bits: u32) -> Self;
    /// SHA-256 Ch: for each bit, `f` where `e` is set, otherwise `g`.
    fn ch(e: Self, f: Self, g: Self) -> Self;
    /// SHA-256 Maj: the majority of `a`, `b` and `c` in each bit.
    fn maj(a: Self, b: Self, c: Self) -> Self;
}

impl Lane for u32 {
    #[inline(always)]
    fn splat(value: u32) -> Self {
        value
    }
    #[inline(always)]
    fn add(self, other: Self) -> Self {
        self.wrapping_add(other)
    }
    #[inline(always)]
    fn xor(self, other: Self) -> Self {
        self ^ other
    }
    #[inline(always)]
    fn rotr(self, bits: u32) -> Self {
        self.rotate_right(bits)
    }
    #[inline(always)]
    fn shr(self, bits: u32) -> Self {
        self >> bits
    }
    #[inline(always)]
    fn ch(e: Self, f: Self, g: Self) -> Self {
        g ^ (e & (f ^ g))
    }
    #[inline(always)]
    fn maj(a: Self, b: Self, c: Self) -> Self {
        (a & b) | (c & (a | b))
    }
}

#[inline(always)]
fn big_sigma0<L: Lane>(x: L) -> L {
    x.rotr(2).xor(x.rotr(13)).xor(x.rotr(22))
}

#[inline(always)]
fn big_sigma1<L: Lane>(x: L) -> L {
    x.rotr(6).xor(x.rotr(11)).xor(x.rotr(25))
}

#[inline(always)]
fn small_sigma0<L: Lane>(x: L) -> L {
    x.rotr(7).xor(x.rotr(18)).xor(x.shr(3))
}

#[inline(always)]
fn small_sigma1<L: Lane>(x: L) -> L {
    x.rotr(17).xor(x.rotr(19)).xor(x.shr(10))
}

/// Compresses one block into `state` and returns the new chaining state.
#[inline(always)]
pub fn compress<L: Lane>(state: &[L; 8], block: &[L; 16]) -> [L; 8] {
    let mut w = [L::splat(0); 64];
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    macro_rules! round {
        ($i:literal) => {
            let t1 = h
                .add(big_sigma1(e))
                .add(L::ch(e, f, g))
                .add(L::splat(K[$i]))
                .add(w[$i]);
            let t2 = big_sigma0(a).add(L::maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.add(t2);
        };
    }
    macro_rules! message_rounds {
        ($($i:literal)*) => {$(
            w[$i] = block[$i];
            round!($i);
        )*};
    }
    macro_rules! schedule_rounds {
        ($($i:literal)*) => {$(
            w[$i] = small_sigma1(w[$i - 2])
                .add(w[$i - 7])
                .add(small_sigma0(w[$i - 15]))
                .add(w[$i - 16]);
            round!($i);
        )*};
    }

    message_rounds!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);
    schedule_rounds!(
        16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
        32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47
        48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63
    );

    [
        a.add(state[0]),
        b.add(state[1]),
        c.add(state[2]),
        d.add(state[3]),
        e.add(state[4]),
        f.add(state[5]),
        g.add(state[6]),
        h.add(state[7]),
    ]
}

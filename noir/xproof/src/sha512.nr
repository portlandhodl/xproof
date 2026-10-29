// sha512.nr — SHA-512 (FIPS 180-4) compression + HMAC-SHA512 specialised to BIP32 CKDpub.
// Constants are checked against their definitions (square/cube roots of the first primes)
// by tools/check-sha512-constants.py.

pub global IV: [u64; 8] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];

global K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

use std::ops::WrappingAdd;

fn wa(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

fn rotr(x: u64, n: u64) -> u64 {
    (x >> n) | (x << (64 - n))
}

pub fn compress(state: [u64; 8], block: [u64; 16]) -> [u64; 8] {
    let mut w: [u64; 80] = [0; 80];
    for i in 0..16 {
        w[i] = block[i];
    }
    for i in 16..80 {
        let s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
        let s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = wa(wa(w[i - 16], s0), wa(w[i - 7], s1));
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for i in 0..80 {
        let s1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
        let ch = (e & f) ^ (!e & g);
        let t1 = wa(wa(wa(h, s1), wa(ch, K[i])), w[i]);
        let s0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = wa(s0, maj);
        h = g;
        g = f;
        f = e;
        e = wa(d, t1);
        d = c;
        c = b;
        b = a;
        a = wa(t1, t2);
    }
    [
        wa(state[0], a), wa(state[1], b),
        wa(state[2], c), wa(state[3], d),
        wa(state[4], e), wa(state[5], f),
        wa(state[6], g), wa(state[7], h),
    ]
}

// ---- HMAC-SHA512 for BIP32 CKDpub ------------------------------------------------
// key  = 32-byte chain code (zero-padded to the 128-byte block)
// data = ser_P(K) (33 bytes) || ser32(i) (4 bytes)   — 37 bytes, one padded block
// The two key-pad compressions depend only on the chain code, so callers can share them.

fn be_word(bytes: [u8; 128], w: u32) -> u64 {
    let mut out: u64 = 0;
    for i in 0..8 {
        out = (out << 8) + (bytes[w * 8 + i] as u64);
    }
    out
}

pub struct PadStates {
    pub inner: [u64; 8],
    pub outer: [u64; 8],
}

pub fn hmac_pad_states(chain_code: [u8; 32]) -> PadStates {
    let mut ib = [0x36; 128];
    let mut ob = [0x5c; 128];
    for i in 0..32 {
        ib[i] = chain_code[i] ^ 0x36;
        ob[i] = chain_code[i] ^ 0x5c;
    }
    let mut iw = [0; 16];
    let mut ow = [0; 16];
    for w in 0..16 {
        iw[w] = be_word(ib, w);
        ow[w] = be_word(ob, w);
    }
    PadStates { inner: compress(IV, iw), outer: compress(IV, ow) }
}

/// HMAC-SHA512(chain_code, ser_p || index_be) given the chain code's pad states.
/// Returns the 8 big-endian digest words (IL = words 0..4, IR = words 4..8).
pub fn hmac_ckd(pads: PadStates, ser_p: [u8; 33], index: u32) -> [u64; 8] {
    // inner: 37 data bytes, 0x80, zeros, 128-bit length (128+37)*8 = 1320
    let mut b = [0; 128];
    for i in 0..33 {
        b[i] = ser_p[i];
    }
    let ib: [u8; 4] = (index as Field).to_be_bytes();
    for i in 0..4 {
        b[33 + i] = ib[i];
    }
    b[37] = 0x80;
    b[126] = (1320 >> 8) as u8;
    b[127] = (1320 & 0xff) as u8;
    let mut w = [0; 16];
    for i in 0..16 {
        w[i] = be_word(b, i);
    }
    let inner = compress(pads.inner, w);
    // outer: 64-byte inner digest = 8 words, 0x80, zeros, length (128+64)*8 = 1536
    let mut ow = [0; 16];
    for i in 0..8 {
        ow[i] = inner[i];
    }
    ow[8] = 0x8000000000000000;
    ow[15] = 1536;
    compress(pads.outer, ow)
}

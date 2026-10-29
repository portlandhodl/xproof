// secp.nr — secp256k1 helpers for the xproof relation.
use crate::bignum::{U256, assert_add, assert_lt, assert_mulmod, to_be_bytes};

// Field prime p and group order n, little-endian u64 limbs.
pub global P: U256 = [0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];
pub global N: U256 = [0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
global SEVEN: U256 = [7, 0, 0, 0];

pub struct Point {
    pub x: U256,
    pub y: U256,
}

/// Prover-supplied quotients/remainders proving y^2 = x^3 + 7 (mod p).
pub struct CurveHint {
    pub xx: U256,
    pub q_xx: U256,
    pub xxx: U256,
    pub q_xxx: U256,
    pub yy: U256,
    pub q_yy: U256,
}

/// Point is on secp256k1 with canonical coordinates, and x < n (so x can serve as an
/// ECDSA r value without reduction).
pub fn assert_valid_point(pt: Point, h: CurveHint) {
    assert_lt(pt.x, N);
    assert_lt(pt.y, P);
    assert_mulmod(pt.x, pt.x, h.q_xx, h.xx, P);
    assert_mulmod(h.xx, pt.x, h.q_xxx, h.xxx, P);
    assert_mulmod(pt.y, pt.y, h.q_yy, h.yy, P);
    assert_add(h.xxx, SEVEN, h.yy);
}

/// SEC1 compressed encoding.
pub fn ser_p(pt: Point) -> [u8; 33] {
    let mut out = [0; 33];
    out[0] = 2 + ((pt.y[0] & 1) as u8);
    let xb = to_be_bytes(pt.x);
    for i in 0..32 {
        out[i + 1] = xb[i];
    }
    out
}

/// Hints for one "point relation via ECDSA" check (see `assert_x_of_q_plus_tg`).
pub struct EcdsaHint {
    pub e: U256,     // message scalar
    pub q: U256,     // quotient for the mod-n product
    pub e_raw: U256, // t*r mod n before optional negation (== e when not negated)
    pub s: U256,     // r or n - r (whichever is low-S)
    pub s_neg: bool, // s == n - r
}

/// Constrains  x(t·G + sign·Q) == r  using the ECDSA verification gadget:
///   verify(Q, msg = e, sig = (r, s)) checks x((e/s)·G + (r/s)·Q) mod n == r.
/// With s = ±r and e = ±t·r this is x(±(t·G ± Q)) == r. Requires r < n (caller).
///   negate_t = false: e = t·r      → x(Q + t·G) == r
///   negate_t = true:  e = -t·r     → x(Q - t·G) == r
pub fn assert_x_rel(qpt: Point, t: U256, r: U256, negate_t: bool, h: EcdsaHint) {
    assert_mulmod(t, r, h.q, h.e_raw, N);
    if negate_t {
        assert_add(h.e, h.e_raw, N); // e = n - e_raw (e_raw != 0 w.o.p.)
    } else {
        assert(h.e == h.e_raw);
    }
    if h.s_neg {
        assert_add(h.s, r, N);
    } else {
        assert(h.s == r);
    }
    let rb = to_be_bytes(r);
    let sb = to_be_bytes(h.s);
    let mut sig = [0; 64];
    for i in 0..32 {
        sig[i] = rb[i];
        sig[32 + i] = sb[i];
    }
    assert(
        std::ecdsa_secp256k1::verify_signature(to_be_bytes(qpt.x), to_be_bytes(qpt.y), sig, to_be_bytes(h.e)),
        "ECDSA relation check failed",
    );
}

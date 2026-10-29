// bignum.nr — checks over 256-bit integers held as 4 little-endian u64 limbs.
// The circuit never *computes* modular products; the prover supplies results and
// quotients as hints, and these functions constrain them. All intermediate values stay
// far below the BN254 field size (< 2^140), so field equalities are integer equalities.

pub type U256 = [u64; 4];

global TWO_64: Field = 18446744073709551616;
// 2^-64 mod r (BN254 scalar field).
global INV_TWO_64: Field = 1 / 18446744073709551616;
global CARRY_OFFSET: Field = 295147905179352825856; // 2^68

/// a < b
pub fn assert_lt(a: U256, b: U256) {
    let mut borrow: u128 = 1; // computing b - a - 1 >= 0
    for k in 0..4 {
        let need = a[k] as u128 + borrow;
        let bk = b[k] as u128;
        borrow = if bk < need { 1 } else { 0 };
        // (implicitly) digit = bk + borrow*2^64 - need, in [0, 2^64)
    }
    assert(borrow == 0, "assert_lt failed");
}

/// a + b == c  (exact, no wrap)
pub fn assert_add(a: U256, b: U256, c: U256) {
    let mut carry: u128 = 0;
    for k in 0..4 {
        let s = a[k] as u128 + b[k] as u128 + carry;
        assert((s & 0xffffffffffffffff) as u64 == c[k], "assert_add limb mismatch");
        carry = s >> 64;
    }
    assert(carry == 0, "assert_add overflow");
}

/// a * b == q * m + r  and  r < m
pub fn assert_mulmod(a: U256, b: U256, q: U256, r: U256, m: U256) {
    let mut carry: Field = 0;
    for k in 0..8 {
        let mut s: Field = carry;
        for i in 0..4 {
            if k >= i {
                let j = k - i;
                if j < 4 {
                    s += (a[i] as Field) * (b[j] as Field) - (q[i] as Field) * (m[j] as Field);
                }
            }
        }
        if k < 4 {
            s -= r[k] as Field;
        }
        // s must be an exact multiple of 2^64; the quotient is the (signed, small) carry.
        let c = s * INV_TWO_64;
        (c + CARRY_OFFSET).assert_max_bit_size::<70>();
        carry = c;
    }
    assert(carry == 0, "assert_mulmod: product mismatch");
    assert_lt(r, m);
}

/// Big-endian bytes of a little-endian-limb U256.
pub fn to_be_bytes(a: U256) -> [u8; 32] {
    let mut out = [0; 32];
    for k in 0..4 {
        let limb: [u8; 8] = (a[3 - k] as Field).to_be_bytes();
        for i in 0..8 {
            out[k * 8 + i] = limb[i];
        }
    }
    out
}

/// U256 from big-endian u64 words (e.g. the first half of a SHA-512 digest).
pub fn from_be_words(w0: u64, w1: u64, w2: u64, w3: u64) -> U256 {
    [w3, w2, w1, w0]
}

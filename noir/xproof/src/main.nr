// xproof — Noir circuit for the BIP32 ownership-link statement (browser / WASM prover).
//
// Public:  key_a, key_b (SEC1 compressed), context_hash, expires_at  — same values as the
//          SP1 journal, so verifiers check identical semantics.
// Private: parent point K_par and chain code c_par (the xpub), path_a / path_b (each
//          1..=MAX_DEPTH non-hardened steps), and prover hints.
//
// Relation:  key_a = ser_P(CKDpub*((K_par, c_par), path_a))
//            key_b = ser_P(CKDpub*((K_par, c_par), path_b)),  key_a != key_b
// Each CKDpub step: I = HMAC-SHA512(c, ser_P(K) || ser32(i)); t = I[0..32] < n;
//                   K' = K + t·G; c' = I[32..64].
// The point step K' = K + t·G is constrained without in-circuit EC arithmetic, using two
// secp256k1 ECDSA-verification gadgets (see secp::assert_x_rel and SPEC.md §4):
//   x(K + t·G) == x(K')   and   x(K' − t·G) == x(K)   ⇒   K' = K + t·G.

mod bignum;
mod secp;
mod sha512;

use bignum::{U256, assert_lt, from_be_words};
use secp::{CurveHint, EcdsaHint, N, Point, assert_valid_point, assert_x_rel, ser_p};

pub global MAX_DEPTH: u32 = 3;

pub struct StepHint {
    child: Point,
    child_curve: CurveHint,
    fwd: EcdsaHint, // x(K + t·G) == x(K')
    back: EcdsaHint, // x(K' − t·G) == x(K)
}

/// Walk `path` (first `len` steps active) from the root. Steps past `len` are still
/// evaluated (fixed circuit shape) on index 0 but do not advance the node.
fn derive(
    root: Point,
    root_cc: [u8; 32],
    root_pads: sha512::PadStates,
    path: [u32; MAX_DEPTH],
    len: u32,
    hints: [StepHint; MAX_DEPTH],
) -> [u8; 33] {
    assert((len >= 1) & (len <= MAX_DEPTH), "path length out of range");
    let mut node = root;
    let mut cc = root_cc;
    for d in 0..MAX_DEPTH {
        let active = d < len;
        let index = path[d];
        assert(index < 0x80000000, "hardened step cannot be derived from an xpub");
        let pads = if d == 0 { root_pads } else { sha512::hmac_pad_states(cc) };
        let i = sha512::hmac_ckd(pads, ser_p(node), index);
        let t: U256 = from_be_words(i[0], i[1], i[2], i[3]);
        assert_lt(t, N); // BIP32: IL >= n is an invalid child

        let h = hints[d];
        assert_valid_point(h.child, h.child_curve);
        assert_x_rel(node, t, h.child.x, false, h.fwd);
        assert_x_rel(h.child, t, node.x, true, h.back);

        if active {
            node = h.child;
            let mut next = [0; 32];
            let ir: [[u8; 8]; 4] = [
                (i[4] as Field).to_be_bytes(), (i[5] as Field).to_be_bytes(),
                (i[6] as Field).to_be_bytes(), (i[7] as Field).to_be_bytes(),
            ];
            for w in 0..4 {
                for b in 0..8 {
                    next[w * 8 + b] = ir[w][b];
                }
            }
            cc = next;
        }
    }
    ser_p(node)
}

fn main(
    key_a: pub [u8; 33],
    key_b: pub [u8; 33],
    context_hash: pub [u8; 32],
    expires_at: pub u64,
    parent: Point,
    parent_curve: CurveHint,
    chain_code: [u8; 32],
    path_a: [u32; MAX_DEPTH],
    len_a: u32,
    path_b: [u32; MAX_DEPTH],
    len_b: u32,
    hints_a: [StepHint; MAX_DEPTH],
    hints_b: [StepHint; MAX_DEPTH],
) {
    assert_valid_point(parent, parent_curve);
    let pads = sha512::hmac_pad_states(chain_code); // shared by both paths' first step
    assert(derive(parent, chain_code, pads, path_a, len_a, hints_a) == key_a, "key_a mismatch");
    assert(derive(parent, chain_code, pads, path_b, len_b, hints_b) == key_b, "key_b mismatch");
    assert(key_a != key_b, "keys must differ");
    // context_hash and expires_at are bound into the proof as public inputs (anti-replay).
    let _ = (context_hash, expires_at);
}

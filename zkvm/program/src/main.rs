//! xproof guest program — the actual proven statement.
//!
//! Proves, in zero knowledge over witness (parent_pubkey, chain_code, path_a, path_b):
//!
//!   K_A = CKDpub*((K_par, c_par), path_a)      (committed to the journal)
//!   K_B = CKDpub*((K_par, c_par), path_b)      (committed to the journal)
//!
//! where each CKDpub step is BIP32 normal derivation:
//!   I = HMAC-SHA512(key = c, data = ser_P(K) || ser32(i));  K' = K + I[0..32]·G;  c' = I[32..64]
//!
//! i.e. "K_A and K_B both descend (at any depth, e.g. m/0/1 and m/1/3) from one xpub I know."
//! The xpub, chain code, paths and path lengths never appear in the public output.

#![no_main]
sp1_zkvm::entrypoint!(main);

use hmac::{Hmac, Mac};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, Scalar};
use sha2::Sha512;
use xproof_lib::{journal_bytes, MAX_DEPTH};

type HmacSha512 = Hmac<Sha512>;

/// An extended public key: point, its compressed encoding, and chain code.
#[derive(Clone)]
struct Node {
    point: ProjectivePoint,
    ser: [u8; 33],
    chain: [u8; 32],
}

/// One BIP32 CKDpub step.
fn ckd_pub(parent: &Node, index: u32) -> Node {
    assert!(index < 0x8000_0000, "hardened indices cannot derive from an xpub");
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&parent.chain).expect("hmac key len");
    mac.update(&parent.ser);
    mac.update(&index.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut il = [0u8; 32];
    il.copy_from_slice(&out[..32]);
    // BIP32: index is invalid if IL >= group order; such a proof cannot be constructed.
    let tweak = Option::<Scalar>::from(Scalar::from_repr(il.into()))
        .expect("invalid child: tweak >= curve order (BIP32 rule: skip this index)");
    let point = parent.point + ProjectivePoint::mul_by_generator(&tweak);
    let mut ser = [0u8; 33];
    ser.copy_from_slice(point.to_affine().to_encoded_point(true).as_bytes());
    let mut chain = [0u8; 32];
    chain.copy_from_slice(&out[32..]);
    Node { point, ser, chain }
}

fn derive_path(start: &Node, path: &[u32]) -> Node {
    path.iter().fold(start.clone(), |n, &i| ckd_pub(&n, i))
}

pub fn main() {
    // ---- private witness ----
    let parent_pubkey_v = sp1_zkvm::io::read_vec();
    let chain_code_v = sp1_zkvm::io::read_vec();
    let path_a: Vec<u32> = sp1_zkvm::io::read();
    let path_b: Vec<u32> = sp1_zkvm::io::read();
    // ---- public (echoed into the journal) ----
    let context_hash_v = sp1_zkvm::io::read_vec();
    let expires_at: u64 = sp1_zkvm::io::read();

    let parent_pubkey: [u8; 33] = parent_pubkey_v.as_slice().try_into().expect("parent pubkey must be 33 bytes");
    let chain_code: [u8; 32] = chain_code_v.as_slice().try_into().expect("chain code must be 32 bytes");
    let context_hash: &[u8; 32] = context_hash_v.as_slice().try_into().expect("context hash must be 32 bytes");
    assert!(!path_a.is_empty() && !path_b.is_empty(), "paths must have depth >= 1");
    assert!(path_a.len() <= MAX_DEPTH && path_b.len() <= MAX_DEPTH, "path too deep");
    assert!(path_a != path_b, "paths must differ");

    let root = Node {
        point: PublicKey::from_sec1_bytes(&parent_pubkey).expect("parent pubkey not on curve").to_projective(),
        ser: parent_pubkey,
        chain: chain_code,
    };

    // Derive the shared prefix once (e.g. m/0 for m/0/1 vs m/0/2), then each tail.
    let common = path_a.iter().zip(&path_b).take_while(|(a, b)| a == b).count();
    let branch = derive_path(&root, &path_a[..common]);
    let key_a = derive_path(&branch, &path_a[common..]).ser;
    let key_b = derive_path(&branch, &path_b[common..]).ser;

    // Public values: the two derived child keys + anti-replay context.
    sp1_zkvm::io::commit_slice(&journal_bytes(&key_a, &key_b, context_hash, expires_at));
}

//! xproof-lib — shared definition of the proven statement's public values (the zkVM "journal").
//!
//! Journal layout (106 bytes, big-endian where applicable):
//!   key_a        33 bytes  compressed child pubkey being attested
//!   key_b        33 bytes  compressed child pubkey anchored on-chain
//!   context_hash 32 bytes  SHA-256 of the verifier session string (anti-replay)
//!   expires_at    8 bytes  unix epoch millis (freshness bound)

/// Maximum derivation depth (below the hidden xpub) accepted for either key.
pub const MAX_DEPTH: usize = 16;

pub const JOURNAL_LEN: usize = 33 + 33 + 32 + 8;

pub fn journal_bytes(key_a: &[u8; 33], key_b: &[u8; 33], context_hash: &[u8; 32], expires_at: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(JOURNAL_LEN);
    out.extend_from_slice(key_a);
    out.extend_from_slice(key_b);
    out.extend_from_slice(context_hash);
    out.extend_from_slice(&expires_at.to_be_bytes());
    out
}

#[derive(Debug, Clone)]
pub struct Journal {
    pub key_a: [u8; 33],
    pub key_b: [u8; 33],
    pub context_hash: [u8; 32],
    pub expires_at: u64,
}

pub fn parse_journal(bytes: &[u8]) -> Result<Journal, &'static str> {
    if bytes.len() != JOURNAL_LEN {
        return Err("bad journal length");
    }
    let mut exp = [0u8; 8];
    exp.copy_from_slice(&bytes[98..106]);
    Ok(Journal {
        key_a: bytes[0..33].try_into().unwrap(),
        key_b: bytes[33..66].try_into().unwrap(),
        context_hash: bytes[66..98].try_into().unwrap(),
        expires_at: u64::from_be_bytes(exp),
    })
}

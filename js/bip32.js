// bip32.js — real BIP32: master key from seed, normal (non-hardened) child-key
// derivation for both private and public keys, and xpub serialization.
//
// Normal derivation (the only kind an xpub supports):
//   I  = HMAC-SHA512(key = chainCode, data = ser_P(K_par) || ser32(i))
//   IL = I[0..32], IR = I[32..64]
//   k_child = (IL + k_par) mod n          K_child = IL·G + K_par
//   c_child = IR
//
// The value IL is the "tweak" the ZK proof reasons about.

import { hmacSha512, base58CheckEncode, concatBytes, hash160 } from "./hash.js";
import {
  bytesToBigint, bigintToBytes32, scalarMul, pointAdd,
  compressPoint, POINT_G, ORDER_N,
} from "./secp256k1.js";

const MASTER_HMAC_KEY = new TextEncoder().encode("Bitcoin seed");

export async function masterFromSeed(seedBytes) {
  const I = await hmacSha512(MASTER_HMAC_KEY, seedBytes);
  const priv = I.slice(0, 32);
  const chain = I.slice(32, 64);
  return { priv, chain, pubPoint: scalarMul(bytesToBigint(priv), POINT_G) };
}

async function derivationTweak(chainCode, pubPoint, index) {
  const serI = new Uint8Array(4);
  new DataView(serI.buffer).setUint32(0, index, false); // big-endian
  const I = await hmacSha512(chainCode, concatBytes(compressPoint(pubPoint), serI));
  return { IL: I.slice(0, 32), childChainCode: I.slice(32, 64) };
}

// Non-hardened private child derivation (needs parent privkey).
export async function deriveChildPriv(node, index) {
  if (index >= 0x80000000) throw new Error("hardened derivation not supported here");
  const { IL, childChainCode } = await derivationTweak(node.chain, node.pubPoint, index);
  const childPrivBig = (bytesToBigint(IL) + bytesToBigint(node.priv)) % ORDER_N;
  const childPriv = bigintToBytes32(childPrivBig);
  return {
    priv: childPriv,
    chain: childChainCode,
    pubPoint: scalarMul(childPrivBig, POINT_G),
  };
}

// Non-hardened public child derivation (xpub only — this is what the proof hides).
export async function deriveChildPub(parentPub, index) {
  if (index >= 0x80000000) throw new Error("an xpub cannot derive hardened children");
  const { IL, childChainCode } = await derivationTweak(parentPub.chain, parentPub.pubPoint, index);
  const childPoint = pointAdd(scalarMul(bytesToBigint(IL), POINT_G), parentPub.pubPoint);
  return { pubPoint: childPoint, chain: childChainCode, tweak: IL };
}

export async function fingerprint(pubPoint) {
  return (await hash160(compressPoint(pubPoint))).slice(0, 4);
}

// Real base58check xpub, depth 0 for the demo master. Version 0x0488B21E ("xpub") on
// mainnet, 0x043587CF ("tpub") on test networks such as signet.
export async function serializeXpub(node, { testnet = false } = {}) {
  const payload = concatBytes(
    new Uint8Array(testnet ? [0x04, 0x35, 0x87, 0xcf] : [0x04, 0x88, 0xb2, 0x1e]),
    new Uint8Array([0x00]),                    // depth 0
    new Uint8Array([0x00, 0x00, 0x00, 0x00]),  // parent fingerprint (none for master)
    new Uint8Array([0x00, 0x00, 0x00, 0x00]),  // child number (0 for master)
    node.chain,
    compressPoint(node.pubPoint)
  );
  return base58CheckEncode(payload);
}

// Public-data view of a node (what an xpub carries: parent pubkey + chain code).
export function toXpubData(node) {
  return { pubPoint: node.pubPoint, chain: node.chain };
}

// ---- Multi-level paths ------------------------------------------------------

export const MAX_DEPTH = 16; // must match xproof_lib::MAX_DEPTH in the zkVM guest

// "m/0/1", "0/1" or "0" → [0, 1]. Non-hardened only (the proof starts from an xpub).
export function parsePath(str) {
  let s = String(str).trim();
  if (/^m\/?$/i.test(s)) throw new Error("path needs at least one step below the xpub");
  s = s.replace(/^m\//i, "");
  const path = s.split("/").map((p) => {
    p = p.trim();
    if (/['hH]$/.test(p)) throw new Error(`hardened step ${p} cannot be derived from an xpub`);
    if (!/^\d+$/.test(p) || Number(p) >= 0x80000000) throw new Error(`bad path step “${p}”`);
    return Number(p);
  });
  if (path.length > MAX_DEPTH) throw new Error(`path deeper than ${MAX_DEPTH}`);
  return path;
}

export const formatPath = (path) => "m/" + path.join("/");

// Walk a path from the xpub side. Returns the final node plus every intermediate
// step (used by the tree view).
export async function derivePathPub(xpub, path) {
  let node = { pubPoint: xpub.pubPoint, chain: xpub.chain };
  const steps = [];
  for (const i of path) {
    node = await deriveChildPub(node, i);
    steps.push({ index: i, ...node });
  }
  return { ...node, steps };
}

export async function derivePathPriv(node, path) {
  for (const i of path) node = await deriveChildPriv(node, i);
  return node;
}

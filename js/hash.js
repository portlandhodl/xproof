// hash.js — hash utilities. SHA-256/SHA-512/HMAC prefer WebCrypto; when the page is
// served from an insecure context (crypto.subtle undefined, e.g. http://LAN-IP), they
// fall back to the pure-JS implementations in sha2soft.js (test-vector covered).
// RIPEMD-160 is pure JS regardless (WebCrypto doesn't expose it).

import { sha256Soft, sha512Soft, hmacSha512Soft } from "./sha2soft.js";

const HAS_SUBTLE = typeof crypto !== "undefined" && !!crypto.subtle;

export function hexToBytes(hex) {
  if (hex.length % 2) hex = "0" + hex;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

export async function sha256(data) {
  if (!HAS_SUBTLE) return sha256Soft(data);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function sha512(data) {
  if (!HAS_SUBTLE) return sha512Soft(data);
  return new Uint8Array(await crypto.subtle.digest("SHA-512", data));
}

export async function hmacSha512(keyBytes, data) {
  if (!HAS_SUBTLE) return hmacSha512Soft(keyBytes, data);
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

export async function hash160(data) {
  return ripemd160(await sha256(data));
}

// ---------------------------------------------------------------------------
// Base58Check
// ---------------------------------------------------------------------------

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = "";
  for (const b of bytes) { if (b === 0) out += "1"; else break; }
  for (let i = digits.length - 1; i >= 0; i--) out += B58_ALPHABET[digits[i]];
  return out;
}

export async function base58CheckEncode(payload) {
  const chk = (await sha256(await sha256(payload))).slice(0, 4);
  return base58Encode(concatBytes(payload, chk));
}

// ---------------------------------------------------------------------------
// RIPEMD-160 (pure JS, little-endian lengths, per spec)
// ---------------------------------------------------------------------------

function rol32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

const RMD_R1 = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const RMD_R2 = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
const RMD_S1 = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const RMD_S2 = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];
const RMD_K1 = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const RMD_K2 = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

function rmdF(j, x, y, z) {
  if (j < 16) return (x ^ y ^ z) >>> 0;
  if (j < 32) return ((x & y) | (~x & z)) >>> 0;
  if (j < 48) return ((x | ~y) ^ z) >>> 0;
  if (j < 64) return ((x & z) | (y & ~z)) >>> 0;
  return (x ^ (y | ~z)) >>> 0;
}

export function ripemd160(message) {
  const msgLen = message.length;
  const paddedLen = (((msgLen + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(paddedLen);
  buf.set(message);
  buf[msgLen] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(paddedLen - 8, msgLen * 8, true);
  dv.setUint32(paddedLen - 4, Math.floor(msgLen / 0x20000000), true);

  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;

  for (let block = 0; block < paddedLen; block += 64) {
    const X = new Array(16);
    for (let i = 0; i < 16; i++) X[i] = dv.getUint32(block + i * 4, true);

    let a1 = h0, b1 = h1, c1 = h2, d1 = h3, e1 = h4;
    let a2 = h0, b2 = h1, c2 = h2, d2 = h3, e2 = h4;

    for (let j = 0; j < 80; j++) {
      let t = (rol32((a1 + rmdF(j, b1, c1, d1) + X[RMD_R1[j]] + RMD_K1[(j / 16) | 0]) >>> 0, RMD_S1[j]) + e1) >>> 0;
      a1 = e1; e1 = d1; d1 = rol32(c1, 10); c1 = b1; b1 = t;

      t = (rol32((a2 + rmdF(79 - j, b2, c2, d2) + X[RMD_R2[j]] + RMD_K2[(j / 16) | 0]) >>> 0, RMD_S2[j]) + e2) >>> 0;
      a2 = e2; e2 = d2; d2 = rol32(c2, 10); c2 = b2; b2 = t;
    }

    const t = (h1 + c1 + d2) >>> 0;
    h1 = (h2 + d1 + e2) >>> 0;
    h2 = (h3 + e1 + a2) >>> 0;
    h3 = (h4 + a1 + b2) >>> 0;
    h4 = (h0 + b1 + c2) >>> 0;
    h0 = t;
  }

  const out = new Uint8Array(20);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, h0, true);
  odv.setUint32(4, h1, true);
  odv.setUint32(8, h2, true);
  odv.setUint32(12, h3, true);
  odv.setUint32(16, h4, true);
  return out;
}

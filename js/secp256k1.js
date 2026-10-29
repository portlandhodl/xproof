// secp256k1.js — minimal BigInt implementation: point arithmetic, (de)compression,
// ECDSA sign/verify. Real cryptography, fine for demo-scale workloads.

export const FIELD_P = 2n ** 256n - 2n ** 32n - 977n;
export const ORDER_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
export const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
export const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
export const POINT_G = { x: GX, y: GY };

const mod = (a, m = FIELD_P) => { const r = a % m; return r >= 0n ? r : r + m; };

export function modInv(a, m = FIELD_P) {
  // Extended Euclidean
  let [lm, hm] = [1n, 0n];
  let [low, high] = [mod(a, m), m];
  while (low > 1n) {
    const r = high / low;
    [lm, hm] = [hm - lm * r, lm];
    [low, high] = [high - low * r, low];
  }
  return mod(lm, m);
}

export function pointAdd(p, q) {
  if (!p) return q;
  if (!q) return p;
  if (p.x === q.x) {
    if (mod(p.y + q.y) === 0n) return null; // P + (-P)
    return pointDouble(p);
  }
  const lam = mod((q.y - p.y) * modInv(q.x - p.x));
  const x = mod(lam * lam - p.x - q.x);
  const y = mod(lam * (p.x - x) - p.y);
  return { x, y };
}

export function pointDouble(p) {
  if (!p) return null;
  if (p.y === 0n) return null;
  const lam = mod(3n * p.x * p.x * modInv(2n * p.y));
  const x = mod(lam * lam - 2n * p.x);
  const y = mod(lam * (p.x - x) - p.y);
  return { x, y };
}

export function scalarMul(k, point = POINT_G) {
  let n = mod(k, ORDER_N);
  let result = null;
  let addend = point;
  while (n > 0n) {
    if (n & 1n) result = pointAdd(result, addend);
    addend = pointDouble(addend);
    n >>= 1n;
  }
  return result;
}

export function pointEqual(p, q) {
  if (!p || !q) return p === q;
  return p.x === q.x && p.y === q.y;
}

export function bigintToBytes32(n) {
  return hexToBytesStrict(n.toString(16).padStart(64, "0"));
}

export function bytesToBigint(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function hexToBytesStrict(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function compressPoint(p) {
  const out = new Uint8Array(33);
  out[0] = p.y & 1n ? 0x03 : 0x02;
  out.set(bigintToBytes32(p.x), 1);
  return out;
}

export function decompressPoint(bytes) {
  const x = bytesToBigint(bytes.slice(1));
  const y2 = mod(x * x * x + 7n);
  let y = powMod(y2, (FIELD_P + 1n) / 4n);
  if (((y & 1n) === 1n) !== (bytes[0] === 0x03)) y = mod(-y);
  return { x, y };
}

function powMod(base, exp, m = FIELD_P) {
  let result = 1n, b = mod(base);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * b, m);
    b = mod(b * b, m);
    exp >>= 1n;
  }
  return result;
}

export function pubKeyFromPriv(privBytes) {
  return scalarMul(bytesToBigint(privBytes), POINT_G);
}

// ---------------------------------------------------------------------------
// ECDSA over secp256k1 (for the "on-chain" anchor signature)
// ---------------------------------------------------------------------------

function randomScalar() {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return mod(bytesToBigint(buf), ORDER_N);
}

export function ecdsaSign(privBytes, msgHashBytes) {
  const d = bytesToBigint(privBytes);
  const e = mod(bytesToBigint(msgHashBytes), ORDER_N);
  while (true) {
    const k = randomScalar();
    const R = scalarMul(k);
    if (!R) continue;
    const r = mod(R.x, ORDER_N);
    if (r === 0n) continue;
    const s = mod(modInv(k, ORDER_N) * (e + r * d), ORDER_N);
    if (s === 0n) continue;
    return { r, s };
  }
}

export function ecdsaVerify(pubPoint, msgHashBytes, sig) {
  const { r, s } = sig;
  if (r <= 0n || r >= ORDER_N || s <= 0n || s >= ORDER_N) return false;
  const e = mod(bytesToBigint(msgHashBytes), ORDER_N);
  const w = modInv(s, ORDER_N);
  const u1 = mod(e * w, ORDER_N);
  const u2 = mod(r * w, ORDER_N);
  const X = pointAdd(scalarMul(u1), scalarMul(u2, pubPoint));
  if (!X) return false;
  return mod(X.x, ORDER_N) === r;
}

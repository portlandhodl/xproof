// noir-witness.js — builds the private inputs ("witness") for the Noir xproof circuit.
// Mirrors noir/xproof/src/main.nr exactly: for each path, MAX_DEPTH steps are evaluated;
// steps past the path length derive index 0 from the current node without advancing it.
// Hints are values the circuit only *checks*: child points, modular products/quotients,
// and low-S signature halves for the ECDSA relation gadget (see SPEC.md §4).

import { hmacSha512, bytesToHex, hexToBytes, concatBytes } from "./hash.js";
import { scalarMul, pointAdd, compressPoint, bytesToBigint, POINT_G, ORDER_N, FIELD_P } from "./secp256k1.js";

export const NOIR_MAX_DEPTH = 3; // must match MAX_DEPTH in noir/xproof/src/main.nr

const n = ORDER_N, p = FIELD_P;
const MASK = (1n << 64n) - 1n;
const limbs = (x) => [0n, 1n, 2n, 3n].map((k) => ((x >> (64n * k)) & MASK).toString());
const bytes = (u8) => [...u8];

function curveHint(pt) {
  const xx = (pt.x * pt.x) % p, xxx = (xx * pt.x) % p, yy = (pt.y * pt.y) % p;
  return {
    xx: limbs(xx), q_xx: limbs((pt.x * pt.x) / p),
    xxx: limbs(xxx), q_xxx: limbs((xx * pt.x) / p),
    yy: limbs(yy), q_yy: limbs((pt.y * pt.y) / p),
  };
}

// Hint for secp::assert_x_rel(Q, t, r, negate_t).
function ecdsaHint(t, r, negateT) {
  const eRaw = (t * r) % n;
  const e = negateT ? n - eRaw : eRaw;
  const sNeg = r > n / 2n;
  return { e: limbs(e), q: limbs((t * r) / n), e_raw: limbs(eRaw), s: limbs(sNeg ? n - r : r), s_neg: sNeg };
}

const point = (pt) => ({ x: limbs(pt.x), y: limbs(pt.y) });

async function ckd(node, index) {
  const ser = new Uint8Array(4);
  new DataView(ser.buffer).setUint32(0, index, false);
  const I = await hmacSha512(node.chain, concatBytes(compressPoint(node.point), ser));
  const t = bytesToBigint(I.slice(0, 32));
  if (t >= n) throw new Error("invalid BIP32 child (IL >= n) — pick another index");
  const child = pointAdd(node.point, scalarMul(t, POINT_G));
  if (!child || child.x >= n) throw new Error("child x >= n (probability ~2^-128) — pick another index");
  return { t, child: { point: child, chain: I.slice(32, 64) } };
}

async function pathHints(root, path) {
  if (path.length < 1 || path.length > NOIR_MAX_DEPTH) {
    throw new Error(`the in-browser circuit supports paths of depth 1–${NOIR_MAX_DEPTH}`);
  }
  let node = root;
  const hints = [];
  for (let d = 0; d < NOIR_MAX_DEPTH; d++) {
    const active = d < path.length;
    const { t, child } = await ckd(node, active ? path[d] : 0);
    hints.push({
      child: point(child.point),
      child_curve: curveHint(child.point),
      fwd: ecdsaHint(t, child.point.x, false),
      back: ecdsaHint(t, node.point.x, true),
    });
    if (active) node = child;
  }
  const padded = [...path, ...Array(NOIR_MAX_DEPTH - path.length).fill(0)];
  return { path: padded, len: path.length, hints, key: compressPoint(node.point) };
}

/**
 * @param {{pubPoint, chain}} xpub   parent point + chain code (the secret)
 * @param {number[]} pathA, pathB    non-hardened paths, depth 1..NOIR_MAX_DEPTH
 * @param {Uint8Array} contextHash   sha256(context)
 * @param {number} expiresAt         unix ms
 */
export async function buildInputs({ xpub, pathA, pathB, contextHash, expiresAt }) {
  if (xpub.pubPoint.x >= n) throw new Error("parent x >= n (probability ~2^-128)");
  const root = { point: xpub.pubPoint, chain: xpub.chain };
  const a = await pathHints(root, pathA);
  const b = await pathHints(root, pathB);
  if (bytesToHex(a.key) === bytesToHex(b.key)) throw new Error("paths must lead to different keys");
  return {
    inputs: {
      key_a: bytes(a.key),
      key_b: bytes(b.key),
      context_hash: bytes(contextHash),
      expires_at: String(expiresAt),
      parent: point(xpub.pubPoint),
      parent_curve: curveHint(xpub.pubPoint),
      chain_code: bytes(xpub.chain),
      path_a: a.path, len_a: a.len,
      path_b: b.path, len_b: b.len,
      hints_a: a.hints, hints_b: b.hints,
    },
    keyA: bytesToHex(a.key),
    keyB: bytesToHex(b.key),
  };
}

// Public inputs of a proof, in circuit order: key_a[33], key_b[33], context_hash[32], expires_at.
// Each is a 32-byte field element (hex). Returns the same shape as the SP1 journal.
export function parsePublicInputs(publicInputs) {
  const v = publicInputs.map((f) => BigInt(f));
  if (v.length !== 99) throw new Error(`expected 99 public inputs, got ${v.length}`);
  const hexBytes = (arr) => arr.map((x) => x.toString(16).padStart(2, "0")).join("");
  return {
    key_a: hexBytes(v.slice(0, 33)),
    key_b: hexBytes(v.slice(33, 66)),
    context_hash: hexBytes(v.slice(66, 98)),
    expires_at: Number(v[98]),
  };
}

export { hexToBytes };

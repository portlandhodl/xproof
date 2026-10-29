// btc.js — just enough Bitcoin to fund and spend a P2WPKH key on signet, and to let a
// verifier independently re-check that spend:
//   bech32 (BIP173) addresses, segwit v0 transaction serialization, BIP143 sighash,
//   DER signatures (low-S), and an Esplora REST client (mempool.space signet by default).

import { sha256, hash160, bytesToHex, hexToBytes, concatBytes } from "./hash.js";
import { ecdsaSign, ecdsaVerify, compressPoint, decompressPoint, ORDER_N } from "./secp256k1.js";

export const NETWORK = { name: "signet", hrp: "tb", explorer: "https://mempool.space/signet" };
export const ESPLORA = NETWORK.explorer + "/api";

// ---------------------------------------------------------------------------
// bech32 (segwit v0 only — that's all P2WPKH needs)
// ---------------------------------------------------------------------------

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
const hrpExpand = (hrp) => [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));

function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0;
  const out = [], maxv = (1 << to) - 1;
  for (const v of data) {
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
  }
  if (pad && bits) out.push((acc << (to - bits)) & maxv);
  else if (!pad && (bits >= from || ((acc << (to - bits)) & maxv))) return null;
  return out;
}

export function segwitEncode(hrp, version, program) {
  const data = [version, ...convertBits(program, 8, 5, true)];
  const mod = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [0, 1, 2, 3, 4, 5].map((i) => (mod >>> (5 * (5 - i))) & 31);
  return hrp + "1" + [...data, ...checksum].map((d) => CHARSET[d]).join("");
}

// Returns {version, program} or throws. Accepts v0 (bech32) only.
export function segwitDecode(hrp, addr) {
  const a = addr.trim().toLowerCase();
  const pos = a.lastIndexOf("1");
  if (a.slice(0, pos) !== hrp) throw new Error(`address must start with ${hrp}1`);
  const data = [...a.slice(pos + 1)].map((c) => CHARSET.indexOf(c));
  if (data.length < 6 || data.includes(-1)) throw new Error("bad bech32 characters");
  if (polymod([...hrpExpand(hrp), ...data]) !== 1) throw new Error("bad bech32 checksum (only v0 tb1q… addresses supported)");
  const version = data[0];
  const program = convertBits(data.slice(1, -6), 5, 8, false);
  if (version !== 0 || !program || (program.length !== 20 && program.length !== 32)) {
    throw new Error("only segwit v0 (tb1q…) addresses supported");
  }
  return { version, program: new Uint8Array(program) };
}

export async function p2wpkhAddress(pubkeyBytes) {
  return segwitEncode(NETWORK.hrp, 0, await hash160(pubkeyBytes));
}

export function scriptForAddress(addr) {
  const { version, program } = segwitDecode(NETWORK.hrp, addr);
  return concatBytes(new Uint8Array([version, program.length]), program);
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

const le32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
const le64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const rev = (b) => Uint8Array.from(b).reverse();
function varint(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, n >> 8]);
  return concatBytes(new Uint8Array([0xfe]), le32(n));
}
const withLen = (b) => concatBytes(varint(b.length), b);
export const dsha256 = async (b) => sha256(await sha256(b));

// tx = { version, locktime, inputs: [{txid, vout, sequence, value, witness?}], outputs: [{value, script}] }

export function serializeTx(tx) {
  const parts = [le32(tx.version), new Uint8Array([0x00, 0x01]), varint(tx.inputs.length)];
  for (const i of tx.inputs) parts.push(rev(hexToBytes(i.txid)), le32(i.vout), new Uint8Array([0]), le32(i.sequence));
  parts.push(varint(tx.outputs.length));
  for (const o of tx.outputs) parts.push(le64(o.value), withLen(o.script));
  for (const i of tx.inputs) {
    const w = i.witness || [];
    parts.push(varint(w.length), ...w.map(withLen));
  }
  parts.push(le32(tx.locktime));
  return concatBytes(...parts);
}

export async function txid(tx) {
  // txid = double-SHA256 of the non-witness serialization, byte-reversed.
  const parts = [le32(tx.version), varint(tx.inputs.length)];
  for (const i of tx.inputs) parts.push(rev(hexToBytes(i.txid)), le32(i.vout), new Uint8Array([0]), le32(i.sequence));
  parts.push(varint(tx.outputs.length));
  for (const o of tx.outputs) parts.push(le64(o.value), withLen(o.script));
  parts.push(le32(tx.locktime));
  return bytesToHex(rev(await dsha256(concatBytes(...parts))));
}

// BIP143 sighash (SIGHASH_ALL) for a P2WPKH input spent by `pubkeyHash` (20 bytes).
export async function bip143Sighash(tx, index, pubkeyHash) {
  const prevouts = concatBytes(...tx.inputs.map((i) => concatBytes(rev(hexToBytes(i.txid)), le32(i.vout))));
  const sequences = concatBytes(...tx.inputs.map((i) => le32(i.sequence)));
  const outputs = concatBytes(...tx.outputs.map((o) => concatBytes(le64(o.value), withLen(o.script))));
  const inp = tx.inputs[index];
  const scriptCode = concatBytes(new Uint8Array([0x19, 0x76, 0xa9, 0x14]), pubkeyHash, new Uint8Array([0x88, 0xac]));
  return dsha256(concatBytes(
    le32(tx.version), await dsha256(prevouts), await dsha256(sequences),
    rev(hexToBytes(inp.txid)), le32(inp.vout), scriptCode, le64(inp.value), le32(inp.sequence),
    await dsha256(outputs), le32(tx.locktime), le32(1),
  ));
}

// ---------------------------------------------------------------------------
// DER signatures
// ---------------------------------------------------------------------------

function derInt(n) {
  let b = hexToBytes(n.toString(16).padStart(64, "0"));
  let i = 0;
  while (i < b.length - 1 && b[i] === 0 && b[i + 1] < 0x80) i++;
  b = b.slice(i);
  if (b[0] & 0x80) b = concatBytes(new Uint8Array([0]), b);
  return concatBytes(new Uint8Array([0x02, b.length]), b);
}

export function derEncode({ r, s }) {
  const body = concatBytes(derInt(r), derInt(s));
  return concatBytes(new Uint8Array([0x30, body.length]), body);
}

export function derDecode(b) {
  if (b[0] !== 0x30 || b[2] !== 0x02) throw new Error("bad DER");
  const rl = b[3], r = b.slice(4, 4 + rl);
  if (b[4 + rl] !== 0x02) throw new Error("bad DER");
  const sl = b[5 + rl], s = b.slice(6 + rl, 6 + rl + sl);
  return { r: BigInt("0x" + bytesToHex(r)), s: BigInt("0x" + bytesToHex(s)) };
}

// ---------------------------------------------------------------------------
// Build + sign a sweep of every UTXO of one P2WPKH key to one destination.
// ---------------------------------------------------------------------------

export async function buildSweep({ utxos, privBytes, pubPoint, destAddress, feeRate }) {
  if (!utxos.length) throw new Error("no UTXOs to spend — deposit signet sats to key B first");
  const pubkey = compressPoint(pubPoint);
  const pkh = await hash160(pubkey);
  const total = utxos.reduce((n, u) => n + u.value, 0);
  const vsize = Math.ceil(10.5 + 68 * utxos.length + 31) + 1;
  const fee = Math.max(Math.ceil(vsize * feeRate), vsize); // never below 1 sat/vB
  const value = total - fee;
  if (value < 330) throw new Error(`balance ${total} sats can't cover the ${fee} sat fee plus dust limit`);

  const tx = {
    version: 2,
    locktime: 0,
    inputs: utxos.map((u) => ({ txid: u.txid, vout: u.vout, value: u.value, sequence: 0xfffffffd })),
    outputs: [{ value, script: scriptForAddress(destAddress) }],
  };
  for (let i = 0; i < tx.inputs.length; i++) {
    const sighash = await bip143Sighash(tx, i, pkh);
    let sig = ecdsaSign(privBytes, sighash);
    if (sig.s > ORDER_N / 2n) sig = { r: sig.r, s: ORDER_N - sig.s }; // BIP62 low-S, required by policy
    tx.inputs[i].witness = [concatBytes(derEncode(sig), new Uint8Array([0x01])), pubkey];
  }
  return { tx, hex: bytesToHex(serializeTx(tx)), txid: await txid(tx), fee, value, total };
}

// ---------------------------------------------------------------------------
// Independent verification of an on-chain spend by `pubkeyHex`, from Esplora JSON.
// Recomputes the BIP143 sighash from the tx and its prevouts, then checks ECDSA.
// ---------------------------------------------------------------------------

export async function verifyEsploraSpend(etx, pubkeyHex) {
  const pkh = await hash160(hexToBytes(pubkeyHex));
  const tx = {
    version: etx.version,
    locktime: etx.locktime,
    inputs: etx.vin.map((v) => ({ txid: v.txid, vout: v.vout, sequence: v.sequence, value: v.prevout?.value ?? 0 })),
    outputs: etx.vout.map((o) => ({ value: o.value, script: hexToBytes(o.scriptpubkey) })),
  };
  for (let i = 0; i < etx.vin.length; i++) {
    const w = etx.vin[i].witness || [];
    if (w.length !== 2 || w[1].toLowerCase() !== pubkeyHex.toLowerCase()) continue;
    const sigBytes = hexToBytes(w[0]);
    if (sigBytes[sigBytes.length - 1] !== 0x01) continue; // SIGHASH_ALL only
    const sighash = await bip143Sighash(tx, i, pkh);
    const ok = ecdsaVerify(decompressPoint(hexToBytes(pubkeyHex)), sighash, derDecode(sigBytes.slice(0, -1)));
    return { ok, input: i };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Esplora client
// ---------------------------------------------------------------------------

async function esplora(path, opts) {
  const r = await fetch(ESPLORA + path, opts);
  const text = await r.text();
  if (!r.ok) throw new Error(`${path}: ${r.status} ${text.slice(0, 200)}`);
  return text;
}

export const getUtxos = async (addr) => JSON.parse(await esplora(`/address/${addr}/utxo`));
export const getAddressTxs = async (addr) => JSON.parse(await esplora(`/address/${addr}/txs`));
export const broadcast = (hex) => esplora("/tx", { method: "POST", body: hex });
export async function getFeeRate() {
  try { return Math.max(1, JSON.parse(await esplora("/v1/fees/recommended")).halfHourFee); } catch { return 2; }
}

export async function getBalance(addr) {
  const s = JSON.parse(await esplora(`/address/${addr}`));
  return {
    confirmed: s.chain_stats.funded_txo_sum - s.chain_stats.spent_txo_sum,
    unconfirmed: s.mempool_stats.funded_txo_sum - s.mempool_stats.spent_txo_sum,
    txCount: s.chain_stats.tx_count + s.mempool_stats.tx_count,
  };
}

// Find and independently verify a spend by `pubkeyHex` on signet. Returns null if none.
export async function findVerifiedSpend(pubkeyHex) {
  const addr = await p2wpkhAddress(hexToBytes(pubkeyHex));
  const txs = await getAddressTxs(addr);
  for (const etx of txs) {
    const res = await verifyEsploraSpend(etx, pubkeyHex);
    if (res) return { ...res, txid: etx.txid, confirmed: etx.status.confirmed, height: etx.status.block_height, addr };
  }
  return { ok: false, addr, txid: null };
}

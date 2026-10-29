// zk.js — prover and verifier for the demo proof object.
//
// ┌───────────────────────────────────────────────────────────────────────┐
// │  HONEST SCOPE NOTE                                                    │
// │                                                                       │
// │  The RELATION CHECK (step 1 in `prove`) is the exact logic a real     │
// │  SNARK/zkVM circuit would constrain: two HMAC-SHA512 BIP32 tweaks     │
// │  re-deriving K_A and K_B from a hidden xpub. That logic is REAL here.│
// │                                                                       │
// │  The ZERO-KNOWLEDGE ENVELOPE (step 2) is SIMULATED: instead of a      │
// │  Groth16 / RISC-Zero proof it emits a Fiat-Shamir-shaped transcript   │
// │  (witness commitment + challenge). It demonstrates proof structure,   │
// │  bindings (context, expiry, anchor key), and the fact that no witness │
// │  material appears in the output — but it is NOT yet a SNARK.          │
// │  Every swap-in point is marked  // === PRODUCTION SWAP ===            │
// └───────────────────────────────────────────────────────────────────────┘

import { sha256, hmacSha512, bytesToHex, hexToBytes, concatBytes } from "./hash.js";
import {
  scalarMul, pointAdd, pointEqual, compressPoint, decompressPoint,
  bytesToBigint, POINT_G,
} from "./secp256k1.js";

export const STATEMENT_ID = "xproof-ownership-link-v1";

// ---------------------------------------------------------------------------
// THE RELATION — this is exactly what the circuit constrains.
//   ∃ (K_par, c_par, path_A, path_B):
//     K_A = CKDpub*((K_par, c_par), path_A)
//     K_B = CKDpub*((K_par, c_par), path_B)
//   each CKDpub step:  I = HMAC-SHA512(c, ser_P(K) || i);  K' = K + I[0..32]·G;  c' = I[32..64]
// Paths may have any (non-hardened) depth, e.g. m/0/1 vs m/1/3.
// ---------------------------------------------------------------------------

async function ckdPub(node, index) {
  const serI = new Uint8Array(4);
  new DataView(serI.buffer).setUint32(0, index, false);
  const I = await hmacSha512(node.chain, concatBytes(compressPoint(node.pubPoint), serI));
  const tweak = I.slice(0, 32);
  return {
    tweak,
    pubPoint: pointAdd(node.pubPoint, scalarMul(bytesToBigint(tweak), POINT_G)),
    chain: I.slice(32, 64),
  };
}

const fmt = (path) => "m/" + path.join("/");

export async function checkRelation({ xpub, pathA, pathB, keyA, keyB }) {
  const checks = [];
  const walk = async (path, tag) => {
    let node = { pubPoint: xpub.pubPoint, chain: xpub.chain };
    for (let d = 0; d < path.length; d++) {
      node = await ckdPub(node, path[d]);
      checks.push({
        label: `${tag} step ${d + 1}: t = HMAC-SHA512(c, ser_P(K) ‖ ${path[d]})[0..32] → ${fmt(path.slice(0, d + 1))}`,
        value: bytesToHex(node.tweak),
        ok: true,
      });
    }
    return node.pubPoint;
  };

  const derivedA = await walk(pathA, "A");
  const derivedB = await walk(pathB, "B");
  checks.push({
    label: `K_A == CKDpub*(xpub, ${fmt(pathA)})  (child A derivation)`,
    ok: pointEqual(derivedA, decompressPoint(hexToBytes(keyA))),
  });
  checks.push({
    label: `K_B == CKDpub*(xpub, ${fmt(pathB)})  (child B derivation)`,
    ok: pointEqual(derivedB, decompressPoint(hexToBytes(keyB))),
  });

  return {
    checks,
    witnessBytes: {
      parentPubKeyHex: bytesToHex(compressPoint(xpub.pubPoint)),
      chainCodeHex: bytesToHex(xpub.chain),
      pathA: fmt(pathA),
      pathB: fmt(pathB),
    },
  };
}

// ---------------------------------------------------------------------------
// PROVER
// ---------------------------------------------------------------------------

export async function prove({ xpub, pathA, pathB, keyA, keyB, context, expiresAtMs }) {
  // Step 1 — run the circuit logic locally (REAL).
  const relation = await checkRelation({ xpub, pathA, pathB, keyA, keyB });
  if (!relation.checks.every((c) => c.ok)) {
    return { ok: false, relation, proof: null };
  }

  // Step 2 — wrap in a proof carrying ONLY public inputs. (SIMULATED envelope)
  //
  // === PRODUCTION SWAP ===
  //   RISC Zero  : receipt = prover.prove(env, XPROOF_GUEST_ELF)
  //                guest does exactly `checkRelation()` with (K_A,K_B) committed.
  //   SP1        : client.prove(pk, stdin).groth16()   // Groth16 wrapper — the
  //                core STARK mode is NOT zero-knowledge, don't use it for ZK.
  //   circom     : groth16.fullProve({Kpar,c_par,i,j}, "xproof.wasm", zkey)
  // The witness below never leaves this function; only the proof object does.
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);

  const witnessCommitment = await sha256(concatBytes(
    hexToBytes(relation.witnessBytes.parentPubKeyHex),
    hexToBytes(relation.witnessBytes.chainCodeHex),
    new TextEncoder().encode(JSON.stringify([pathA, pathB])),
    nonce
  ));

  const publicInputs = {
    key_a: keyA,
    key_b: keyB,
    context_hash: bytesToHex(await sha256(new TextEncoder().encode(context))),
    expires_at: expiresAtMs,
  };

  const fsChallenge = await sha256(concatBytes(
    new TextEncoder().encode(STATEMENT_ID),
    new TextEncoder().encode(JSON.stringify(publicInputs)),
    witnessCommitment,
    nonce
  ));

  const proof = {
    statement: STATEMENT_ID,
    scheme: "SIMULATED-SNARK (structure of a Fiat-Shamir NIZK; production = Groth16/RISC Zero receipt)",
    public_inputs: publicInputs,
    proof: {
      witness_commitment: bytesToHex(witnessCommitment),
      nonce: bytesToHex(nonce),
      fs_challenge: bytesToHex(fsChallenge),
    },
  };

  return { ok: true, relation, proof };
}

// ---------------------------------------------------------------------------
// VERIFIER — everything here is a REAL check except the last one.
// ---------------------------------------------------------------------------

export async function verify({ proofJson, expectedContext, anchorCheck, witnessBytesForLeakScan }) {
  let proof;
  const results = [];

  try {
    proof = JSON.parse(proofJson);
  } catch {
    return { ok: false, results: [{ label: "Proof parses as JSON", ok: false, kind: "real", detail: "invalid JSON" }] };
  }

  // 1. Integrity / transcript binding (REAL): recompute the Fiat-Shamir challenge.
  const expectedChallenge = bytesToHex(await sha256(concatBytes(
    new TextEncoder().encode(STATEMENT_ID),
    new TextEncoder().encode(JSON.stringify(proof.public_inputs)),
    hexToBytes(proof.proof.witness_commitment),
    hexToBytes(proof.proof.nonce)
  )));
  results.push({
    label: "Proof integrity — transcript recomputation matches (public inputs are bound)",
    ok: expectedChallenge === proof.proof.fs_challenge && proof.statement === STATEMENT_ID,
    kind: "real",
    detail: "any edit to key_a / key_b / context breaks this check",
  });

  // 2. Context binding & freshness (REAL).
  const ctxHash = bytesToHex(await sha256(new TextEncoder().encode(expectedContext)));
  results.push({
    label: "Context matches verifier session; proof not expired",
    ok: proof.public_inputs.context_hash === ctxHash && Date.now() < proof.public_inputs.expires_at,
    kind: "real",
    detail: "prevents replay of an old proof in a new session",
  });

  // 3. On-chain anchor for key B (REAL): K_B must have a valid signature on a chain.
  //    `anchorCheck` looks it up and re-verifies the signature (signet tx or mock chain).
  const anchor = await anchorCheck(proof.public_inputs.key_b);
  results.push({
    label: "Key B is anchored on-chain — its signature re-verified by the verifier",
    ok: anchor.ok,
    kind: "real",
    detail: anchor.detail,
  });

  // 4. Leak scan (REAL over the proof bytes; demo-only because it uses this session's
  //    witness values to search for them — a real verifier doesn't know them, which is
  //    precisely the point).
  const blob = JSON.stringify(proof);
  const needles = witnessBytesForLeakScan
    ? [witnessBytesForLeakScan.parentPubKeyHex, witnessBytesForLeakScan.chainCodeHex]
    : [];
  const leaked = needles.filter((n) => n && blob.includes(n));
  results.push({
    label: "No witness material in proof bytes (xpub pubkey / chain code absent)",
    ok: leaked.length === 0,
    kind: "real",
    detail: leaked.length
      ? `LEAKED: ${leaked.join(", ").slice(0, 60)}…`
      : "searched serialized proof for parent pubkey + chain code — not present",
  });

  // 5. SNARK validity (SIMULATED).
  //
  // === PRODUCTION SWAP ===
  //   groth16 / snarkjs : await snarkjs.groth16.verify(vkey, publicSignals, proof)
  //   RISC Zero         : receipt.verify(XPROOF_GUEST_ID)
  //   SP1               : client.verify(proof, &vk)
  results.push({
    label: "ZK proof validity (knowledge of linking xpub)",
    ok: true,
    kind: "simulated",
    detail: "SIMULATED — production replaces this with receipt/SNARK verification of the relation above",
  });

  const ok = results.every((r) => r.ok);
  return { ok, results };
}

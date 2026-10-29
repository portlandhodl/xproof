// prover.worker.js — runs the Noir/UltraHonk prover and verifier off the main thread.
// Messages in:  {id, op: "prove",  circuitUrl, inputs, threads, srsSize}
//               {id, op: "verify", vkUrl, proof, publicInputs, threads, srsSize}
// Messages out: {id, type: "progress", stage, detail} | {id, type: "done", result} | {id, type: "error", error}
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend, UltraHonkVerifierBackend } from "@aztec/bb.js";
import initNoirC from "@noir-lang/noirc_abi";
import initACVM from "@noir-lang/acvm_js";
import acvmUrl from "@noir-lang/acvm_js/web/acvm_js_bg.wasm?url";
import noircUrl from "@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url";

// UltraHonk with zero-knowledge and a Keccak transcript (EVM-verifiable).
const PROOF_OPTIONS = { verifierTarget: "evm" };

let noirReady;
const initNoir = () => (noirReady ??= Promise.all([initACVM({ module_or_path: acvmUrl }), initNoirC({ module_or_path: noircUrl })]));

async function fetchBytes(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

async function prove({ circuitUrl, inputs, threads, srsSize }, progress) {
  progress("load", "downloading circuit + WASM");
  const [program] = await Promise.all([fetch(circuitUrl).then((r) => r.json()), initNoir()]);
  progress("witness", "solving the circuit (HMAC-SHA512 ×22, ECDSA relation ×12)");
  const t0 = performance.now();
  const { witness } = await new Noir(program).execute(inputs);
  const witnessMs = performance.now() - t0;
  progress("crs", `starting Barretenberg (${threads} thread${threads > 1 ? "s" : ""}), fetching setup parameters`);
  const api = await Barretenberg.new({ threads, srsSize, logger: (m) => progress("bb", m) });
  try {
    progress("prove", "generating UltraHonk proof");
    const t1 = performance.now();
    const { proof, publicInputs } = await new UltraHonkBackend(program.bytecode, api).generateProof(witness, PROOF_OPTIONS);
    return { proof, publicInputs, witnessMs, proveMs: performance.now() - t1 };
  } finally {
    await api.destroy();
  }
}

async function verify({ vkUrl, proof, publicInputs, threads, srsSize }, progress) {
  progress("load", "loading verification key");
  const verificationKey = await fetchBytes(vkUrl);
  const api = await Barretenberg.new({ threads, srsSize });
  try {
    progress("verify", "verifying UltraHonk proof");
    const t0 = performance.now();
    const ok = await new UltraHonkVerifierBackend(api).verifyProof({ proof, publicInputs, verificationKey }, PROOF_OPTIONS);
    return { ok, verifyMs: performance.now() - t0 };
  } finally {
    await api.destroy();
  }
}

self.onmessage = async ({ data }) => {
  const { id, op } = data;
  const progress = (stage, detail) => self.postMessage({ id, type: "progress", stage, detail });
  try {
    const result = op === "prove" ? await prove(data, progress) : await verify(data, progress);
    self.postMessage({ id, type: "done", result });
  } catch (e) {
    self.postMessage({ id, type: "error", error: String(e?.message || e) });
  }
};

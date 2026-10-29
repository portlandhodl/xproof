// run.mjs — compile a Noir project with noir_wasm, report gate count, and optionally
// execute + prove + verify with bb.js (UltraHonk, ZK, EVM-verifiable transcript).
//   node tools/run.mjs <project-dir> [inputs.json] [--prove] [--out artifact.json]
import { compile_program, createFileManager } from "@noir-lang/noir_wasm";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { readFileSync, writeFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { resolve } from "node:path";

const [dir, inputsPath] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const flag = (f) => process.argv.includes(f);
const outIdx = process.argv.indexOf("--out");

const t0 = Date.now();
const { program } = await compile_program(createFileManager(resolve(dir)), undefined, () => {}, () => {});
console.log(`compiled in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
if (outIdx > 0) writeFileSync(process.argv[outIdx + 1], JSON.stringify(program));

const api = await Barretenberg.new({ threads: Number(process.env.THREADS || 16) });
const settings = { ipaAccumulation: false, oracleHashType: "keccak", disableZk: false, optimizedSolidityVerifier: false };
const bytecode = gunzipSync(Buffer.from(program.bytecode, "base64"));
const stats = await api.circuitStats({
  circuit: { name: "c", bytecode, verificationKey: new Uint8Array() }, includeGatesPerOpcode: false, settings,
});
console.log(`acir opcodes ${stats.numAcirOpcodes} · gates ${stats.numGates} · dyadic 2^${Math.log2(stats.numGatesDyadic)}`);

if (inputsPath) {
  const noir = new Noir(program);
  const t1 = Date.now();
  const { witness, returnValue } = await noir.execute(JSON.parse(readFileSync(inputsPath, "utf8")));
  console.log(`executed in ${((Date.now() - t1) / 1000).toFixed(1)}s`, returnValue !== undefined ? JSON.stringify(returnValue).slice(0, 300) : "");
  if (flag("--prove")) {
    const backend = new UltraHonkBackend(program.bytecode, api);
    const t2 = Date.now();
    const proof = await backend.generateProof(witness, { verifierTarget: "evm" });
    console.log(`proved in ${((Date.now() - t2) / 1000).toFixed(1)}s · proof ${proof.proof.length} bytes · ${proof.publicInputs.length} public inputs`);
    const t3 = Date.now();
    console.log(`verified: ${await backend.verifyProof(proof, { verifierTarget: "evm" })} in ${((Date.now() - t3) / 1000).toFixed(1)}s`);
  }
}
await api.destroy();

// build-circuit.mjs — compile the Noir circuit and derive its verification key.
// Outputs (committed, served statically):
//   circuits/xproof.json      compiled ACIR program (bytecode + ABI)
//   circuits/xproof.vk        UltraHonk verification key (ZK, keccak transcript)
//   circuits/manifest.json    versions, gate count, sha256 of both files
import { compile_program, createFileManager } from "@noir-lang/noir_wasm";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";

const root = new URL("../../", import.meta.url);
const out = new URL("circuits/", root);
mkdirSync(out, { recursive: true });
const pkg = (p) => JSON.parse(readFileSync(new URL(`node_modules/${p}/package.json`, import.meta.url.replace(/tools\/.*$/, "")), "utf8")).version;

const { program } = await compile_program(createFileManager(new URL("xproof", new URL("../", import.meta.url)).pathname), undefined, () => {}, () => {});
const json = JSON.stringify(program);
writeFileSync(new URL("xproof.json", out), json);

const api = await Barretenberg.new({ threads: 16 });
const vk = await new UltraHonkBackend(program.bytecode, api).getVerificationKey({ verifierTarget: "evm" });
writeFileSync(new URL("xproof.vk", out), vk);
const stats = await api.circuitStats({
  circuit: { name: "xproof", bytecode: gunzipSync(Buffer.from(program.bytecode, "base64")), verificationKey: new Uint8Array() },
  includeGatesPerOpcode: false,
  settings: { ipaAccumulation: false, oracleHashType: "keccak", disableZk: false, optimizedSolidityVerifier: false },
});
await api.destroy();

const sha = (b) => createHash("sha256").update(b).digest("hex");
const manifest = {
  statement: "xproof-ownership-link-v1",
  proof_system: "UltraHonk (zero-knowledge, keccak transcript / verifierTarget=evm)",
  max_depth: Number(readFileSync(new URL("../xproof/src/main.nr", import.meta.url), "utf8").match(/MAX_DEPTH: u32 = (\d+)/)[1]),
  gates: stats.numGates,
  gates_dyadic_log2: Math.log2(stats.numGatesDyadic),
  public_inputs: "key_a[33] ‖ key_b[33] ‖ context_hash[32] ‖ expires_at",
  noir: pkg("@noir-lang/noir_wasm"),
  bb_js: pkg("@aztec/bb.js"),
  circuit_sha256: sha(json),
  vk_sha256: sha(vk),
};
writeFileSync(new URL("manifest.json", out), JSON.stringify(manifest, null, 2) + "\n");
console.log(manifest);

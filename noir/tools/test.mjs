// test.mjs — circuit tests against the committed build (circuits/xproof.json):
//   1. path shapes: keys must equal the SP1 guest's output for the same seed/paths
//   2. soundness: forged witnesses must fail to execute (no proof can exist)
//   3. one full prove + verify (UltraHonk, ZK) unless --quick
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { readFileSync } from "node:fs";
const R = new URL("../../js/", import.meta.url).href;
const B = await import(R + "bip32.js"), W = await import(R + "noir-witness.js"), H = await import(R + "hash.js");
const S = await import(R + "secp256k1.js");

const program = JSON.parse(readFileSync(new URL("../../circuits/xproof.json", import.meta.url), "utf8"));
const noir = new Noir(program);
const master = await B.masterFromSeed(H.hexToBytes("000102030405060708090a0b0c0d0e0f")); // BIP32 TV1
const inputsFor = async (a, b) => (await W.buildInputs({
  xpub: B.toXpubData(master), pathA: B.parsePath(a), pathB: B.parsePath(b),
  contextHash: await H.sha256(new TextEncoder().encode("c")), expiresAt: 9999999999999,
})).inputs;
let failures = 0;
const check = (ok, msg) => { console.log(`${ok ? "  ok " : "FAIL "} ${msg}`); if (!ok) failures++; };
const hexOf = (a) => Buffer.from(a).toString("hex");

console.log("path shapes (expected keys from the SP1 guest, `xproof-host execute`):");
const SP1 = {
  "0/1 1/3": ["02e740d213a1aa5746c66bae1ecda3b95d7f64d4bf8aff9d93702fc302f28df0f1", "02e347b51cef755094b35cf0c26c20886e57d3407f708f797c2ef5880cb484ace4"],
  "0/1 0/2": ["02e740d213a1aa5746c66bae1ecda3b95d7f64d4bf8aff9d93702fc302f28df0f1", "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b"],
  "0 0/5/2": ["027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c", "022b8744e9bd64ab07fbef0fa67e20437a69d605c0b6163c0733be6befbaae4f87"],
};
for (const [k, [ka, kb]] of Object.entries(SP1)) {
  const inputs = await inputsFor(...k.split(" "));
  let ok = hexOf(inputs.key_a) === ka && hexOf(inputs.key_b) === kb;
  try { await noir.execute(inputs); } catch { ok = false; }
  check(ok, `m/${k.replace(" ", " ↔ m/")} executes and matches SP1`);
}
try { await inputsFor("0/1/2/3", "1"); check(false, "depth 4 refused"); } catch { check(true, "depth 4 refused by the witness builder"); }

console.log("soundness (each forged witness must be rejected):");
const honest = await inputsFor("0/1", "1/3");
const L = (x) => [0n, 1n, 2n, 3n].map((k) => ((x >> (64n * k)) & ((1n << 64n) - 1n)).toString());
const fromL = (l) => l.reduce((a, v, k) => a + (BigInt(v) << (64n * BigInt(k))), 0n);
const forgeries = {
  "negated key_a (parity byte flipped)": (i) => { i.key_a[0] ^= 1; },
  "negated child point with consistent key (parity attack)": (i) => {
    const h = i.hints_a[1], ny = S.FIELD_P - fromL(h.child.y);
    h.child.y = L(ny); h.child_curve.yy = L((ny * ny) % S.FIELD_P); h.child_curve.q_yy = L((ny * ny) / S.FIELD_P);
    i.key_a[0] ^= 1;
  },
  "unrelated key_b": (i) => { i.key_b[5] ^= 0x40; },
  "wrong path index": (i) => { i.path_b[1] = 4; },
  "hardened index": (i) => { i.path_a[0] = 0x80000000; },
  "high-S signature half": (i) => { const h = i.hints_a[0].fwd; h.s = L(S.ORDER_N - fromL(h.s)); h.s_neg = !h.s_neg; },
  "path length 0": (i) => { i.len_a = 0; },
  "path length 4": (i) => { i.len_a = 4; },
  "same key twice": (i) => { i.key_b = i.key_a; i.path_b = i.path_a; i.len_b = i.len_a; i.hints_b = i.hints_a; },
  "child point off the curve": (i) => { const h = i.hints_b[0]; h.child.y = L(fromL(h.child.y) + 1n); },
};
try { await noir.execute(honest); check(true, "honest witness executes (control)"); } catch (e) { check(false, "honest witness: " + e.message); }
for (const [name, forge] of Object.entries(forgeries)) {
  const i = structuredClone(honest); forge(i);
  let rejected = false;
  try { await noir.execute(i); } catch { rejected = true; }
  check(rejected, name);
}

if (!process.argv.includes("--quick")) {
  console.log("prove + verify (UltraHonk, ZK, keccak transcript):");
  const { witness } = await noir.execute(honest);
  const api = await Barretenberg.new({ threads: 16 });
  const backend = new UltraHonkBackend(program.bytecode, api);
  const t0 = Date.now();
  const proof = await backend.generateProof(witness, { verifierTarget: "evm" });
  check(await backend.verifyProof(proof, { verifierTarget: "evm" }), `proof verifies (${proof.proof.length} bytes, ${((Date.now() - t0) / 1000).toFixed(0)}s)`);
  const vk = readFileSync(new URL("../../circuits/xproof.vk", import.meta.url));
  const fresh = await new UltraHonkBackend(program.bytecode, api).getVerificationKey({ verifierTarget: "evm" });
  check(Buffer.compare(vk, Buffer.from(fresh)) === 0, "committed circuits/xproof.vk matches the circuit");
  proof.publicInputs[0] = "0x" + "0".repeat(62) + "03";
  check(!(await backend.verifyProof(proof, { verifierTarget: "evm" })), "proof rejected with a tampered public input");
  await api.destroy();
}
console.log(failures ? `\n${failures} FAILED` : "\nall tests passed");
process.exit(failures ? 1 : 0);

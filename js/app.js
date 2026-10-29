// app.js — orchestration: Wallet → Prover → Verifier.
// Only zero-knowledge proofs are offered: UltraHonk generated in the browser (Noir → WASM),
// and, when a self-hosted xproof-host server is reachable, SP1 → Groth16.
// Key B's on-chain anchor is a real signet spend, re-verified from the chain by the verifier.
// Keys A and B may sit at any non-hardened depth below the xpub (e.g. m/0/1 vs m/1/3).

import { sha256, bytesToHex as hex } from "./hash.js";
import * as S from "./secp256k1.js";
import * as B from "./bip32.js";
import * as BTC from "./btc.js";
import { buildInputs, parsePublicInputs, NOIR_MAX_DEPTH } from "./noir-witness.js";
import { proveInBrowser, verifyInBrowser, threadCount } from "../vendor/zk/zk-browser.js";

const $ = (id) => document.getElementById(id);

const state = {
  master: null,
  xpubData: null,     // {pubPoint, chain} — the witness
  pathA: null,        // number[]
  pathB: null,
  childA: null,
  childB: null,
  realJournal: null,  // public values of the last generated proof
  proving: false,
  addrA: null,        // signet P2WPKH addresses of the two keys
  addrB: null,
  server: false,      // self-hosted xproof-host API reachable (enables the Groth16 prover)
};

// Signet wallet persistence (this browser only — test coins, never real funds).
const STORE = { seed: "xproof.signet.seed", pathA: "xproof.pathA", pathB: "xproof.pathB", lastProof: "xproof.lastProof" };

const enc = new TextEncoder();
const hexRe = /^[0-9a-f]*$/i;
const keyHex = (node) => hex(S.compressPoint(node.pubPoint));
function hexToBytesStrict(h) {
  if (typeof h !== "string" || h.length % 2 || !hexRe.test(h)) throw new Error("proof is not valid hex");
  return new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
}

function parseJournal(journalHex) {
  if (!hexRe.test(journalHex) || journalHex.length !== 212) return null;
  return {
    key_a: journalHex.slice(0, 66),
    key_b: journalHex.slice(66, 132),
    context_hash: journalHex.slice(132, 196),
    expires_at: Number(BigInt("0x" + journalHex.slice(196, 212))),
  };
}

function setStep(n) {
  for (const li of $("stepper").children) {
    const s = Number(li.dataset.step);
    li.classList.toggle("done", s < n);
    li.classList.toggle("active", s === n);
  }
}

function showError(id, msg) {
  $(id).textContent = msg || "";
  $(id).classList.toggle("hidden", !msg);
}

function resetProofs() {
  state.realJournal = null;
  $("realProofBox").classList.add("hidden");
  $("verifyJson").value = "";
  $("checkResults").innerHTML = "";
  $("verdict").className = "hidden";
  $("proofMode").textContent = "none";
  $("btnVerify").disabled = true;
  $("btnTamper").disabled = true;
}

// ---- Derivation tree (SVG) ----------------------------------------------------

function renderTree(pathA, pathB) {
  const svg = $("tree");
  const NS = "http://www.w3.org/2000/svg";
  const COL = 84, X0 = 46, MID = 85, UP = 38, DOWN = 132;

  let common = 0;
  while (common < pathA.length && common < pathB.length && pathA[common] === pathB[common]) common++;
  const depth = Math.max(pathA.length, pathB.length);
  const width = X0 * 2 + COL * depth + 40;
  svg.setAttribute("viewBox", `0 0 ${width} 170`);
  svg.style.width = width + "px";
  svg.innerHTML =
    `<defs><linearGradient id="sharedGrad"><stop offset="0" stop-color="#fbbf24"/>` +
    `<stop offset="1" stop-color="#c4b5fd"/></linearGradient></defs>`;

  const edges = document.createElementNS(NS, "g");
  const nodes = document.createElementNS(NS, "g");
  svg.append(edges, nodes);

  const edge = (p, q, cls) => {
    const path = document.createElementNS(NS, "path");
    const mx = (p.x + q.x) / 2;
    path.setAttribute("d", `M${p.x},${p.y} C${mx},${p.y} ${mx},${q.y} ${q.x},${q.y}`);
    path.setAttribute("class", "edge " + cls);
    edges.appendChild(path);
  };
  const node = (x, y, text, cls, label, labelCls, labelBelow) => {
    const g = document.createElementNS(NS, "g");
    g.setAttribute("class", cls);
    g.innerHTML =
      `<circle cx="${x}" cy="${y}" r="${cls.includes("n-root") ? 20 : 15}"/>` +
      `<text class="idx" x="${x}" y="${y}">${text}</text>` +
      (label ? `<text class="lbl ${labelCls}" x="${x}" y="${y + (labelBelow ? 30 : -28)}">${label}</text>` : "");
    nodes.appendChild(g);
    return { x, y };
  };

  const root = node(X0, MID, "xpub", "n-root", "hidden", "root", true);
  let prev = root;
  for (let d = 0; d < common; d++) {
    const isLeafA = d === pathA.length - 1, isLeafB = d === pathB.length - 1;
    const leaf = isLeafA || isLeafB;
    const label = isLeafA && isLeafB ? "A = B" : isLeafA ? "Key A" : isLeafB ? "Key B" : "";
    const n = node(X0 + COL * (d + 1), MID, pathA[d], "n-shared" + (leaf ? " leaf" : ""), label, isLeafA ? "a" : "b", false);
    edge(prev, n, "shared");
    prev = n;
  }
  const branch = prev;
  for (const [path, tag] of [[pathA, "a"], [pathB, "b"]]) {
    if (path.length === common) continue;
    // If one key is an ancestor of the other, the descendant continues on the centre line.
    const other = tag === "a" ? pathB : pathA;
    const y = other.length === common ? MID : tag === "a" ? UP : DOWN;
    let p = branch;
    for (let d = common; d < path.length; d++) {
      const leaf = d === path.length - 1;
      const n = node(X0 + COL * (d + 1), y, path[d], `n-${tag}` + (leaf ? " leaf" : ""),
        leaf ? (tag === "a" ? "Key A" : "Key B") : "", tag, y === DOWN || (y === MID && tag === "b"));
      edge(p, n, tag);
      p = n;
    }
  }
}

// ---- Step 1: wallet + paths ----------------------------------------------------

async function derivePaths() {
  if (!state.master) return false;
  let pathA, pathB;
  try {
    pathA = B.parsePath($("pathA").value);
    pathB = B.parsePath($("pathB").value);
    if (pathA.join("/") === pathB.join("/")) throw new Error("Path A and Path B must differ");
  } catch (e) {
    showError("pathError", e.message);
    for (const id of ["btnProveWasm", "btnProveZk"]) $(id).disabled = true;
    return false;
  }
  showError("pathError", "");

  const childA = await B.derivePathPub(state.xpubData, pathA);
  const childB = await B.derivePathPub(state.xpubData, pathB);
  const childBPriv = await B.derivePathPriv(state.master, pathB);
  if (!S.pointEqual(childBPriv.pubPoint, childB.pubPoint)) {
    throw new Error("xpub-side and priv-side derivation disagree");
  }
  childB.priv = childBPriv.priv;

  const changed = !state.pathA || state.pathA.join("/") !== pathA.join("/") || state.pathB.join("/") !== pathB.join("/");
  Object.assign(state, { pathA, pathB, childA, childB });
  if (changed) resetProofs();

  localStorage.setItem(STORE.pathA, pathA.join("/"));
  localStorage.setItem(STORE.pathB, pathB.join("/"));
  const oldAddrB = state.addrB;
  state.addrA = await BTC.p2wpkhAddress(S.compressPoint(childA.pubPoint));
  state.addrB = await BTC.p2wpkhAddress(S.compressPoint(childB.pubPoint));
  $("addrA").textContent = state.addrA;
  $("addrB").textContent = state.addrB;
  $("linkB").href = `${BTC.NETWORK.explorer}/address/${state.addrB}`;
  if (!$("spendDest").value || $("spendDest").value === oldAddrB) $("spendDest").value = state.addrB;
  if (oldAddrB !== state.addrB) refreshBalance();

  $("pathALabel").textContent = B.formatPath(pathA);
  $("pathBLabel").textContent = B.formatPath(pathB);
  $("pubA").textContent = keyHex(childA);
  $("pubB").textContent = keyHex(childB);
  $("privB").textContent = hex(childB.priv);
  renderTree(pathA, pathB);

  setRealButtons();
  return true;
}

async function loadWallet(seed) {
  state.master = await B.masterFromSeed(seed);
  state.xpubData = B.toXpubData(state.master);
  state.pathA = state.pathB = null;
  state.addrB = null;
  $("spendOut").classList.add("hidden");
  showError("spendError", "");
  $("xpubStr").textContent = await B.serializeXpub(state.master, { testnet: true });
  $("seedHex").textContent = hex(seed);
  localStorage.setItem(STORE.seed, hex(seed));
  $("walletOut").classList.remove("hidden");
  $("btnGen").textContent = "New wallet";
  await derivePaths();
  setStep(2);
}

$("btnGen").onclick = async () => {
  if (state.master && !confirm(
    "Replace the saved signet wallet? Any sats on it are lost unless you copy the seed first.\n\nSeed: " +
    $("seedHex").textContent)) return;
  $("btnGen").disabled = true;
  try {
    const seed = new Uint8Array(16);
    crypto.getRandomValues(seed);
    await loadWallet(seed);
  } finally {
    $("btnGen").disabled = false;
  }
};

$("btnRestore").onclick = async () => {
  const h = $("restoreSeed").value.trim().toLowerCase();
  if (!/^([0-9a-f]{2}){16,64}$/.test(h)) return alert("Seed must be 16–64 bytes of hex.");
  await loadWallet(new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16))));
  $("restoreBox").open = false;
};

let deriveTimer;
for (const id of ["pathA", "pathB"]) {
  $(id).addEventListener("input", () => {
    clearTimeout(deriveTimer);
    deriveTimer = setTimeout(derivePaths, 200);
  });
}
for (const btn of document.querySelectorAll(".presets .chipbtn")) {
  btn.onclick = () => {
    $("pathA").value = btn.dataset.a;
    $("pathB").value = btn.dataset.b;
    derivePaths();
  };
}

// ---- Step 1b: signet deposit + spend from key B ----------------------------------

const fmtSats = (n) => n.toLocaleString("en-US") + " sats";

async function refreshBalance() {
  const addr = state.addrB;
  if (!addr) return;
  try {
    const b = await BTC.getBalance(addr);
    if (addr !== state.addrB) return; // paths changed meanwhile
    const total = b.confirmed + b.unconfirmed;
    $("balB").textContent = fmtSats(total);
    $("balBNote").textContent = b.unconfirmed ? `(${fmtSats(b.unconfirmed)} unconfirmed)` : b.txCount ? "" : "— waiting for a deposit";
    $("btnSpend").disabled = total <= 0;
  } catch (e) {
    $("balB").textContent = "—";
    $("balBNote").textContent = "explorer unreachable: " + (e.message || e).slice(0, 80);
  }
}
setInterval(() => { if (!document.hidden) refreshBalance(); }, 20000);
$("btnRefresh").onclick = refreshBalance;
$("btnCopyB").onclick = async () => {
  try { await navigator.clipboard.writeText(state.addrB); $("btnCopyB").textContent = "Copied ✓"; }
  catch { getSelection().selectAllChildren($("addrB")); $("btnCopyB").textContent = "Selected"; }
  setTimeout(() => { $("btnCopyB").textContent = "Copy"; }, 1500);
};

$("btnSpend").onclick = async () => {
  $("btnSpend").disabled = true;
  showError("spendError", "");
  $("spendOut").classList.add("hidden");
  try {
    const dest = $("spendDest").value.trim();
    BTC.scriptForAddress(dest); // validate before touching the network
    const [utxos, feeRate] = await Promise.all([BTC.getUtxos(state.addrB), BTC.getFeeRate()]);
    const sweep = await BTC.buildSweep({
      utxos, privBytes: state.childB.priv, pubPoint: state.childB.pubPoint, destAddress: dest, feeRate,
    });
    const txid = (await BTC.broadcast(sweep.hex)).trim();
    if (txid !== sweep.txid) throw new Error(`broadcast returned ${txid}, expected ${sweep.txid}`);
    const out = $("spendOut");
    out.innerHTML = `✅ Broadcast <a target="_blank" rel="noopener"></a><br><span class="dim"></span>`;
    out.querySelector("a").href = `${BTC.NETWORK.explorer}/tx/${txid}`;
    out.querySelector("a").textContent = `tx ${txid.slice(0, 16)}…${txid.slice(-6)} ↗`;
    out.querySelector(".dim").textContent =
      `spent ${utxos.length} UTXO${utxos.length > 1 ? "s" : ""} (${fmtSats(sweep.total)}) → ${fmtSats(sweep.value)} to ${dest.slice(0, 14)}…, fee ${fmtSats(sweep.fee)}. ` +
      `Key B's pubkey + signature are now public on signet — that's the anchor the verifier re-checks.`;
    out.classList.remove("hidden");
    setTimeout(refreshBalance, 1500);
  } catch (e) {
    showError("spendError", "Spend failed: " + (e.message || e));
  } finally {
    $("btnSpend").disabled = false;
  }
};

function loadIntoVerifier(text, mode) {
  $("verifyJson").value = text;
  $("btnVerify").disabled = false;
  $("btnTamper").disabled = false;
  $("proofMode").textContent = mode;
  $("checkResults").innerHTML = "";
  $("verdict").className = "hidden";
  setStep(3);
}

// ---- Step 2: provers — in-browser (Noir → UltraHonk, WASM) and server (SP1 → Groth16) ----

const CIRCUIT = { url: "circuits/xproof.json", vk: "circuits/xproof.vk", manifest: "circuits/manifest.json" };
let manifest = null;

// Fit to measurements in headless Chrome on a server CPU (README "Performance"):
// 1 thread ≈ 280 s, 16 threads ≈ 65 s. Slower laptops/phones can take 2–3× longer.
function wasmEstimateSec() {
  return Math.round(50 + 230 / Math.pow(threadCount(), 0.7));
}
const fmtDur = (s) => (s < 90 ? `${Math.round(s)}s` : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`);

const REAL_MODES = {
  noir: { btn: "btnProveWasm", label: "In-browser UltraHonk (WASM)", est: wasmEstimateSec },
  groth16: { btn: "btnProveZk", label: "SP1 → Groth16 (server)", est: () => 240, server: true },
};
const wasmDepthOk = () => state.pathA && Math.max(state.pathA.length, state.pathB.length) <= NOIR_MAX_DEPTH;

function setRealButtons() {
  for (const [mode, m] of Object.entries(REAL_MODES)) {
    let off = state.proving || !state.pathA || (m.server && !state.server);
    if (mode === "noir") off ||= !wasmDepthOk() || !manifest;
    $(m.btn).disabled = off;
  }
  const deep = state.pathA && !wasmDepthOk();
  $("depthNote").classList.toggle("hidden", !deep);
  if (deep) {
    $("depthNote").textContent = `The in-browser circuit has a fixed size and supports paths up to depth ${NOIR_MAX_DEPTH}. ` +
      (state.server ? "Use a server prover (depth ≤ 16) for these paths." : "Pick shallower paths, or self-host the server prover (depth ≤ 16).");
  }
}

function setBusy(btnId, busy) { $(btnId).classList.toggle("busy", busy); }

const STAGES = {
  load: "Loading circuit & WebAssembly", witness: "Solving the circuit (witness)", crs: "Fetching setup parameters",
  prove: "Generating the proof", server: "Proving on the server",
};

async function proveNoir(onStage) {
  const pathA = state.pathA, pathB = state.pathB;
  const { inputs } = await buildInputs({
    xpub: state.xpubData, pathA, pathB,
    contextHash: await sha256(enc.encode($("ctx").value)),
    expiresAt: Date.now() + 24 * 3600 * 1000, // generous: browser proofs can take a while
  });
  const t0 = Date.now();
  const res = await proveInBrowser({
    circuitUrl: CIRCUIT.url, inputs, srsLog2: manifest.gates_dyadic_log2,
    onProgress: (stage, detail) => stage !== "bb" && onStage(stage, detail),
  });
  return {
    journal: parsePublicInputs(res.publicInputs),
    sizeBytes: res.proof.length,
    elapsedMs: Date.now() - t0,
    meta: `UltraHonk, zero-knowledge · ${threadCount()} thread${threadCount() > 1 ? "s" : ""} · witness ${(res.witnessMs / 1000).toFixed(0)}s`,
    payload: { mode: "noir", proof_hex: hex(res.proof), public_inputs: res.publicInputs, vk_sha256: manifest.vk_sha256 },
  };
}

async function proveServer(onStage) {
  onStage("server", "contacting prover…");
  const resp = await fetch("api/prove", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      parent_pub: hex(S.compressPoint(state.master.pubPoint)),
      chain_code: hex(state.master.chain),
      path_a: state.pathA.join("/"),
      path_b: state.pathB.join("/"),
      context: $("ctx").value,
      expires_at: Date.now() + 24 * 3600 * 1000,
      mode: "groth16",
    }),
  });
  const data = await resp.json().catch(() => ({ ok: false, error: `HTTP ${resp.status}` }));
  if (!data.ok) throw new Error(data.error || "proving failed");
  return {
    journal: parseJournal(data.journal_hex),
    sizeBytes: data.proof_hex.length / 2,
    elapsedMs: data.elapsed_ms,
    meta: `Groth16, zero-knowledge · vk ${data.vk_hex.slice(0, 18)}…`,
    payload: { mode: "groth16", groth16_hex: data.proof_hex, journal_hex: data.journal_hex },
  };
}

async function proveReal(mode) {
  const cfg = REAL_MODES[mode];
  state.proving = true;
  setRealButtons();
  setBusy(cfg.btn, true);
  showError("realError", "");
  $("realProgress").classList.remove("hidden");
  const est = cfg.est();
  const t0 = Date.now();
  let stage = "load";
  const onStage = (s, detail) => {
    stage = s;
    $("realStage").textContent = STAGES[s] || s;
    $("realStatus").textContent = detail || "";
  };
  onStage(mode === "noir" ? "load" : "server", "");
  const tick = setInterval(() => {
    const s = (Date.now() - t0) / 1000;
    // Asymptotic fill so the bar never claims to be done before the prover is.
    $("realBar").style.width = (95 * (1 - Math.exp(-s / (est * 0.6)))).toFixed(1) + "%";
    $("realElapsed").textContent = `${fmtDur(s)} elapsed · typically ~${fmtDur(est)} here`;
  }, 500);
  $("realBar").style.width = "0";
  const pathA = state.pathA, pathB = state.pathB;
  try {
    const r = mode === "noir" ? await proveNoir(onStage) : await proveServer(onStage);
    if (state.pathA !== pathA || state.pathB !== pathB) throw new Error("paths changed while proving — prove again");
    state.realJournal = r.journal;

    const j = r.journal;
    const size = r.sizeBytes < 4096 ? `${r.sizeBytes} bytes` : `${(r.sizeBytes / 1024).toFixed(0)} KB`;
    $("realJournal").textContent =
      `key_a         ${j.key_a}\nkey_b         ${j.key_b}\n` +
      `context_hash  ${j.context_hash}\nexpires_at    ${new Date(j.expires_at).toISOString()}`;
    $("realMeta").textContent = `${cfg.label} · ${r.meta} · proved in ${fmtDur(r.elapsedMs / 1000)} · proof ${size} · paths stay hidden`;
    $("realProofBox").classList.remove("hidden");
    const text = JSON.stringify(r.payload, null, 2);
    if (text.length < 1e6) localStorage.setItem(STORE.lastProof, text);
    loadIntoVerifier(text, modeLabel(r.payload.mode));
  } catch (e) {
    showError("realError", `Proof failed during “${STAGES[stage] || stage}”: ${e.message || e}`);
  } finally {
    clearInterval(tick);
    state.proving = false;
    setBusy(cfg.btn, false);
    setRealButtons();
    $("realProgress").classList.add("hidden");
  }
}

const MODE_LABELS = { noir: "ZK UltraHonk (browser)", groth16: "ZK Groth16" };
const modeLabel = (m) => MODE_LABELS[m] || "unrecognised";

$("btnProveWasm").onclick = () => proveReal("noir");
$("btnProveZk").onclick = () => proveReal("groth16");
window.addEventListener("beforeunload", (e) => { if (state.proving) e.preventDefault(); });

$("btnDownload").onclick = () => {
  const blob = new Blob([$("verifyJson").value], { type: "application/json" });
  const a = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(blob),
    download: `xproof-${JSON.parse($("verifyJson").value).mode}-${new Date().toISOString().slice(0, 19).replace(/:/g, "")}.json`,
  });
  a.click();
  URL.revokeObjectURL(a.href);
};

// ---- Step 3: verifier ---------------------------------------------------------

const isKnownPayload = (p) => p && Object.hasOwn(MODE_LABELS, p.mode);

$("btnTamper").onclick = () => {
  try {
    const p = JSON.parse($("verifyJson").value);
    const flip = (h, i) => h.slice(0, i) + (h[i] === "0" ? "1" : "0") + h.slice(i + 1);
    if (p.mode === "noir") {
      // Claim a different key A (flip the parity byte) — the proof no longer matches.
      p.public_inputs[0] = "0x" + (BigInt(p.public_inputs[0]) ^ 1n).toString(16).padStart(64, "0");
    } else if (p.mode === "groth16") {
      // Claim a different key A in the public values — the SNARK no longer matches.
      p.journal_hex = flip(p.journal_hex, 1);
    }
    $("verifyJson").value = JSON.stringify(p, null, 2);
    $("proofMode").textContent += " (tampered)";
  } catch { /* ignore */ }
};

const ANCHOR_LABEL = "Key B is anchored on signet — its spend signature re-verified by the verifier";

function pushCheck(res, i) {
  const li = document.createElement("li");
  li.className = res.ok ? "ok" : "fail";
  li.style.animationDelay = `${i * 70}ms`;
  li.innerHTML =
    `<span class="ico">${res.ok ? "✅" : "❌"}</span><span class="label"></span><span class="detail"></span>`;
  li.querySelector(".label").textContent = res.label;
  li.querySelector(".detail").textContent = res.detail;
  $("checkResults").appendChild(li);
}

// Anchor for key B: a real signet spend, found from key_b alone; BIP143 sighash recomputed here.
async function anchorCheck(keyBHex) {
  try {
    const spend = await BTC.findVerifiedSpend(keyBHex);
    if (spend.ok) {
      return {
        ok: true,
        detail: `signet tx ${spend.txid.slice(0, 16)}… input #${spend.input} — BIP143 sighash recomputed, ECDSA signature by key B verifies ` +
          `(${spend.confirmed ? `confirmed in block ${spend.height}` : "in mempool, unconfirmed"})`,
      };
    }
    return { ok: false, detail: `no spend by ${spend.addr.slice(0, 14)}… on signet yet — deposit to key B and spend it in step 1` };
  } catch {
    return { ok: false, detail: "signet explorer unreachable — can't check the anchor right now" };
  }
}

// Proof-system check for each mode. Returns {ok, journal, label, detail}.
async function checkProofSystem(input) {
  if (input.mode === "noir") {
    const label = "UltraHonk proof verifies against the xproof circuit's verification key (in this browser)";
    try {
      const { ok, verifyMs } = await verifyInBrowser({
        vkUrl: CIRCUIT.vk, proof: hexToBytesStrict(input.proof_hex), publicInputs: input.public_inputs,
      });
      const vkNote = manifest && input.vk_sha256 && input.vk_sha256 !== manifest.vk_sha256
        ? " · WARNING: proof claims a different circuit version" : "";
      return {
        ok, label, journal: ok ? parsePublicInputs(input.public_inputs) : null,
        detail: ok
          ? `zero-knowledge proof of ${input.proof_hex.length / 2} bytes verified in ${(verifyMs / 1000).toFixed(1)}s · vk sha256 ${manifest?.vk_sha256.slice(0, 16)}…${vkNote}`
          : "rejected: proof does not match these public inputs",
      };
    } catch (e) {
      return { ok: false, label, detail: `rejected: ${e.message || e}` };
    }
  }
  const label = "Groth16 SNARK verifies (standalone verifier: proof bytes + public values + vk hash)";
  if (!state.server) return { ok: false, label, detail: "Groth16 proofs are checked by the self-hosted xproof-host server, which isn't available on this page" };
  let vdata;
  try {
    const resp = await fetch("api/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ groth16_hex: input.groth16_hex, journal_hex: input.journal_hex }),
    });
    vdata = await resp.json();
  } catch (e) {
    vdata = { ok: false, error: String(e) };
  }
  return {
    ok: !!vdata.ok, label, journal: vdata.ok ? parseJournal(vdata.journal_hex) : null,
    detail: vdata.ok
      ? `zero-knowledge proof of ${input.groth16_hex.length / 2} bytes verified · vk ${vdata.vk_hex.slice(0, 18)}…`
      : `rejected: ${vdata.error}`,
  };
}

async function verifyReal(input) {
  const results = [];
  const proofHex = input.proof_hex || input.groth16_hex || "";

  // 1. The proof itself.
  const sys = await checkProofSystem(input);
  results.push({ label: sys.label, ok: sys.ok, detail: sys.detail });
  if (!sys.ok) return results;
  const j = sys.journal;

  // 2. Which keys the proof links. If this browser holds the wallet, they must be its children.
  if (state.childA) {
    const ok = j.key_a === keyHex(state.childA) && j.key_b === keyHex(state.childB);
    results.push({
      label: "Proof links the two child keys shown in step 1",
      ok,
      detail: `binds K_A ${j.key_a.slice(0, 16)}… and K_B ${j.key_b.slice(0, 16)}… (derivation paths stay hidden)` +
        (ok ? "" : " — not this wallet's keys"),
    });
  } else {
    results.push({
      label: "Proof links two child keys of one hidden xpub",
      ok: true,
      detail: `K_A ${j.key_a} · K_B ${j.key_b}`,
    });
  }

  // 3. Context + expiry (only the context hash is in the proof).
  const ctxHash = hex(await sha256(enc.encode($("ctx").value)));
  results.push({
    label: "Context hash matches this session; proof not expired",
    ok: j.context_hash === ctxHash && Date.now() < j.expires_at,
    detail: j.context_hash !== ctxHash ? "context mismatch — the proof was made for a different session"
      : Date.now() >= j.expires_at ? `expired ${new Date(j.expires_at).toLocaleString()}`
      : `anti-replay context bound into the proof · valid until ${new Date(j.expires_at).toLocaleString()}`,
  });

  // 4. On-chain anchor for key B — found by the verifier from key_b alone.
  const anchor = await anchorCheck(j.key_b);
  results.push({
    label: ANCHOR_LABEL,
    ok: anchor.ok,
    detail: anchor.detail,
  });

  // 5. Leak scan (demo-only: needs this session's witness to know what to search for).
  if (state.master) {
    const needles = [hex(S.compressPoint(state.master.pubPoint)), hex(state.master.chain)];
    const leaked = needles.filter((n) => proofHex.includes(n) || JSON.stringify(input).includes(n));
    results.push({
      label: "No witness material in proof bytes (xpub pubkey / chain code absent)",
      ok: leaked.length === 0,
      detail: leaked.length ? `LEAKED ${leaked[0].slice(0, 30)}…` : "searched the full proof — parent pubkey + chain code not present",
    });
  }
  return results;
}

$("btnVerify").onclick = async () => {
  $("btnVerify").disabled = true;
  $("checkResults").innerHTML = "";
  $("verdict").className = "hidden";
  try {
    let results;
    const raw = $("verifyJson").value;
    let parsed = null;
    try { parsed = JSON.parse(raw); } catch { /* handled below */ }

    if (!isKnownPayload(parsed)) {
      results = [{ label: "Proof file is a supported zero-knowledge proof", ok: false,
        detail: "expected JSON with mode \"noir\" or \"groth16\" (see SPEC.md §6.2)" }];
    } else {
      results = await verifyReal(parsed);
    }

    results.forEach(pushCheck);
    const ok = results.every((r) => r.ok);
    const onlyAnchorMissing = !ok && results.filter((r) => !r.ok).every((r) => r.label === ANCHOR_LABEL);
    const verdict = $("verdict");
    verdict.className = ok ? "pass" : onlyAnchorMissing ? "partial" : "fail";
    const kind = modeLabel(parsed?.mode);
    verdict.textContent = ok
      ? `✓ LINK PROVEN · ${kind} — key A shares a wallet with on-chain key B. The verifier never saw the xpub or the paths.`
      : onlyAnchorMissing
        ? `◐ LINK PROVEN · ${kind} — but key B has no verified signet spend yet, so it isn't anchored on-chain.`
        : "✗ PROOF REJECTED — see failed checks above.";
    if (ok) for (const li of $("stepper").children) li.classList.add("done");
  } finally {
    $("btnVerify").disabled = false;
  }
};

// Restore the saved signet wallet, if any.
const savedSeed = localStorage.getItem(STORE.seed);
if (localStorage.getItem(STORE.pathA)) $("pathA").value = localStorage.getItem(STORE.pathA);
if (localStorage.getItem(STORE.pathB)) $("pathB").value = localStorage.getItem(STORE.pathB);
if (savedSeed && /^([0-9a-f]{2})+$/.test(savedSeed)) {
  loadWallet(new Uint8Array(savedSeed.match(/../g).map((x) => parseInt(x, 16)))).catch(console.error);
}

// Default session context + show backend info.
$("ctx").value = "audit-session-" + Math.random().toString(36).slice(2, 10);
setStep(1);
// ---- Startup: in-browser prover manifest, optional self-hosted server ----------------

function renderPill() {
  const t = threadCount();
  const wasm = manifest ? `In-browser ZK prover · ${t} thread${t > 1 ? "s" : ""}` : "In-browser prover unavailable";
  $("backendPill").className = "pill " + (manifest ? "pill-ok" : "pill-off");
  $("backendInfo").textContent = state.server ? `${wasm} · server prover online` : wasm;
  $("wasmEst").textContent = `WASM · ~${fmtDur(wasmEstimateSec())} here`;
}

fetch(CIRCUIT.manifest).then((r) => r.json()).then((m) => {
  manifest = m;
  $("backendPill").title = `circuit ${m.statement} · ${m.gates.toLocaleString()} gates (2^${m.gates_dyadic_log2}) · ` +
    `Noir ${m.noir} · bb.js ${m.bb_js} · vk sha256 ${m.vk_sha256}`;
}).catch(() => {}).finally(() => { renderPill(); setRealButtons(); });

// Static hosts (GitHub Pages) have no server API; don't probe there.
(location.hostname.endsWith("github.io") ? Promise.reject() : fetch("api/info").then((r) => r.json())).then((i) => {
  if (!i.vk_hex) return;
  state.server = true;
  for (const el of document.querySelectorAll(".server-only")) el.classList.remove("hidden");
  $("serverNote").classList.add("hidden");
  renderPill();
  setRealButtons();
}).catch(() => {});

// Load a proof file someone sent you.
$("proofFile").onchange = async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const text = await file.text();
  e.target.value = "";
  try {
    loadIntoVerifier(text, modeLabel(JSON.parse(text).mode));
  } catch {
    loadIntoVerifier(text, "unreadable file");
  }
};

// A finished proof survives a reload (useful for long in-browser runs).
const lastProof = localStorage.getItem(STORE.lastProof);
if (lastProof) {
  try {
    const p = JSON.parse(lastProof);
    $("verifyJson").value = lastProof;
    $("proofMode").textContent = modeLabel(p.mode) + " (restored)";
    $("btnVerify").disabled = $("btnTamper").disabled = false;
  } catch { /* ignore */ }
}

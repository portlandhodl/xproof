// zk-browser.js — main-thread API for the in-browser (WASM) xproof prover/verifier.
// Built by Vite into /vendor/zk/ and imported by js/app.js.

let worker, nextId = 0;
const pending = new Map();

function getWorker() {
  if (!worker) {
    worker = new Worker(new URL("./prover.worker.js", import.meta.url), { type: "module" });
    worker.onmessage = ({ data }) => {
      const p = pending.get(data.id);
      if (!p) return;
      if (data.type === "progress") return p.onProgress?.(data.stage, data.detail);
      pending.delete(data.id);
      data.type === "done" ? p.resolve(data.result) : p.reject(new Error(data.error));
    };
    worker.onerror = (e) => {
      e.preventDefault?.();
      const why = e.message ? `${e.message}${e.filename ? ` (${e.filename.split("/").pop()}:${e.lineno})` : ""}`
        : "prover worker crashed — most likely the browser ran out of memory";
      for (const p of pending.values()) p.reject(new Error(why));
      pending.clear();
      worker = null;
    };
  }
  return worker;
}

function call(msg, onProgress) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject, onProgress });
    getWorker().postMessage({ id, ...msg });
  });
}

/** Threads usable by Barretenberg: >1 needs SharedArrayBuffer (cross-origin isolation). */
export const threadCount = () =>
  globalThis.crossOriginIsolated ? Math.min(navigator.hardwareConcurrency || 4, 16) : 1;

// URLs are resolved against the page, not the worker script.
const abs = (u) => new URL(u, location.href).href;

// srsSize: number of BN254 CRS points to download — the circuit's dyadic size (2^log2).
export const proveInBrowser = ({ circuitUrl, inputs, srsLog2 = 21, onProgress }) =>
  call({ op: "prove", circuitUrl: abs(circuitUrl), inputs, threads: threadCount(), srsSize: 2 ** srsLog2 }, onProgress);

export const verifyInBrowser = ({ vkUrl, proof, publicInputs, onProgress }) =>
  call({ op: "verify", vkUrl: abs(vkUrl), proof, publicInputs, threads: threadCount(), srsSize: 2 ** 17 }, onProgress); // verifier needs only a minimal CRS (CDN chunk = 2^17 points)

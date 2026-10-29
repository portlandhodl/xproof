let s, u = 0;
const t = /* @__PURE__ */ new Map();
function w() {
  return s || (s = new Worker(new URL(
    /* @vite-ignore */
    "" + new URL("assets/prover.worker-MYwKIlQu.js", import.meta.url).href,
    import.meta.url
  ), { type: "module" }), s.onmessage = ({ data: e }) => {
    const r = t.get(e.id);
    if (r) {
      if (e.type === "progress") return r.onProgress?.(e.stage, e.detail);
      t.delete(e.id), e.type === "done" ? r.resolve(e.result) : r.reject(new Error(e.error));
    }
  }, s.onerror = (e) => {
    e.preventDefault?.();
    const r = e.message ? `${e.message}${e.filename ? ` (${e.filename.split("/").pop()}:${e.lineno})` : ""}` : "prover worker crashed — most likely the browser ran out of memory";
    for (const o of t.values()) o.reject(new Error(r));
    t.clear(), s = null;
  }), s;
}
function i(e, r) {
  const o = ++u;
  return new Promise((n, p) => {
    t.set(o, { resolve: n, reject: p, onProgress: r }), w().postMessage({ id: o, ...e });
  });
}
const l = () => globalThis.crossOriginIsolated ? Math.min(navigator.hardwareConcurrency || 4, 16) : 1, c = (e) => new URL(e, location.href).href, a = ({ circuitUrl: e, inputs: r, srsLog2: o = 21, onProgress: n }) => i({ op: "prove", circuitUrl: c(e), inputs: r, threads: l(), srsSize: 2 ** o }, n), f = ({ vkUrl: e, proof: r, publicInputs: o, onProgress: n }) => i({ op: "verify", vkUrl: c(e), proof: r, publicInputs: o, threads: l(), srsSize: 2 ** 17 }, n);
export {
  a as proveInBrowser,
  l as threadCount,
  f as verifyInBrowser
};

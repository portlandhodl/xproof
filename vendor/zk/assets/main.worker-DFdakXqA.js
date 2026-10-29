/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
const C = Symbol("Comlink.proxy"), D = Symbol("Comlink.endpoint"), z = Symbol("Comlink.releaseProxy"), M = Symbol("Comlink.finalizer"), d = Symbol("Comlink.thrown"), T = (t) => typeof t == "object" && t !== null || typeof t == "function", v = {
  canHandle: (t) => T(t) && t[C],
  serialize(t) {
    const { port1: e, port2: r } = new MessageChannel();
    return E(t, e), [r, [r]];
  },
  deserialize(t) {
    return t.start(), O(t);
  }
}, H = {
  canHandle: (t) => T(t) && d in t,
  serialize({ value: t }) {
    let e;
    return t instanceof Error ? e = {
      isError: !0,
      value: {
        message: t.message,
        name: t.name,
        stack: t.stack
      }
    } : e = { isError: !1, value: t }, [e, []];
  },
  deserialize(t) {
    throw t.isError ? Object.assign(new Error(t.value.message), t.value) : t.value;
  }
}, _ = /* @__PURE__ */ new Map([
  ["proxy", v],
  ["throw", H]
]);
function U(t, e) {
  for (const r of t)
    if (e === r || r === "*" || r instanceof RegExp && r.test(e))
      return !0;
  return !1;
}
function E(t, e = globalThis, r = ["*"]) {
  e.addEventListener("message", function s(n) {
    if (!n || !n.data)
      return;
    if (!U(r, n.origin)) {
      console.warn(`Invalid origin '${n.origin}' for comlink proxy`);
      return;
    }
    const { id: o, type: a, path: i } = Object.assign({ path: [] }, n.data), h = (n.data.argumentList || []).map(f);
    let c;
    try {
      const u = i.slice(0, -1).reduce((g, m) => g[m], t), l = i.reduce((g, m) => g[m], t);
      switch (a) {
        case "GET":
          c = l;
          break;
        case "SET":
          u[i.slice(-1)[0]] = f(n.data.value), c = !0;
          break;
        case "APPLY":
          c = l.apply(u, h);
          break;
        case "CONSTRUCT":
          {
            const g = new l(...h);
            c = G(g);
          }
          break;
        case "ENDPOINT":
          {
            const { port1: g, port2: m } = new MessageChannel();
            E(t, m), c = B(g, [g]);
          }
          break;
        case "RELEASE":
          c = void 0;
          break;
        default:
          return;
      }
    } catch (u) {
      c = { value: u, [d]: 0 };
    }
    Promise.resolve(c).catch((u) => ({ value: u, [d]: 0 })).then((u) => {
      const [l, g] = S(u);
      e.postMessage(Object.assign(Object.assign({}, l), { id: o }), g), a === "RELEASE" && (e.removeEventListener("message", s), x(e), M in t && typeof t[M] == "function" && t[M]());
    }).catch((u) => {
      const [l, g] = S({
        value: new TypeError("Unserializable return value"),
        [d]: 0
      });
      e.postMessage(Object.assign(Object.assign({}, l), { id: o }), g);
    });
  }), e.start && e.start();
}
function $(t) {
  return t.constructor.name === "MessagePort";
}
function x(t) {
  $(t) && t.close();
}
function O(t, e) {
  const r = /* @__PURE__ */ new Map();
  return t.addEventListener("message", function(n) {
    const { data: o } = n;
    if (!o || !o.id)
      return;
    const a = r.get(o.id);
    if (a)
      try {
        a(o);
      } finally {
        r.delete(o.id);
      }
  }), A(t, r, [], e);
}
function p(t) {
  if (t)
    throw new Error("Proxy has been released and is not useable");
}
function I(t) {
  return y(t, /* @__PURE__ */ new Map(), {
    type: "RELEASE"
  }).then(() => {
    x(t);
  });
}
const w = /* @__PURE__ */ new WeakMap(), b = "FinalizationRegistry" in globalThis && new FinalizationRegistry((t) => {
  const e = (w.get(t) || 0) - 1;
  w.set(t, e), e === 0 && I(t);
});
function j(t, e) {
  const r = (w.get(e) || 0) + 1;
  w.set(e, r), b && b.register(t, e, t);
}
function V(t) {
  b && b.unregister(t);
}
function A(t, e, r = [], s = function() {
}) {
  let n = !1;
  const o = new Proxy(s, {
    get(a, i) {
      if (p(n), i === z)
        return () => {
          V(o), I(t), e.clear(), n = !0;
        };
      if (i === "then") {
        if (r.length === 0)
          return { then: () => o };
        const h = y(t, e, {
          type: "GET",
          path: r.map((c) => c.toString())
        }).then(f);
        return h.then.bind(h);
      }
      return A(t, e, [...r, i]);
    },
    set(a, i, h) {
      p(n);
      const [c, u] = S(h);
      return y(t, e, {
        type: "SET",
        path: [...r, i].map((l) => l.toString()),
        value: c
      }, u).then(f);
    },
    apply(a, i, h) {
      p(n);
      const c = r[r.length - 1];
      if (c === D)
        return y(t, e, {
          type: "ENDPOINT"
        }).then(f);
      if (c === "bind")
        return A(t, e, r.slice(0, -1));
      const [u, l] = k(h);
      return y(t, e, {
        type: "APPLY",
        path: r.map((g) => g.toString()),
        argumentList: u
      }, l).then(f);
    },
    construct(a, i) {
      p(n);
      const [h, c] = k(i);
      return y(t, e, {
        type: "CONSTRUCT",
        path: r.map((u) => u.toString()),
        argumentList: h
      }, c).then(f);
    }
  });
  return j(o, t), o;
}
function F(t) {
  return Array.prototype.concat.apply([], t);
}
function k(t) {
  const e = t.map(S);
  return [e.map((r) => r[0]), F(e.map((r) => r[1]))];
}
const R = /* @__PURE__ */ new WeakMap();
function B(t, e) {
  return R.set(t, e), t;
}
function G(t) {
  return Object.assign(t, { [C]: !0 });
}
function S(t) {
  for (const [e, r] of _)
    if (r.canHandle(t)) {
      const [s, n] = r.serialize(t);
      return [
        {
          type: "HANDLER",
          name: e,
          value: s
        },
        n
      ];
    }
  return [
    {
      type: "RAW",
      value: t
    },
    R.get(t) || []
  ];
}
function f(t) {
  switch (t.type) {
    case "HANDLER":
      return _.get(t.name).deserialize(t.value);
    case "RAW":
      return t.value;
  }
}
function y(t, e, r, s) {
  return new Promise((n) => {
    const o = N();
    e.set(o, n), t.start && t.start(), t.postMessage(Object.assign({ id: o }, r), s);
  });
}
function N() {
  return new Array(4).fill(0).map(() => Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString(16)).join("-");
}
function Z() {
  return typeof SharedArrayBuffer < "u" && (typeof window < "u" ? window : globalThis).crossOriginIsolated;
}
function K(t) {
  return O(t);
}
function X() {
  return navigator.hardwareConcurrency;
}
const Y = { ready: !0 };
function q(t, e) {
  t.addEventListener("message", function r(s) {
    s.data && s.data.ready === !0 && (t.removeEventListener("message", r), e());
  });
}
async function J() {
  const t = new Worker(new URL(
    /* @vite-ignore */
    "" + new URL("thread.worker-C_jf2gkW.js", import.meta.url).href,
    import.meta.url
  ), { type: "module" });
  return await new Promise((e) => q(t, e)), t;
}
const Q = (t) => {
  const r = (() => {
    if (typeof window < "u" && window.crypto)
      return window.crypto;
    if (typeof globalThis < "u" && globalThis.crypto)
      return globalThis.crypto;
  })();
  if (!r)
    throw new Error("randomBytes UnsupportedEnvironment");
  const s = new Uint8Array(t), n = 65536;
  if (t > n)
    for (let o = 0; o < t; o += n)
      r.getRandomValues(s.subarray(o, o + n));
  else
    r.getRandomValues(s);
  return s;
};
class tt {
  memory;
  instance;
  logger = () => {
  };
  getImportObj(e) {
    return {
      // We need to implement a part of the wasi api:
      // https://github.com/WebAssembly/WASI/blob/main/phases/snapshot/docs.md
      // We literally only need to support random_get, everything else is noop implementated in barretenberg.wasm.
      wasi_snapshot_preview1: {
        random_get: (s, n) => {
          s = s >>> 0;
          const o = Q(n);
          this.getMemory().set(o, s);
        },
        clock_time_get: (s, n, o) => {
          o = o >>> 0;
          const a = BigInt((/* @__PURE__ */ new Date()).getTime()) * 1000000n;
          new DataView(this.getMemory().buffer).setBigUint64(o, a, !0);
        },
        proc_exit: () => {
          throw this.logger("PANIC: proc_exit was called."), new Error();
        }
      },
      // These are functions implementations for imports we've defined are needed.
      // The native C++ build defines these in a module called "env". We must implement TypeScript versions here.
      env: {
        /**
         * The 'info' call we use for logging in C++, calls this under the hood.
         * The native code will just print to std:err (to avoid std::cout which is used for IPC).
         * Here we just emit the log line for the client to decide what to do with.
         */
        logstr: (s) => {
          const n = this.stringFromAddress(s), o = this.getMemory(), a = `${n} (mem: ${(o.length / (1024 * 1024)).toFixed(2)}MiB)`;
          this.logger(a);
        },
        throw_or_abort_impl: (s) => {
          const n = this.stringFromAddress(s);
          throw new Error(n);
        },
        memory: e
      }
    };
  }
  exports() {
    return this.instance.exports;
  }
  /**
   * When returning values from the WASM, use >>> operator to convert signed representation to unsigned representation.
   */
  call(e, ...r) {
    if (!this.exports()[e])
      throw new Error(`WASM function ${e} not found.`);
    try {
      return this.exports()[e](...r) >>> 0;
    } catch (s) {
      const n = `WASM function ${e} aborted, error: ${s}`;
      throw this.logger(n), this.logger(s.stack), s;
    }
  }
  memSize() {
    return this.getMemory().length;
  }
  /**
   * Returns a copy of the data, not a view.
   */
  getMemorySlice(e, r) {
    return this.getMemory().subarray(e, r).slice();
  }
  writeMemory(e, r) {
    this.getMemory().set(r, e);
  }
  getMemory() {
    return new Uint8Array(this.memory.buffer);
  }
  // PRIVATE METHODS
  stringFromAddress(e) {
    e = e >>> 0;
    const r = this.getMemory();
    let s = e;
    for (; r[s] !== 0; ++s)
      ;
    return new TextDecoder("ascii").decode(r.slice(e, s));
  }
}
class et {
  wasm;
  allocs = [];
  inScratchPtr = 0;
  // Next input starts here, grows UP
  outScratchPtr = 1024;
  // Next output ends here, grows DOWN
  constructor(e) {
    this.wasm = e;
  }
  getInputs(e) {
    return e.map((r) => {
      if (typeof r == "object") {
        const s = r.length;
        if (this.inScratchPtr + s <= this.outScratchPtr) {
          const n = this.inScratchPtr;
          return this.inScratchPtr += s, this.wasm.writeMemory(n, r), n;
        } else {
          const n = this.wasm.call("bbmalloc", s);
          return this.wasm.writeMemory(n, r), this.allocs.push(n), n;
        }
      } else
        return r;
    });
  }
  getOutputPtrs(e) {
    return e.map((r) => {
      const s = r || 4;
      if (this.inScratchPtr + s <= this.outScratchPtr)
        return this.outScratchPtr -= s, this.outScratchPtr;
      {
        const n = this.wasm.call("bbmalloc", s);
        return this.allocs.push(n), n;
      }
    });
  }
  addOutputPtr(e) {
    e >= 1024 && this.allocs.push(e);
  }
  freeAll() {
    for (const e of this.allocs)
      this.wasm.call("bbfree", e);
  }
}
class P extends tt {
  static MAX_THREADS = 32;
  workers = [];
  remoteWasms = [];
  nextWorker = 0;
  nextThreadId = 1;
  useCustomLogger = !1;
  // Pre-allocated scratch buffers for msgpack I/O to avoid malloc/free overhead
  msgpackInputScratch = 0;
  // 8MB input buffer
  msgpackOutputScratch = 0;
  // 8MB output buffer
  MSGPACK_SCRATCH_SIZE = 1024 * 1024 * 8;
  // 8MB
  getNumThreads() {
    return this.workers.length + 1;
  }
  /**
   * Init as main thread. Spawn child threads.
   */
  async init(e, r = Math.min(X(), P.MAX_THREADS), s, n = 37, o = this.getDefaultMaximumMemoryPages(), a = !1) {
    this.useCustomLogger = s !== void 0, this.logger = s ?? (() => {
    });
    const i = n * 2 ** 16 / (1024 * 1024), h = o * 2 ** 16 / (1024 * 1024), c = Z();
    this.logger(`Initializing bb wasm: initial memory ${n} pages ${i}MiB; max memory: ${o} pages, ${h}MiB; threads: ${r}; shared memory: ${c}`), this.memory = new WebAssembly.Memory({ initial: n, maximum: o, shared: c });
    const u = await WebAssembly.instantiate(e, this.getImportObj(this.memory));
    if (this.instance = u, this.call("_initialize"), this.msgpackInputScratch = this.call("bbmalloc", this.MSGPACK_SCRATCH_SIZE), this.msgpackOutputScratch = this.call("bbmalloc", this.MSGPACK_SCRATCH_SIZE), this.logger(`Allocated msgpack scratch buffers: input @ ${this.msgpackInputScratch}, output @ ${this.msgpackOutputScratch} (${this.MSGPACK_SCRATCH_SIZE} bytes each)`), r > 1 && (this.logger(`Creating ${r} worker threads`), this.workers = await Promise.all(Array.from({ length: r - 1 }).map(J)), this.useCustomLogger && this.workers.forEach((l) => this.setupWorkerLogForwarding(l)), this.remoteWasms = await Promise.all(this.workers.map(K)), await Promise.all(this.remoteWasms.map((l) => l.initThread(e, this.memory, this.useCustomLogger))), a))
      for (const l of this.workers)
        l.unref();
  }
  getDefaultMaximumMemoryPages() {
    return typeof self < "u" && typeof self.navigator < "u" && /iPad|iPhone/.test(self.navigator.userAgent) ? 2 ** 14 : 2 ** 16;
  }
  /**
   * Set up forwarding of log messages from worker threads to our logger.
   * Workers post messages with { type: 'log', msg: string } which we intercept here.
   */
  setupWorkerLogForwarding(e) {
    const r = (s) => {
      s && typeof s == "object" && "type" in s && s.type === "log" && "msg" in s && this.logger(s.msg);
    };
    "on" in e && typeof e.on == "function" ? e.on("message", r) : "addEventListener" in e && e.addEventListener("message", (s) => {
      r(s.data);
    });
  }
  /**
   * Called on main thread. Signals child threads to gracefully exit.
   */
  async destroy() {
    await Promise.all(this.workers.map((e) => e.terminate()));
  }
  getImportObj(e) {
    const r = super.getImportObj(e);
    return {
      ...r,
      wasi: {
        "thread-spawn": (s) => {
          s = s >>> 0;
          const n = this.nextThreadId++, o = this.nextWorker++ % this.remoteWasms.length;
          return this.remoteWasms[o].call("wasi_thread_start", n, s).catch(this.logger), n;
        }
      },
      env: {
        ...r.env,
        env_hardware_concurrency: () => this.remoteWasms.length + 1
      }
    };
  }
  callWasmExport(e, r, s) {
    const n = new et(this), o = n.getInputs(r), a = n.getOutputPtrs(s);
    this.call(e, ...o, ...a);
    const i = this.getOutputArgs(s, a, n);
    return n.freeAll(), i;
  }
  getOutputArgs(e, r, s) {
    return e.map((n, o) => {
      if (n)
        return this.getMemorySlice(r[o], r[o] + n);
      const a = this.getMemorySlice(r[o], r[o] + 4), i = new DataView(a.buffer, a.byteOffset, a.byteLength).getUint32(0, !0);
      s.addOutputPtr(i);
      const h = this.getMemorySlice(i, i + 4), c = new DataView(h.buffer, h.byteOffset, h.byteLength).getUint32(0, !1);
      return this.getMemorySlice(i + 4, i + 4 + c);
    });
  }
  cbindCall(e, r) {
    const s = r.length > this.MSGPACK_SCRATCH_SIZE;
    let n;
    s ? n = this.call("bbmalloc", r.length) : n = this.msgpackInputScratch, this.writeMemory(n, r);
    const o = 8, a = this.msgpackOutputScratch, i = this.msgpackOutputScratch + 4, h = this.msgpackOutputScratch + o, c = this.MSGPACK_SCRATCH_SIZE - o;
    let u = this.getMemory(), l = new DataView(u.buffer);
    l.setUint32(a, h, !0), l.setUint32(i, c, !0), this.call(e, n, r.length, a, i), s && this.call("bbfree", n), u = this.getMemory(), l = new DataView(u.buffer);
    const g = l.getUint32(a, !0), m = l.getUint32(i, !0), W = g === h, L = this.getMemorySlice(g, g + m);
    return W || this.call("bbfree", g), L;
  }
}
E(new P());
postMessage(Y);

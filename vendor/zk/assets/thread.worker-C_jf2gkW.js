/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
const k = Symbol("Comlink.proxy"), I = Symbol("Comlink.endpoint"), W = Symbol("Comlink.releaseProxy"), M = Symbol("Comlink.finalizer"), w = Symbol("Comlink.thrown"), P = (e) => typeof e == "object" && e !== null || typeof e == "function", z = {
  canHandle: (e) => P(e) && e[k],
  serialize(e) {
    const { port1: t, port2: r } = new MessageChannel();
    return A(e, t), [r, [r]];
  },
  deserialize(e) {
    return e.start(), V(e);
  }
}, N = {
  canHandle: (e) => P(e) && w in e,
  serialize({ value: e }) {
    let t;
    return e instanceof Error ? t = {
      isError: !0,
      value: {
        message: e.message,
        name: e.name,
        stack: e.stack
      }
    } : t = { isError: !1, value: e }, [t, []];
  },
  deserialize(e) {
    throw e.isError ? Object.assign(new Error(e.value.message), e.value) : e.value;
  }
}, O = /* @__PURE__ */ new Map([
  ["proxy", z],
  ["throw", N]
]);
function j(e, t) {
  for (const r of e)
    if (t === r || r === "*" || r instanceof RegExp && r.test(t))
      return !0;
  return !1;
}
function A(e, t = globalThis, r = ["*"]) {
  t.addEventListener("message", function s(n) {
    if (!n || !n.data)
      return;
    if (!j(r, n.origin)) {
      console.warn(`Invalid origin '${n.origin}' for comlink proxy`);
      return;
    }
    const { id: o, type: c, path: u } = Object.assign({ path: [] }, n.data), g = (n.data.argumentList || []).map(m);
    let a;
    try {
      const i = u.slice(0, -1).reduce((l, h) => l[h], e), f = u.reduce((l, h) => l[h], e);
      switch (c) {
        case "GET":
          a = f;
          break;
        case "SET":
          i[u.slice(-1)[0]] = m(n.data.value), a = !0;
          break;
        case "APPLY":
          a = f.apply(i, g);
          break;
        case "CONSTRUCT":
          {
            const l = new f(...g);
            a = v(l);
          }
          break;
        case "ENDPOINT":
          {
            const { port1: l, port2: h } = new MessageChannel();
            A(e, h), a = U(l, [l]);
          }
          break;
        case "RELEASE":
          a = void 0;
          break;
        default:
          return;
      }
    } catch (i) {
      a = { value: i, [w]: 0 };
    }
    Promise.resolve(a).catch((i) => ({ value: i, [w]: 0 })).then((i) => {
      const [f, l] = E(i);
      t.postMessage(Object.assign(Object.assign({}, f), { id: o }), l), c === "RELEASE" && (t.removeEventListener("message", s), _(t), M in e && typeof e[M] == "function" && e[M]());
    }).catch((i) => {
      const [f, l] = E({
        value: new TypeError("Unserializable return value"),
        [w]: 0
      });
      t.postMessage(Object.assign(Object.assign({}, f), { id: o }), l);
    });
  }), t.start && t.start();
}
function D(e) {
  return e.constructor.name === "MessagePort";
}
function _(e) {
  D(e) && e.close();
}
function V(e, t) {
  const r = /* @__PURE__ */ new Map();
  return e.addEventListener("message", function(n) {
    const { data: o } = n;
    if (!o || !o.id)
      return;
    const c = r.get(o.id);
    if (c)
      try {
        c(o);
      } finally {
        r.delete(o.id);
      }
  }), x(e, r, [], t);
}
function d(e) {
  if (e)
    throw new Error("Proxy has been released and is not useable");
}
function C(e) {
  return y(e, /* @__PURE__ */ new Map(), {
    type: "RELEASE"
  }).then(() => {
    _(e);
  });
}
const p = /* @__PURE__ */ new WeakMap(), b = "FinalizationRegistry" in globalThis && new FinalizationRegistry((e) => {
  const t = (p.get(e) || 0) - 1;
  p.set(e, t), t === 0 && C(e);
});
function B(e, t) {
  const r = (p.get(t) || 0) + 1;
  p.set(t, r), b && b.register(e, t, e);
}
function F(e) {
  b && b.unregister(e);
}
function x(e, t, r = [], s = function() {
}) {
  let n = !1;
  const o = new Proxy(s, {
    get(c, u) {
      if (d(n), u === W)
        return () => {
          F(o), C(e), t.clear(), n = !0;
        };
      if (u === "then") {
        if (r.length === 0)
          return { then: () => o };
        const g = y(e, t, {
          type: "GET",
          path: r.map((a) => a.toString())
        }).then(m);
        return g.then.bind(g);
      }
      return x(e, t, [...r, u]);
    },
    set(c, u, g) {
      d(n);
      const [a, i] = E(g);
      return y(e, t, {
        type: "SET",
        path: [...r, u].map((f) => f.toString()),
        value: a
      }, i).then(m);
    },
    apply(c, u, g) {
      d(n);
      const a = r[r.length - 1];
      if (a === I)
        return y(e, t, {
          type: "ENDPOINT"
        }).then(m);
      if (a === "bind")
        return x(e, t, r.slice(0, -1));
      const [i, f] = S(g);
      return y(e, t, {
        type: "APPLY",
        path: r.map((l) => l.toString()),
        argumentList: i
      }, f).then(m);
    },
    construct(c, u) {
      d(n);
      const [g, a] = S(u);
      return y(e, t, {
        type: "CONSTRUCT",
        path: r.map((i) => i.toString()),
        argumentList: g
      }, a).then(m);
    }
  });
  return B(o, e), o;
}
function L(e) {
  return Array.prototype.concat.apply([], e);
}
function S(e) {
  const t = e.map(E);
  return [t.map((r) => r[0]), L(t.map((r) => r[1]))];
}
const R = /* @__PURE__ */ new WeakMap();
function U(e, t) {
  return R.set(e, t), e;
}
function v(e) {
  return Object.assign(e, { [k]: !0 });
}
function E(e) {
  for (const [t, r] of O)
    if (r.canHandle(e)) {
      const [s, n] = r.serialize(e);
      return [
        {
          type: "HANDLER",
          name: t,
          value: s
        },
        n
      ];
    }
  return [
    {
      type: "RAW",
      value: e
    },
    R.get(e) || []
  ];
}
function m(e) {
  switch (e.type) {
    case "HANDLER":
      return O.get(e.name).deserialize(e.value);
    case "RAW":
      return e.value;
  }
}
function y(e, t, r, s) {
  return new Promise((n) => {
    const o = H();
    t.set(o, n), e.start && e.start(), e.postMessage(Object.assign({ id: o }, r), s);
  });
}
function H() {
  return new Array(4).fill(0).map(() => Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString(16)).join("-");
}
function $(e) {
  return e ? (t) => {
    postMessage({ type: "log", msg: t });
  } : console.log;
}
function T() {
  self.close();
}
const G = { ready: !0 }, Y = (e) => {
  const r = (() => {
    if (typeof window < "u" && window.crypto)
      return window.crypto;
    if (typeof globalThis < "u" && globalThis.crypto)
      return globalThis.crypto;
  })();
  if (!r)
    throw new Error("randomBytes UnsupportedEnvironment");
  const s = new Uint8Array(e), n = 65536;
  if (e > n)
    for (let o = 0; o < e; o += n)
      r.getRandomValues(s.subarray(o, o + n));
  else
    r.getRandomValues(s);
  return s;
};
class X {
  memory;
  instance;
  logger = () => {
  };
  getImportObj(t) {
    return {
      // We need to implement a part of the wasi api:
      // https://github.com/WebAssembly/WASI/blob/main/phases/snapshot/docs.md
      // We literally only need to support random_get, everything else is noop implementated in barretenberg.wasm.
      wasi_snapshot_preview1: {
        random_get: (s, n) => {
          s = s >>> 0;
          const o = Y(n);
          this.getMemory().set(o, s);
        },
        clock_time_get: (s, n, o) => {
          o = o >>> 0;
          const c = BigInt((/* @__PURE__ */ new Date()).getTime()) * 1000000n;
          new DataView(this.getMemory().buffer).setBigUint64(o, c, !0);
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
          const n = this.stringFromAddress(s), o = this.getMemory(), c = `${n} (mem: ${(o.length / (1024 * 1024)).toFixed(2)}MiB)`;
          this.logger(c);
        },
        throw_or_abort_impl: (s) => {
          const n = this.stringFromAddress(s);
          throw new Error(n);
        },
        memory: t
      }
    };
  }
  exports() {
    return this.instance.exports;
  }
  /**
   * When returning values from the WASM, use >>> operator to convert signed representation to unsigned representation.
   */
  call(t, ...r) {
    if (!this.exports()[t])
      throw new Error(`WASM function ${t} not found.`);
    try {
      return this.exports()[t](...r) >>> 0;
    } catch (s) {
      const n = `WASM function ${t} aborted, error: ${s}`;
      throw this.logger(n), this.logger(s.stack), s;
    }
  }
  memSize() {
    return this.getMemory().length;
  }
  /**
   * Returns a copy of the data, not a view.
   */
  getMemorySlice(t, r) {
    return this.getMemory().subarray(t, r).slice();
  }
  writeMemory(t, r) {
    this.getMemory().set(r, t);
  }
  getMemory() {
    return new Uint8Array(this.memory.buffer);
  }
  // PRIVATE METHODS
  stringFromAddress(t) {
    t = t >>> 0;
    const r = this.getMemory();
    let s = t;
    for (; r[s] !== 0; ++s)
      ;
    return new TextDecoder("ascii").decode(r.slice(t, s));
  }
}
class q extends X {
  /**
   * Init as worker thread.
   * @param useCustomLogger - If true, logs will be posted back to main thread for custom logger routing
   */
  async initThread(t, r, s = !1) {
    this.logger = $(s) || this.logger, this.memory = r, this.instance = await WebAssembly.instantiate(t, this.getImportObj(this.memory));
  }
  destroy() {
    T();
  }
  getImportObj(t) {
    const r = super.getImportObj(t);
    return {
      ...r,
      wasi: {
        "thread-spawn": () => {
          this.logger("PANIC: threads cannot spawn threads!"), this.logger(new Error().stack), T();
        }
      },
      // These are functions implementations for imports we've defined are needed.
      // The native C++ build defines these in a module called "env". We must implement TypeScript versions here.
      env: {
        ...r.env,
        env_hardware_concurrency: () => 1
      }
    };
  }
}
A(new q());
postMessage(G);

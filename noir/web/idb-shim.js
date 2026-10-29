// idb-shim.js — aliased for 'idb-keyval' inside the browser bundle (see vite.config.js).
// bb.js caches the decompressed CRS in IndexedDB as one value; for our 2^21 circuit that is
// 128 MiB, above Chromium's per-value limit (~127 MiB), and the failed write aborts proving.
// Cache writes are best-effort here: on failure the CRS is simply downloaded again next time.
import { get as idbGet, set as idbSet } from "../node_modules/idb-keyval/dist/index.js";

export const get = (key) => idbGet(key).catch(() => undefined);
export async function set(key, value) {
  try {
    await idbSet(key, value);
  } catch (e) {
    console.warn(`[xproof] not caching ${key} in IndexedDB: ${e?.message || e}`);
  }
}

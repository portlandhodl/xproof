// Builds the browser prover bundle into ../../vendor/zk (served as static files).
import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  base: "./", // relative asset/worker URLs: works under any subpath (e.g. GitHub Pages)
  build: {
    outDir: fileURLToPath(new URL("../../vendor/zk", import.meta.url)),
    emptyOutDir: true,
    target: "es2022",
    assetsInlineLimit: 0,
    lib: { entry: "zk-browser.js", formats: ["es"], fileName: () => "zk-browser.js" },
  },
  resolve: { alias: { "idb-keyval": fileURLToPath(new URL("idb-shim.js", import.meta.url)) } },
  worker: { format: "es" },
});

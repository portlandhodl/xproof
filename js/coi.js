// coi.js — registers coi-sw.js and reloads once so the page becomes cross-origin isolated
// (needed for multi-threaded WASM proving). Classic script: must run before app modules.
(() => {
  if (window.crossOriginIsolated || !window.isSecureContext || !("serviceWorker" in navigator)) return;
  const KEY = "xproof.coi-reloaded";
  navigator.serviceWorker.register(new URL("../coi-sw.js", document.currentScript.src)).then((reg) => {
    const reloadOnce = () => {
      if (sessionStorage.getItem(KEY)) return; // isolation unavailable (e.g. private mode) — stay single-threaded
      sessionStorage.setItem(KEY, "1");
      location.reload();
    };
    if (reg.active && !navigator.serviceWorker.controller) reloadOnce();
    navigator.serviceWorker.addEventListener("controllerchange", reloadOnce);
  }).catch(() => {});
})();

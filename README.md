# xproof

Prove that two Bitcoin keys came from the same wallet (BIP32 xpub), at any relationship
(`m/0/1` and `m/0/2`, `m/0/1` and `m/1/3`, `m/0` and `m/0/5/2`, …), **without revealing the
xpub, its chain code, or the derivation paths**. Only the two keys become public.

**Live demo:** https://portlandhodl.github.io/xproof/. It runs entirely in your browser, on signet.

- 📄 Formal specification: [SPEC.md](SPEC.md)
- 🔐 Zero-knowledge proofs are generated **in the browser** (Noir → UltraHonk, WebAssembly)
- 🖥️ An optional **self-hosted server** adds SP1 zkVM provers (STARK and Groth16)

## How it works (short version)

BIP32 derives every child key from the xpub with HMAC-SHA512 and elliptic-curve addition.
Anyone who has the xpub can link *every* key in the wallet, so you can't just show it to prove
that two keys belong together. xproof runs the derivation inside a zero-knowledge proof
instead. The proof states "I know an xpub that derives both of these keys" and reveals nothing
else.

On the page, end to end:

1. **Wallet:** generate a signet wallet (kept in your browser) and pick two paths.
2. **Anchor:** deposit signet sats to key B's address and spend them. The spend publishes key
   B's signature on-chain.
3. **Prove:** generate a ZK proof that keys A and B share an xpub.
4. **Verify:** the verifier checks the proof, the session context, and the on-chain spend
   (it recomputes the BIP143 sighash and checks the signature itself). Proofs can be downloaded
   and loaded by a different person in a different browser.

## Provers

| | In-browser (default) | Server: Groth16 | Server: STARK |
|---|---|---|---|
| Where it runs | your browser tab (WASM) | `xproof-host` | `xproof-host` |
| Proving system | Noir + Barretenberg UltraHonk | SP1 zkVM → Groth16 | SP1 zkVM compressed STARK |
| Zero-knowledge | ✅ | ✅ | ❌ (debug only) |
| Proof size | 10.7 KB | 356 B | ~1.3 MB |
| Max path depth | 3 | 16 | 16 |
| Setup | universal (Aztec Ignition SRS) | SP1 Groth16 setup | transparent |
| On-chain verifiable | ✅ (keccak transcript) | ✅ | — |

Both proving stacks implement the same relation and public values (SPEC §3). Tests check
that they derive identical keys.

### Performance

Measured in headless Chromium on an 88-core server (one proof = 1.76M gates, 2^21):

| Setup | Time |
|---|---|
| In-browser, 16 threads | **~65 s** (witness 6 s + proving 49 s) |
| In-browser, 1 thread (no cross-origin isolation) | **~4.6 min** |
| In-browser verification | < 1 s |
| Server, SP1 STARK | ~85 s |
| Server, SP1 → Groth16 | ~3.7 min (first run also downloads ~8 GB of circuit files) |

A typical laptop should land between those browser numbers; phones may take several times
longer or run out of memory (untested). Each in-browser proof downloads the circuit (~4 MB
gzipped) and 64 MB of public setup parameters from Aztec's CDN.

Multi-threading needs `SharedArrayBuffer`, which needs cross-origin isolation. GitHub Pages
can't set the required headers, so `coi-sw.js` (a small service worker) adds them. Without it
(private windows, or non-HTTPS LAN addresses) the prover falls back to a single thread.

## Repository layout

```
index.html, styles.css, js/   the web app (no framework)
  js/app.js                   UI + protocol flow
  js/bip32.js, secp256k1.js   BIP32 + secp256k1 (BigInt, validated against BIP32 test vector 1)
  js/btc.js                   bech32, P2WPKH tx building/signing, BIP143, Esplora client
  js/noir-witness.js          builds the Noir circuit witness + hints
  js/zk.js                    the "simulated" mode (teaching aid, not a proof)
coi-sw.js, js/coi.js          cross-origin isolation for static hosting
circuits/                     compiled Noir circuit, verification key, manifest (built)
vendor/zk/                    bundled in-browser prover/verifier (built)
noir/                         Noir circuit source, browser prover source, build + tests
  noir/xproof/src/            main.nr (relation), sha512.nr, secp.nr, bignum.nr
  noir/web/                   prover Web Worker + main-thread API (bundled by Vite)
  noir/tools/                 build-circuit.mjs, test.mjs, run.mjs, check-sha512-constants.py
zkvm/                         SP1 zkVM version (Rust): guest program, host CLI + HTTP server
SPEC.md                       formal specification
```

## Building the in-browser prover

Requirements: Node 20+. The Noir compiler and Barretenberg prover come from npm, so no other
toolchain is needed.

```sh
cd noir
npm ci
npm run build        # compile circuit → circuits/, bundle prover → vendor/zk/
npm test             # SHA-512 constants, path shapes vs SP1, 10 forgery attempts, prove+verify
```

The built `circuits/` and `vendor/zk/` are committed, so the site can be served as plain
static files: `python3 -m http.server` from the repo root works (single-threaded, no
isolation), and so does any static host.

## Running the server version (optional)

The server serves this same page and enables the SP1 prover cards. In those modes the **xpub is
sent to the server**, so only run it on a machine you control.

```sh
cd zkvm
cargo build --release -p xproof-host     # needs the SP1 toolchain (sp1up) and Docker for Groth16
./target/release/xproof-host serve --port 10778
# open http://localhost:10778
```

The CLI also works on its own:

```sh
xproof-host execute --parent-pub HEX --chain-code HEX --path-a 0/1 --path-b 1/3 \
    --context STR --expires-at MS                       # dry run, prints cycle count
xproof-host prove   ... [--groth16] --out proof.hex     # real proof
xproof-host vkey                                        # program verifying-key hash
```

HTTP API:

- `POST /api/prove`: `{parent_pub, chain_code, path_a, path_b, context, expires_at, mode?}`,
  where `mode` is `"compressed"` (default) or `"groth16"`. Returns
  `{ok, mode, receipt_hex, journal_hex, vk_hex, elapsed_ms}`.
- `POST /api/verify`: `{receipt_hex}` or `{groth16_hex, journal_hex}` → `{ok, journal_hex, error}`
- `GET /api/info`: backend description, vk hash, max depth.

On this machine the build needed a newer libstdc++ for SP1's toolchain
(`LD_LIBRARY_PATH=~/tools/anaconda3/envs/xproof-libstdcxx/lib`).

## Deploying to GitHub Pages

`.github/workflows/pages.yml` publishes the static site (`index.html`, `styles.css`,
`coi-sw.js`, `js/`, `vendor/`, `circuits/`) on every push to `main`. In the repo settings, set
Pages → Source to "GitHub Actions".

## Caveats

- **Signet only.** The wallet seed lives in `localStorage`. Never send real bitcoin to it.
- A proof shows **knowledge of the xpub**, not spend authority. The on-chain anchor shows that
  key B has signed at some point. See SPEC §7 for the fresh-signature extension.
- Proofs can be forwarded: anyone who has the file can verify the link.
- The "simulated" mode is a teaching aid, not a proof.

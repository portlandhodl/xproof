# xproof — Specification

**Statement ID:** `xproof-ownership-link-v1`
**Status:** draft, demo implementation (signet only)

xproof proves that two secp256k1 public keys are both BIP32 descendants of one extended
public key (xpub), **without revealing the xpub, its chain code, or the derivation paths**.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

---

## 1. Notation

| Symbol | Meaning |
|---|---|
| `G`, `n`, `p` | secp256k1 generator, group order, field prime |
| `x(P)`, `y(P)` | affine coordinates of point `P` |
| `ser_P(P)` | 33-byte SEC1 compressed encoding: `0x02 \| (y(P) & 1)` ‖ `x(P)` (big-endian) |
| `ser32(i)` | 4-byte big-endian encoding of `i` |
| `HMAC(k, m)` | HMAC-SHA512 |
| `SHA256`, `HASH160` | SHA-256; RIPEMD160(SHA256(·)) |
| `a ‖ b` | byte concatenation |
| `[i₁/…/i_d]` | a derivation path of depth `d` below the xpub |

## 2. Background: BIP32 public derivation

For a node `(K, c)` (public key, chain code) and a **non-hardened** index `0 ≤ i < 2³¹`:

```
I        = HMAC(c, ser_P(K) ‖ ser32(i))
t        = parse256(I[0..32])        — the child is invalid if t ≥ n
K'       = K + t·G                   — invalid if K' = O
c'       = I[32..64]
CKDpub((K, c), i) = (K', c')
```

`CKDpub*((K, c), [i₁/…/i_d])` applies `CKDpub` `d` times. Hardened derivation needs the parent
private key and is out of scope: the prover is assumed to hold an xpub.

## 3. The statement

### 3.1 Relation

Public inputs `x = (key_a, key_b, context_hash, expires_at)`.
Witness `w = (K_par, c_par, path_a, path_b)`.

`R(x, w) = 1` iff all of:

1. `K_par` is a point on secp256k1, and `c_par` is 32 bytes.
2. `path_a` and `path_b` are non-empty, at most `MAX_DEPTH` long, and all indices are `< 2³¹`.
3. `key_a = ser_P(CKDpub*((K_par, c_par), path_a).K)`, and no step is invalid.
4. `key_b = ser_P(CKDpub*((K_par, c_par), path_b).K)`, and no step is invalid.
5. `key_a ≠ key_b`.

`context_hash` and `expires_at` are not constrained by `R`. They are bound to the proof as public
inputs, so a proof made for one session can't be replayed in another (§6.3).

### 3.2 Public input encoding

The canonical public values form a 106-byte **journal**:

```
offset  len  field
0       33   key_a          SEC1 compressed child key A
33      33   key_b          SEC1 compressed child key B (the on-chain anchor)
66      32   context_hash   SHA256(UTF-8(context string))
98       8   expires_at     unix epoch milliseconds, u64 big-endian
```

The SP1 backend commits exactly these bytes. The Noir backend exposes them as 99 BN254
field elements: one per byte of `key_a`, `key_b` and `context_hash` (98), then `expires_at` as one
element. Both encodings decode to the same journal.

### 3.3 What a proof reveals

A valid proof reveals `key_a`, `key_b`, `context_hash`, `expires_at`, and the fact that one
(hidden) xpub links the two keys. It MUST NOT reveal `K_par`, `c_par`, the paths, or their
lengths. §7 lists the known side channels.

### 3.4 Semantics

A proof shows that **the prover knows an xpub that links the keys**. It does *not* show that the
prover can spend from either key: anyone holding the xpub (for example a watch-only auditor) can
produce the same proof. Spend authority comes from the on-chain anchor (§6.4), and from a fresh
signature where needed (§7).

## 4. Backend A — Noir circuit (in-browser, WASM)

Source: `noir/xproof/src/`. Proof system: Barretenberg **UltraHonk** with zero-knowledge and a
Keccak transcript (`verifierTarget: "evm"`), so it can be verified on-chain.
Universal setup: KZG over BN254 using the Aztec Ignition SRS.

### 4.1 Fixed shape

`MAX_DEPTH = 3`. The circuit evaluates exactly `MAX_DEPTH` steps for each path, whatever the
actual lengths `len_a, len_b ∈ [1, 3]`. Step `d ≥ len` derives index `0` from the current node and
**does not advance** it. Every proof therefore does identical work, and proving time does not
depend on path shape.

The two key-pad compressions of `HMAC(c_par, ·)` (`SHA512` over `c_par ⊕ ipad` and
`c_par ⊕ opad`) are computed once and shared by both paths' first step.

### 4.2 SHA-512 and HMAC

SHA-512 follows FIPS 180-4 on `u64` words. The constants are checked against their definitions
(fractional parts of square and cube roots of the first primes) when they are generated. For
`CKDpub`, the HMAC message is exactly 37 bytes (`ser_P(K) ‖ ser32(i)`), so each HMAC costs 4
compressions: ipad, inner data block (length 1320 bits), opad, and outer block (length 1536 bits).

### 4.3 Point steps via the ECDSA-verification gadget

The circuit has no native secp256k1 arithmetic. It constrains `K' = K + t·G` with Barretenberg's
secp256k1 ECDSA-verification black box, `V(Q, e, (r, s))`. `V` accepts iff `0 < r, s < n`,
`s ≤ n/2` (low-S), and `x(R) mod n = r`, where `R = (e·s⁻¹)·G + (r·s⁻¹)·Q`.

**Lemma 1.** If `s ∈ {r, n − r}` and `e ≡ t·r (mod n)`, then `V(Q, e, (r, s))` accepts iff
`x(Q + t·G) ≡ r (mod n)`.
*Proof.* If `s = r`, then `R = t·G + Q`. If `s = −r`, then `R = −(t·G + Q)`, which has the same `x`. ∎

**Lemma 2.** If `s ∈ {r, n − r}` and `e ≡ −t·r (mod n)`, then `V` accepts iff `x(Q − t·G) ≡ r (mod n)`.

For each step the prover supplies the child point `C` as a hint. The circuit enforces:

- (V) `C` and `K` are valid points: `y² ≡ x³ + 7 (mod p)`, `y < p`, and `x < n` (so `x` can serve as
  an ECDSA `r` without reduction).
- (A) "forward": `V(K, t·x(C), (x(C), s₁))`, so by Lemma 1, `x(K + t·G) ≡ x(C)`.
- (B) "back": `V(C, −t·x(K), (x(K), s₂))`, so by Lemma 2, `x(C − t·G) ≡ x(K)`.
- `s₁ ∈ {x(C), n − x(C)}`, `s₂ ∈ {x(K), n − x(K)}`, chosen by the prover to be low-S.

**Theorem.** If (V), (A) and (B) hold, then `C = K + t·G`, except with negligible probability.
*Proof sketch.* Let `P = K + t·G`. From (A), `x(P) ≡ x(C) (mod n)`. Both values lie in `[0, p)`
and `p < 2n`, so either `x(P) = x(C)`, or `x(P) ≥ n`. For `P`, an output of an HMAC-derived
scalar multiplication, `x(P) ≥ n` happens with probability `(p − n)/p < 2⁻¹²⁷` per attempt. So
`C = ±P`. If `C = −P`, then (B) requires `x(−K − 2t·G) ≡ x(K)`. That forces `K = −t·G` (or `t = 0`),
i.e. a key whose discrete log equals the negated HMAC of its own encoding. Finding one is as hard
as finding a fixed point of HMAC-SHA512 under scalar multiplication (probability `≈ 1/n` per
attempt). Hence `C = P`. ∎

Check (B) is what pins the **y-parity**. Without it a prover could claim the negated key
`−K_A`, which has the same `x` but the opposite prefix byte. The test suite includes this attack
(`noir/tools/attacks.mjs`), and the circuit rejects it.

**Completeness.** The honest prover fails only if some point on a path has `x ≥ n`
(probability `< 2⁻¹²⁷` per point), or if `t·x ≡ 0 (mod n)`.

### 4.4 Non-native arithmetic checks

256-bit integers are 4 little-endian `u64` limbs, so every limb is range-checked. The circuit
never computes modular products itself. It checks prover-supplied results:

- `assert_mulmod(a, b, q, r, m)`: `a·b = q·m + r` over the integers, and `r < m`. The check runs
  per 64-bit column with signed carries `cₖ = (Σ_{i+j=k} aᵢbⱼ − qᵢmⱼ − rₖ + cₖ₋₁)·2⁻⁶⁴`. Each
  carry must satisfy `cₖ + 2⁶⁸ < 2⁷⁰`, and `c₇ = 0`. Every intermediate value is `< 2¹⁴⁰`, far below
  the BN254 modulus, so field equalities are integer equalities.
- `assert_lt(a, b)`: borrow chain over `u128`.
- `assert_add(a, b, c)`: exact limb addition with carries.

### 4.5 Circuit parameters (v1)

| | |
|---|---|
| Gates | 1,757,751 (dyadic 2²¹) |
| SHA-512 compressions | 22 (≈65k gates each) |
| ECDSA gadgets | 12 (≈38k gates each) |
| Proof size | 10,688 bytes |
| Public inputs | 99 field elements |

`circuits/manifest.json` records the compiler and backend versions and the SHA-256 of the compiled
circuit and of the verification key. A verifier SHOULD pin `vk_sha256`.

## 5. Backend B — SP1 zkVM (self-hosted server)

Source: `zkvm/program/src/main.rs` (guest), `zkvm/script/src/main.rs` (host). The guest implements
§3.1 directly in Rust (`hmac`, `sha2`, `k256` with SP1's secp256k1 precompile). It allows
`MAX_DEPTH = 16`, derives a shared path prefix only once, and commits the journal (§3.2).

The host emits exactly one kind of proof: the SP1 STARK wrapped in a BN254 **Groth16** SNARK —
zero-knowledge, 356 bytes, verifiable with `sp1-verifier` from (proof, journal, vk hash), or
on-chain. A bare STARK MUST NOT be emitted: it is not zero-knowledge and can expose the witness.

## 6. Protocol

### 6.1 Roles

- **Prover:** holds the xpub (and, for the anchor, key B's private key).
- **Verifier:** knows nothing about the wallet. Receives a proof file, and reads the chain.

### 6.2 Proof file formats (JSON)

```jsonc
// Noir / UltraHonk (in-browser)
{ "mode": "noir",    "proof_hex": "…", "public_inputs": ["0x…" ×99], "vk_sha256": "…" }
// SP1 Groth16
{ "mode": "groth16", "groth16_hex": "…", "journal_hex": "…(212 hex chars)" }
```

### 6.3 Verification procedure

The verifier MUST, in order:

1. **Verify the proof** against the pinned verification key (Noir: `circuits/xproof.vk`; SP1: the
   program vk hash), and obtain the journal.
2. **Check freshness:** `context_hash = SHA256(session_context)`, where the verifier chose the
   session context, and `now < expires_at`.
3. **Check the anchor** for `key_b` (§6.4).
4. Optionally, check that `key_a` is the key it expected to be attested.

### 6.4 On-chain anchor (signet P2WPKH)

The anchor shows that `key_b` is a live key whose holder has signed on-chain. The verifier
derives everything from `key_b`:

1. `addr = bech32("tb", 0, HASH160(key_b))`.
2. Fetch the transactions of `addr` (demo: the Esplora API at `mempool.space/signet`).
3. Find an input whose witness is `[sig ‖ 0x01, key_b]`.
4. Recompute that input's BIP143 `SIGHASH_ALL` digest from the transaction and its prevout amounts,
   DER-decode `sig`, and verify ECDSA under `key_b`.

The verifier MUST NOT trust any prover-supplied transaction data.

## 7. Security considerations

- **Witness privacy.** Both ZK backends hide the witness. The Noir circuit does the same amount of
  work for every path shape. Proving time on the SP1 server grows with the total number of
  derivation steps.
- **Proof transferability.** A proof convinces *anyone*, not just the intended verifier.
  `context_hash` stops it being reused as a fresh login, but not from being forwarded as evidence
  of the link. The link is permanent once revealed.
- **Anchor freshness.** An old spend by `key_b` shows that someone controlled `key_b` at some
  point. It does not show that the prover controls it now. Deployments that need this SHOULD also
  require a signature by `key_b` over `context_hash`, or extend the relation with a private-key check.
- **BIP32 non-hardened leakage.** Anyone who has the xpub **and** any non-hardened child private
  key can recover the parent private key. xproof exists so that the xpub never has to be shared.
- **Trust in setup.** UltraHonk relies on the Ignition SRS (a 1-of-N trusted ceremony). SP1 Groth16
  relies on Succinct's circuit-specific setup.
- **Demo hosting.** The in-browser prover keeps the witness inside the tab. The server modes send
  the xpub to the `xproof-host` process, so run it only on hardware you control.
- **Network.** Signet only. The page's seed storage (localStorage) is not suitable for real funds.

## 8. Versioning

A change to the relation, the public input encoding, or `MAX_DEPTH` MUST produce a new statement
ID and a new verification key. Verifiers SHOULD reject proofs whose `vk_sha256` (Noir) or vk hash
(SP1) they have not pinned.

# Sigil Roadmap

Forward-looking work only. For shipped items and per-version detail see
[CHANGELOG.md](../../CHANGELOG.md) and [state.md](state.md) ("Recently
shipped").

## Outstanding work

The only open items. The 3.6 cyrius-native-TLS arc and most of the v3.7
perf cycle have shipped — see "Closed cycles" below + CHANGELOG.

**P1 — cyrius-6.1.20 bundle-consumer SIGILL: RESOLVED in 3.7.8.** The
reported symptom (SIGILL/exit 132 on `sha256` + `ed25519_*` under cyrius
6.1.x, software `sha1` fine) was real, but the **suspected cause was
wrong**. It was *not* the asm `[rbp-N]` param-load drift — it was **missing
opt-in stdlib deps in bundle-consumer builds.** Cyrius stdlib is opt-in
(not auto-associated); `dist/sigil.cyr` carries none. Since 3.6 the banked
crypto hot path runs `cbank()` → `thread_local_*` on **every**
`sha256`/`ed25519`/`aes` call, every constant-time compare runs
`ct_eq_bytes_lens`, and ML-DSA (default-on @3.7.6) runs `shake256`. A
consumer including only the bundle leaves those undefined — cyrius 6.1.x
*warns* and compiles each unresolved call to a `ud2`, so the program
builds then SIGILLs the instant a crypto path hits one. **Fix:** the
README "Usage — stdlib include order" section now documents all four
required opt-in includes (`lib/ct.cyr`, `lib/keccak.cyr`, `lib/thread.cyr`,
`lib/thread_local.cyr`) and warns it is a *runtime* crash, not a build
error. **Belt-and-suspenders:** the predicted **3.2.0 structural NI fix
also landed** — `src/sha_ni.cyr` / `src/aes_ni.cyr` migrated off hardcoded
`mov r__, [rbp-N]` param loads to the prologue-drift-proof
`param_load(reg, idx)` pseudo (cyrius 6.0.67+), closing the latent
fragility the 2026-05-10 issue warned about. Pin bumped 6.0.87 → **6.1.20**;
verified green (suite 1459/1459, bundle repro exits 0 with correct digests
once the four includes are present). See
[`docs/development/issues/2026-06-09-cyrius-6120-rebreaks-ni-paths-sigill.md`](issues/2026-06-09-cyrius-6120-rebreaks-ni-paths-sigill.md)
and the originating
[`2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md`](issues/2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md).

**x509 — cert verification: COMPLETE.** The P1 off-diagonal ECDSA
chain-link verification **shipped in 3.7.5** — `_x509_verify_link` now
decouples hash-selection (child sig-algo OID) from curve-selection
(issuer key), verifying all four `{P-256, P-384} × {SHA-256, SHA-384}`
combos (FIPS 186-4 §6.4 leftmost-bits digest mapping; new
`_ecdsa_p{256,384}_verify_digest` cores), and `x509_parse_into` sizes
the stored `sig_len` by the issuer curve rather than the hash. See
CHANGELOG 3.7.5 + the now-resolved
`docs/development/issues/2026-06-06-x509-off-diagonal-ecdsa-verify.md`.

**Tooling / process — committed for the next release**

- [ ] **Buried-deferral gate.** A closeout/CI check that greps `src/`
      for deferral language in comments — `deferred`, `TODO`, `FIXME`,
      `XXX`, `HACK`, `follow-up`, `for now`, `not yet`, `later bite`,
      `a future bite`, `out of scope`, `defer-to-` — and **fails (or
      reports) any hit not cross-referenced by a roadmap entry**. This
      converts the recurring "scope cut buried in a source comment"
      failure mode (the hard rule's exact target — every deferral is
      Robert's call, never a silent comment) from a human-caught
      regression into a mechanical gate the next cycle can't ship past
      without either doing the work or surfacing it. Wire it into the
      CLAUDE.md Closeout Pass (and/or sigil's pre-release verification,
      e.g. `programs/check.cyr` if that's where it lands). Start in
      *report* mode, flip to *fail* once the vocabulary is tuned and the
      tree is clean. The grep vocabulary is the only repo-specific part —
      the check itself generalizes across the AGNOS first-party repos
      (worth lifting into the shared tooling once proven here). Extends
      the `docs/doc-health.md` "Programmatic gates (future)" family.
      **Tree status (3.7.7 sweep):** the genuine deferrals were surfaced
      to the Backlog above and the stale comments updated to mark shipped
      work, so the tree is clean except a **known allowlist of false
      positives**: `src/policy.cyr:329,347` (the literal `\uXXXX` JSON
      unicode-escape notation, where `XXX` is a substring — not a
      deferral). The gate must allowlist these (and re-scan as new
      false-positive shapes appear) before flipping to *fail*.

**v3.7 — perf (OPEN)**

- [~] **EC scalar-mult speedup — PARTIALLY DONE in 3.7.8 (~2× both
      curves); ≤ 10 ms P-256 target still open.** Shipped: a fixed-base
      4-bit comb for `u1·G` (`p256_scalarmul_base` / `p384_scalarmul_base`,
      precomputed `64×16`/`96×16` table, zero hot-path doublings) + a 4-bit
      windowed double-and-add for the variable `u2·Q`
      (`p256_scalarmul_var` / `p384_scalarmul_var`), both **verify-only /
      non-CT** (verify is public data; the secret-nonce signing path stays
      on the constant-time `pt{,384}_scalarmul` ladder). **`ecdsa_p256_verify`
      24.675 → 11.600 ms (2.13×)`; `ecdsa_p384_verify` 54.6 → 26.263 ms
      (2.08×)** (`history.csv` row `v3.7.8-ec-comb-window`).
      **STILL OPEN — the ≤ 10 ms `ecdsa_p256_verify` target is not yet met
      (11.6 ms).** The remaining squeeze, in rising risk order:
      1. **Inversion addition-chain** for `fn_p256_inv` (s⁻¹) and the
         `pt_to_affine` field inverse — the existing generic
         square-and-multiply is ~256 sq + ~128 mul each; a fixed chain
         drops to ~265 muls (this is the standalone Backlog item below —
         now explicitly paired with this bite). Isolated, ~5% × 2.
      2. **Mixed Jacobian+affine addition** with an affine comb table —
         saves ~4 muls on each of the ~143 verify-path adds. Isolated to
         the verify path; needs a new add formula (point-add correctness
         risk, KAT-gated).
      3. **Karatsuba `u256_mul_full`** — biggest single lever (~15–25% on
         every field mul) but touches the **audited shared 256-bit
         multiply** used by all P-256 field + scalar ops; a carry bug =
         signature-verify mis-accept, so it needs a full security
         re-review before landing.
      Pairs with the "scatter-store comb" backlog item if a comb is ever
      put on a secret path (it must not be on the current non-CT shape).

- [ ] **Re-run the full crypto bench suite** at the cycle close —
      before/after rows for every verify-path bench; cross-check the
      transitive SEV-SNP / TDX deltas.

**Backlog — unscheduled** (open; gated as noted)

The following were surfaced from in-source deferral comments in the 3.7.7
buried-deferral sweep (previously tracked only in code comments — now
promoted here so they are visible, not buried):

- [ ] **ChaCha20 + X25519 on the parallel batch path.** Both
      (`src/chacha20.cyr`, `src/x25519.cyr`) use function-scope `var`
      working state (quirk #1) and are correct for serial use only — they
      are NOT banked for the parallel batch-verify path. If a consumer
      puts either on a concurrent path, give them the 3.6 per-worker bank
      treatment (`src/crypto_scratch.cyr`). Not needed today (only Ed25519
      verify is batched).

- [ ] **TDX / SGX in-quote PCK X.509 chain walk.** The TEE orchestrators
      (`src/tdx.cyr`, `src/sgx.cyr`) take a *pre-validated* PCK pubkey; the
      X.509 walk from the in-quote PCK leaf up to the Intel SGX Root CA is
      currently the caller's responsibility (kavach reuses its external
      walk). Owning the walk inside sigil would make the orchestrators
      self-contained — consider when a consumer needs it.

- [ ] **Scalar-inversion addition-chain.** `fn_p256_inv` / the field/scalar
      inversions (`src/ecdsa_p256.cyr`) use generic square-and-multiply
      (~256 sq + ~128 mul). A fixed addition chain (à la `fp_inv` in
      `bigint_ext.cyr`) drops this to ~265 muls. Small verify-path win;
      pairs with the EC scalar-mult speedup bite.

- [ ] **`bn_modexp` dead-code decision.** `bn_modexp` (`src/bignum.cyr`,
      schoolbook non-CT public-data modexp) has no call sites since 3.6.6
      moved RSA verify+sign to `bn_mont_modexp`. Either remove it or keep
      it explicitly as the schoolbook reference — maintainer's call at the
      next dead-code closeout. (Its "do not use for secret exponents"
      warnings stay valid while it exists.)

- [ ] **Retire the per-thread bank-indexing workaround** if cyrius gains
      a native thread-local *array* qualifier (`threadlocal var X[N]`).
      The 3.6 bank scheme (`src/crypto_scratch.cyr`) exists only because
      `var X[N]` is a static function-scope global and cyrius TLS is
      slot-based. If a true thread-local array qualifier lands, collapse
      the `[N*8]` banks back to `var X[N]` and drop the module. Check on
      each toolchain bump. *(6.0.62 added real per-thread TLS slots — not
      arrays — so this stays gated.)*

- [ ] **Scatter-store for the fixed-base comb** (cache-timing).
      Distribute the 128-byte point entries across cache lines so a
      same-host cache-timing attacker cannot recover which nibble was
      selected per window. Not needed for AGNOS's single-tenant
      deployment; queue if the threat model shifts to multi-tenant.
      Pairs with the 3.7.4 EC scalar-mult comb.

- [ ] **CLMUL-assisted GHASH** — gated on the cyrius `asm`-block
      global-symbol pseudo (filed upstream:
      [`asm-block-global-symbol-pseudo`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md)).
      AES-GCM 1 KB sits ~700 µs after AES-NI; GHASH (bit-by-bit
      GF(2^128) multiply) now dominates. PCLMULQDQ/VPCLMULQDQ closes the
      gap, same byte-encoding pattern as the SHA-NI/AES-NI dispatchers.

- [x] **NI dispatch structural fix** — **DONE in 3.7.8.** Migrated
      `aes_ni.cyr` / `sha_ni.cyr` dispatchers (cpuid probes + compress /
      encrypt-block fns) off the hardcoded `mov r__, [rbp-N]` parameter
      loads to the prologue-drift-proof `param_load(reg, idx)` pseudo
      (cyrius 6.0.67+; the "asm pseudo" this was gated on). The 3.2.0
      runtime self-test gate is kept as defence-in-depth against any
      future *wrong-output* asm regression. (Note: this was belt-and-
      suspenders — the actual 6.1.20 SIGILL was missing opt-in stdlib
      deps in bundle-consumer builds, fixed via README docs; see the
      resolved P1 above. The CLMUL-GHASH item below stays gated on the
      *separate* asm-block **global-symbol** pseudo, still absent.)

**Possible future surfaces** (consumer-demand-gated)

- [ ] **ML-KEM-768** (PQC KEM) — belongs in a sibling `kem.cyr` if an
      AGNOS consumer needs key agreement. (ML-DSA-65 PQC sign ships
      default-on since 3.7.6.)
- [x] **PQC-default builds** — **DONE in 3.7.6.** Cyrius 6.0.87 raised the
      1 MB preprocessor cap; the `#ifdef SIGIL_PQC` gate was dropped in
      `src/lib.cyr` so ML-DSA-65 is default-on (matching the dist bundle,
      which always included it). `-D SIGIL_PQC` is now a back-compat no-op.

**Open audit findings — NONE.** The audit floor was **cleared at 3.7.3**
(4 genuine per-call-drift LOWs resolved via the `_into` caller-scratch
API; 4 reclassified as correct init-once singletons). See state.md
"Audit floor".

## Closed cycles

Per-version detail in [CHANGELOG.md](../../CHANGELOG.md); per-cycle
audits in [`docs/audit/`](../audit/).

- [`3.0-scope.md`](3.0-scope.md) — 3.0 cycle.
- [`3.2-scope.md`](3.2-scope.md) / [`3.2-tee-arc.md`](3.2-tee-arc.md) —
  3.2.0 + the 3.2.x TEE attestation sub-arc.
- **3.4** — TEE attestation completion (PEM decoder, SGX/TDX/SEV-SNP
  `*_verify_full`, x509 P-384 SPKI).
- **3.5** — modern AEAD + key agreement + the first cyrius-native-TLS
  crypto: Poly1305 / ChaCha20 / ChaCha20-Poly1305 / X25519,
  HMAC-/HKDF-SHA384, AES-128-GCM, EC + Ed25519 private-key parsers,
  ECDSA P-256/P-384 deterministic signing.
- **3.6 — cyrius-native-TLS arc (CLOSED at 3.6.8)** — parallel batch
  verify (mutex drop via per-thread crypto banks, 3.42×); TLS 1.2 PRF;
  the full RSA PKCS#1 v1.5 **and PSS** surface on a new general
  bignum/modexp engine (constant-time Montgomery ladder + base blinding
  + CRT + verify-after-sign); RSA + P-384 x509 chain-link verify;
  Montgomery-on-verify (3.43×); `pem_decode_privkey`→RSAK; AES-128 seal
  keys. Closed out at 3.6.8 (Closeout Pass + the overdue 3.5.6 audit doc
  + un-burying three hidden deferrals). Issue cross-walk:
  [`issues/2026-05-28-cyrius-tls-arc-full-audit.md`](issues/2026-05-28-cyrius-tls-arc-full-audit.md)
  (all five line items delivered).
- **3.7 — perf + x509 (IN PROGRESS)** — Solinas reduction for P-256
  (3.7.0, verify 147→26 ms, 5.65×) and P-384 (3.7.1, 339→55 ms, 6.21×);
  AES-GCM arbitrary-length IVs (3.7.2, SP 800-38D §7.1); the
  caller-scratch `_into` API + **audit-floor clear (8 → 0)** (3.7.3);
  x509 off-diagonal ECDSA **parse**-side fix (3.7.4, SSL.com Root ECC
  class) and the **verify**-side closer (3.7.5, all four hash×curve
  combos — P1 complete); toolchain pin 6.0.62 → 6.0.87 (3.7.5);
  **PQC-default** — ML-DSA-65 default-on, gate dropped now the 6.0.87 cap
  allows it (3.7.6); the **buried-deferral sweep** — genuine deferrals
  surfaced to the Backlog, stale comments marked shipped, false positives
  reduced to a `\uXXXX` allowlist (3.7.7); the **cyrius-6.1.20 bundle-
  consumer SIGILL fix** — README now documents the four required opt-in
  stdlib includes (the real root cause), plus the belt-and-suspenders NI
  `param_load` structural fix + pin 6.0.87 → 6.1.20, **and the EC
  scalar-mult speedup** — fixed-base comb for `u1·G` + windowed `u2·Q`
  (verify-only), `ecdsa_p256_verify` 24.7 → 11.6 ms (2.13×) /
  `ecdsa_p384_verify` 54.6 → 26.3 ms (2.08×) (3.7.8). Remaining: the ≤ 10 ms
  P-256 squeeze (inversion-chain / mixed-add / Karatsuba), the
  buried-deferral *gate*, and the full bench re-run (see Outstanding above).

**Cyrius pin:** `6.1.20` (synced across `cyrius.cyml` and CI).

# Sigil Roadmap

Forward-looking work only. For shipped items and version history
see [CHANGELOG.md](../../CHANGELOG.md). Closed cycles:

- [`3.2-tee-arc.md`](3.2-tee-arc.md) — 3.2.x TEE attestation
  sub-arc, complete 2026-05-21 → 2026-05-26 (6 bites: ECDSA →
  X.509 → SGX → SEV-SNP → TDX → SGX seal).
- [`3.2-scope.md`](3.2-scope.md) — 3.2.0 cycle history.
- [`3.0-scope.md`](3.0-scope.md) — 3.0 cycle history.
- **3.4 — TEE attestation completion** (shipped 2026-05-22).
  - **3.4.0**: PEM decoder + `sgx_quote_verify_full` +
    `tdx_quote_verify_full` + TDX `att_key_type=3` (P-384/SHA-384)
    dispatch. Audit: `docs/audit/2026-05-22-3.4.0-audit.md`.
  - **3.4.1**: x509 P-384 SPKI extraction + `snp_report_verify_full`
    + `X509_CURVE_*` constants + struct layout shift. Closes the
    SEV-SNP gap deferred from 3.4.0. Audit:
    `docs/audit/2026-05-22-3.4.1-audit.md`.
  - **3.4.2**: Packaging fix — `dist/sigil.cyr` regenerated
    from current source (had drifted ten module additions
    behind since the upstream `cyrius distlib` subcommand
    retired); `scripts/regen-dist.sh` shipped as the
    replacement. 2026-05-22 doc-tree restructure rides along.
    Audit: `docs/audit/2026-05-22-3.4.2-audit.md`.
- **3.5.0–3.5.6 — modern AEAD + key agreement** (shipped
  2026-05-27/28): Poly1305 → ChaCha20 → ChaCha20-Poly1305 AEAD →
  X25519, then a post-closeout HMAC-SHA384 + HKDF-SHA384 patch.
  Completes the TLS 1.3 ChaCha20-Poly1305-SHA256 +
  AES-256-GCM-SHA384 suites with X25519 key share. Audit:
  `docs/audit/2026-05-27-3.5-arc-audit.md`. Per-version detail in
  [CHANGELOG.md](../../CHANGELOG.md).

**Cyrius pin:** `6.0.52` (synced across `cyrius.cyml` and CI).

## v3.5.x — cyrius native-TLS arc support (in progress)

The cyrius native-TLS arc needs sigil-side crypto one slot at a time
across cyrius v6.0.14 → .34
([`issues/2026-05-28-cyrius-tls-arc-full-audit.md`](issues/2026-05-28-cyrius-tls-arc-full-audit.md),
five line items). Sigil ships them as ordered 3.5.x bites; cyrius
bumps its pin and resumes the held slot at each tag. Each crypto bite
carries its own per-bite audit doc; the cycle-wide **Closeout Pass is
held as the last 3.5.x tag (3.5.12)**.

> **Catch-all slot:** fold any small additive/repair need against the
> modern-crypto surface into the nearest unshipped bite or a new 3.5.x
> slot **ahead of** the closeout — never after it.

### Shipped (per-version detail in [CHANGELOG.md](../../CHANGELOG.md))

- **3.5.7 — AES-128-GCM** (`src/aes_gcm.cyr` + 10-round AES-NI path).
  RFC 8446 §9.1 mandatory `TLS_AES_128_GCM_SHA256`. Unblocked cyrius
  v6.0.14. Audit: `docs/audit/2026-05-28-3.5.7-aes128-gcm-audit.md`.
- **3.5.8 — EC + Ed25519 private-key parsers** (`src/privkey.cyr`):
  `ecdsa_p256/p384_privkey_from_der` (SEC1 / PKCS#8),
  `ed25519_privkey_from_der` (PKCS#8), `pem_decode_privkey`. RSA label
  recognized → parser deferred to 3.5.10. Unblocked cyrius v6.0.15/.23
  key loading. Audit:
  `docs/audit/2026-05-28-3.5.8-privkey-parsers-audit.md`.
- **3.5.9 — ECDSA P-256/P-384 sign** (`src/ecdsa_sign.cyr`): RFC 6979
  deterministic-k, raw `r||s` + DER. Unblocked cyrius v6.0.17/.25
  CertificateVerify. Audit:
  `docs/audit/2026-05-28-3.5.9-ecdsa-sign-audit.md`.

### Remaining

> **Renumbered into the 3.6.x line (2026-06-03).** 3.6.0 opened the
> 3.6 line early to land parallel verify (cyrius 6.0.52 shipped the
> thread-local storage that unblocked it — see "Road to v3.6" below,
> now **shipped**). The three unshipped cyrius-native-TLS items below
> therefore carry forward as **3.6.x** tags (RSA → TLS 1.2 PRF →
> closeout), keeping their ordering and forcing slots. Section titles
> left as `3.5.x` for blame continuity; track them as 3.6.x in
> `state.md`.

### 3.5.10 — RSA signature surface (issue line item 2) — **Large**

- [ ] **RSA PKCS#1 v1.5 + PSS, sign + verify, SHA-256 + SHA-384.**
      `rsa_pkcs1_{sign,verify}_sha{256,384}` +
      `rsa_pss_{sign,verify}_sha{256,384}` (8 fns, or 2 dispatched).
      TLS 1.3 server certs are overwhelmingly RSA in the wild
      (Let's Encrypt default; enterprise CAs) — without it cyrius's
      1.3 client cannot verify most RSA-signed CertificateVerify and
      its server cannot present an RSA cert; also blocks all 1.2 RSA
      ciphersuites. SHA-512-RSA stays backlog (rare in 1.3).
      **Sizing — Large / likely multi-bite:** unlike the other four
      items this is *not* existing-shape — sigil has no general
      bignum modexp engine (`bigint_ext` is Curve25519-only). Expect
      to split into sub-tags if it does not fit one patch, e.g.
      `3.5.10` general big-integer modexp engine + the RSA key type +
      `rsa_privkey_from_der` (PKCS#1 / PKCS#8) + `rsa_pubkey_from_*` +
      PKCS#1 v1.5 verify (the most interop-load-bearing path), then
      `3.5.10a/.11`-shaped follow-ons for PSS (MGF1) + the sign paths.
      Each sub-bite gets its own audit doc (Montgomery/modexp
      constant-time, padding-oracle hygiene on verify, blinding on
      sign). **Owns the RSA private-key parser** (moved here from
      3.5.8 — it needs the bignum key type defined in this bite to
      parse into and a sign/verify path to test against; the 3.5.8
      `pem_decode_privkey` already routes the `RSA PRIVATE KEY` header
      to a stub that this bite fills in). **Cyrius forcing slots:**
      v6.0.17 / v6.0.25 (verify + sign for CertificateVerify) and
      v6.0.29–.34 (1.2 RSA suites).

### 3.6.1 — TLS 1.2 PRF — **SHIPPED 2026-06-03** (was 3.5.11, issue line item 5)

- [x] **`tls12_prf_sha256` / `tls12_prf_sha384` — decided: SHIP.**
      `src/tls12_prf.cyr`: `PRF(secret, label, seed) = P_hash(secret,
      label || seed)` with `A(i) = HMAC_hash(secret, A(i-1))`, built on
      the existing `hmac_sha256` / `hmac_sha384`. Chosen to ship (over
      decline) for symmetry with the HKDF surface and so cyrius's TLS
      1.2 path has one crypto boundary; the construction is pure
      HMAC, so it sits cleanly on the crypto side of
      [[feedback_tls_protocol_stays_in_cyrius]] (no protocol/state
      machine). **Flagged to cyrius: sigil now owns the TLS 1.2 PRF —
      cyrius can drop its inline `tls_native.cyr` PRF and call
      `tls12_prf_sha256/384`.** Per-bite audit
      `docs/audit/2026-06-03-3.6.1-tls12-prf-audit.md`; canonical IETF
      RFC 5246 §5 vectors (+9 assertions, `tests/tcyr/tls12_prf.tcyr`).

### 3.5.12 — Closeout (audit / security / hardening) — **last 3.5.x tag**

Ships only after 3.5.7–3.5.11 land. Runs the full CLAUDE.md Closeout
Pass over the entire 3.5.5 → 3.5.11 delta and absorbs the retro-items
the 3.5.6 forcing-function patch deferred.

- [ ] **Dedicated audit doc for the 3.5.6 primitives.** File
      `docs/audit/<date>-3.5.6-hmac-hkdf-sha384-audit.md` covering
      `src/hmac_sha384.cyr` + `src/hkdf_sha384.cyr`: constant-time
      review (only branch is the public `key_len > 128` key-hash
      path), buffer-size verification (`kprime384[128]`, 48-byte
      digests, `48 + info_len + 1` scratch), `secret var` + `memset`
      zeroization, the 255×48 = 12240 OKM cap. Inline review at
      implementation was clean; this formalises it.
- [ ] **Verify the per-bite audit docs (3.5.7–3.5.11) are filed and
      clean** — every new crypto path has constant-time, buffer,
      zeroization, and known-CVE coverage. Roll any open findings
      forward to the audit floor in `state.md`.
- [ ] **Bench coverage sweep.** Confirm `history.csv` rows exist for
      AES-128-GCM, ECDSA sign, RSA sign/verify (+ HMAC/HKDF-SHA384
      `v3.5.x-sha384-kdf`); compare against the prior closeout.
- [ ] **Doc-health refresh.** `docs/doc-health.md` last swept at the
      3.5.4 closeout — refresh the ledger + `sources.md` / `state.md`
      / `CHANGELOG.md` rows to the full 3.5.5–3.5.11 state. New RFC /
      FIPS citations (RFC 6979, RFC 8017, RFC 5208/5958/8410, FIPS
      197 AES-128) land in `sources.md`.
- [ ] **Closeout Pass.** Full suite (all `.tcyr`, zero failures),
      dead-code audit, stale-comment sweep, security re-scan,
      downstream check (consumers in `state.md` build against the
      tag), clean build from scratch (`rm -rf build && cyrius deps &&
      cyrius build`), version verify (`VERSION` == `cyrius.cyml` ==
      tag).

## v3.6 — parallel verify (SHIPPED 3.6.0, 2026-06-03)

Dropped `_sigil_batch_mutex` so `sv_verify_batch` runs the crypto
concurrently across workers. **3.42×** at 64 artifacts / 4 workers
(422.867 ms → 123.563 ms vs `v3.2.0-allocfree`); `batch_parallel.tcyr`
stays 228/228 mutex-off (35/35 clean runs); CSV row
`v3.6-parallel-crypto`. Audit:
`docs/audit/2026-06-03-3.6.0-parallel-verify-audit.md`.

**Forcing function:** cyrius **6.0.52** shipped thread-local storage
(`lib/thread_local.cyr`), which made the cheaper mechanism below
possible.

**What actually shipped vs the original sketch.** The 3.3-era plan was
to thread a *caller-provided scratch pointer* through every crypto
primitive (≈14 signatures + every caller — invasive, error-prone).
With TLS available, 3.6 instead gave each worker a private **bank**
(lane) of every racing `var X[N]`: the array is widened to `[N*8]` and
sliced by `cbank()*N`, where `cbank()` reads the worker's bank index
from a thread-local slot (`src/crypto_scratch.cyr`). **No signature
changes, no caller changes, no cross-function offset map** — each
function owns its array; lanes are disjoint by construction. `var X[N]`
remaining a static function-scope global (CLAUDE.md quirk #1, still
true under cycc 6.0.52) is *accommodated*, not fought. `ge_identity`
was also made alloc-free (it called `u256_from` → `alloc`, which would
race once the mutex was gone).

### Follow-up — revisit when cyrius threading matures

- [ ] **Retire the bank-indexing workaround if cyrius grows native
      per-thread arrays.** The bank scheme exists only because `var
      X[N]` is a static function-scope global and cyrius TLS is
      slot-based (no `threadlocal var X[N]` qualifier). If a future
      cyrius lands a true stack-local or thread-local *array*
      qualifier — or otherwise makes per-call/per-thread arrays the
      default — collapse the `[N*8]` banks back to plain `var X[N]`
      and drop `src/crypto_scratch.cyr`. **Check the cyrius language
      on each toolchain bump; adopt if the current bank approach
      proves inadequate** (e.g. the ~8× `.bss` growth or the per-call
      `cbank()` read becomes a real cost, or a consumer wants parallel
      *signing*, which would need the `secret var` paths banked too —
      unsafe under the current scope-exit-zeroizes-all-lanes shape).
      File as an upstream forcing-function candidate against cyrius if
      a milestone needs it.

## Road to v3.7 — perf tuning: field arithmetic + alloc-free

The 3.2.x verify paths are correct but slow:

- `ecdsa_p256_verify` measured at 136 ms / verify
  (`benches/history.csv` row `v3.2.1`). The 3.2.1 audit's
  INFO-2 documented this as the bench-tuning follow-up.
- `ecdsa_p384_verify` un-measured but structurally ~3× the
  P-256 cost (long-division reduction at 384 bits — 1.5×
  the iterations × ~2× the limb-op cost).
- Both are bottlenecked by the textbook bit-by-bit
  long-division reduction in `_p256_long_div_reduce` /
  `_p384_long_div_reduce`. Solinas word-level reduction
  drops the cost 20–50×.

3.7 closes the bump-allocator-lifetime LOW findings (now seven
across the 3.2.x + 3.4 cycles) and lands Solinas reduction for
both curves.

### 3.7 work items

- [ ] **Solinas reduction for P-256.** Word-level reduction
      against `p256 = 2^256 − 2^224 + 2^192 + 2^96 − 1` per
      FIPS 186-4 Appendix D / NIST SP 800-186. Replace
      `_p256_long_div_reduce` with the new pipeline.
      Re-bench against the `v3.2.1` baseline; target ≤ 10 ms
      / verify. CSV row `v3.7-p256-solinas`.

- [ ] **Solinas reduction for P-384.** Same shape against
      `p384 = 2^384 − 2^128 − 2^96 + 2^32 − 1`. The P-384
      Solinas decomposition is wider (more word-level
      shuffles) but the structure is identical. CSV row
      `v3.7-p384-solinas`.

- [ ] **Unified `_into`-shape API.** Eliminate per-call
      `alloc` in `x509_parse`, `_snp_v_init`, `_sgxv_init`,
      `_tdxv_init`, `_pem_init`, and the
      `sgx_quote_verify_full` / `tdx_quote_verify_full`
      orchestrators. Two patterns to choose between:
      caller-provides-scratch (matches 3.2.0's
      `sv_verify_artifact_into` and 3.4's
      `pem_decode_certs_into`) or library-owns-pool. The
      former is cleaner for long-running consumers (kavach);
      the latter is simpler for one-shot use. Audit doc
      to pick the shape with input from kavach's actual call
      patterns. Closes seven LOWs across the 3.2.2, 3.2.4, 3.4.0,
      and 3.4.1 cycles.

- [ ] **Re-run the full crypto bench suite.** Capture before /
      after rows for every verify-path bench. The 3.7 ship
      target: `ecdsa_p256_verify` and `ecdsa_p384_verify`
      both ≤ 10 ms / verify on the dev host. SEV-SNP / TDX
      verify rows benefit transitively from the P-256 /
      P-384 speedup; cross-check the deltas are clean.

**Sequencing decision:** open 3.7 only if a downstream
consumer surfaces a latency complaint (kavach's batch-
attestation flow, ark's signature-heavy publisher workflow).
Until then, the verify path is fast enough for one-shot
checks. Cache the open audit follow-ups via this cycle's
INFO docs.

## Backlog — unscheduled

Items with a clear shape but no forcing function. Land
in-place when an adjacent edit touches the relevant module.

- [ ] **x509 chain-link verify for non-ECDSA-P256 issuers.**
      3.4.1 lets the leaf cert be P-384 but every issuer in a
      verified chain must remain P-256 (chain-link signatures
      are ECDSA-SHA256 only). Two follow-ups, both gated on a
      downstream consumer ask:
      - **P-384 chain-link verify**: extend
        `_x509_verify_link` to dispatch on issuer curve. A
        P-384 issuer would route to a P-384 sig algorithm
        (likely a new `X509_SIG_ECDSA_SHA384` enum value);
        the cert parser would accept ecdsa-with-SHA384 OID
        (1.2.840.10045.4.3.3 → DER `06 08 2A 86 48 CE 3D 04
        03 03`) and tag certs accordingly.
      - **RSA chain-link verify**: out of scope for sigil
        today — sigil has no RSA primitive. Real AMD ARK/ASK
        links are RSA-4096 + SHA-384. Surfaces only when a
        consumer integrates against real AMD KDS chains
        end-to-end via sigil (vs. external pre-walk + sigil
        ASK→VCEK fragment).

- [ ] **Scatter-store for the fixed-base comb.** Distribute
      the 128-byte point entries across cache lines so a
      cache-timing attacker on the same host cannot recover
      which nibble was selected per window. Not needed for
      AGNOS's single-tenant deployment; queue if the threat
      model shifts to multi-tenant.

- [ ] **CLMUL-assisted GHASH.** AES-GCM 1 KB encrypt/decrypt
      sits around 700 µs after AES-NI landed (2.9.1) — GHASH
      (bit-by-bit GF(2^128) multiply) now dominates.
      PCLMULQDQ / VPCLMULQDQ closes the gap. Same byte-
      encoding pattern as the existing SHA-NI / AES-NI
      dispatchers. Gated on the cyrius `asm`-block global-
      symbol pseudo (filed upstream as
      [`cyrius/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md))
      — without it CLMUL adds another `[rbp-N]`-coupled asm
      site to maintain.

- [x] **`secret var` ambient adoption.** ~20 `memset(..., 0,
      ...)` sites across `src/hkdf.cyr` / `src/aes_gcm.cyr` /
      `src/mldsa.cyr` (counted post-3.0 merge); roughly 8 are
      true private-key / PRK / round-key / GHASH-state
      buffers, the rest intermediate scratch. `secret var`
      (cyrius 5.3.5) gives compiler-guaranteed zeroization.
      **Closed in 3.4.3:** `aes_gcm.cyr` was the last
      unconverted module — 12 stack-local secret buffers
      (GHASH H, GHASH state, AES-CTR keystream,
      encrypt/decrypt tag, GHASH-mul scratch) moved to
      `secret var`. The hkdf/hmac/ed25519/mldsa/trust
      conversions already landed across earlier cycles.
      Module-global workspace buffers (`_mldsa_ws_seedbuf`,
      `_mldsa_sample_state`) and heap allocations
      (`round_keys`) remain on explicit `memset` since
      `secret var` is stack-scope only. Audit:
      `docs/audit/2026-05-23-3.4.3-audit.md`.

- [ ] **NI dispatch structural fix.** When the upstream
      cyrius `asm`-block global-symbol pseudo lands (issue
      linked above), migrate
      `src/aes_ni.cyr:aes256_encrypt_block_ni`,
      `src/aes_ni.cyr:_aes_ni_cpuid_probe`,
      `src/sha_ni.cyr:_sha_ni_compress_one`, and
      `src/sha_ni.cyr:_sha_ni_cpuid_probe` off hardcoded
      `[rbp-N]` parameter loads. The 3.2.0 runtime self-test
      gate catches misemits at boot; the structural fix
      removes the brittleness entirely. Keep the self-test
      gate even after the structural fix lands — defence-in-
      depth.

> The **ChaCha20 + ChaCha20-Poly1305 AEAD** and **X25519 key
> agreement** items were promoted out of this backlog into the
> [Road to v3.5](#road-to-v35--modern-aead--key-agreement-primitives)
> cycle (2026-05-27).

## Possible future surfaces

Out-of-scope today; surface if a consumer asks for them.

- **ML-KEM-768 (PQC KEM).** Sigil is a verification / signing
  library; key agreement belongs in a sibling module (potential
  future `kem.cyr`) if any AGNOS consumer surfaces a need.
  ML-DSA-65 (PQC sign) already shipped in 2.9.x behind
  `-D SIGIL_PQC`.

- **PQC-default builds.** PQC currently sits behind the
  `-D SIGIL_PQC` cmdline flag because the full sigil + stdlib
  + agnosys + mldsa expansion sits right at cyrius cc5's 1 MB
  preprocessor buffer cap (CLAUDE.md quirk #8). When cyrius
  raises this cap (or adds a flag to select a larger buffer),
  flip PQC to default-on and drop the cmdline gate.

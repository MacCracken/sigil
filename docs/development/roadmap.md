# Sigil Roadmap

Forward-looking work only. For shipped items and per-version detail
see [CHANGELOG.md](../../CHANGELOG.md).

## Outstanding work — full inventory

Every open item, in one place, so nothing hides in a lower section.
Detail for each is in its section below.

**3.6.x — cyrius native-TLS tail — CLOSED (3.6.8)**
- [x] RSA-PSS (MGF1) verify + sign, SHA-256/384 — **shipped 3.6.5**
- [x] Montgomery on the verify path + RSA verify/sign benches — **shipped 3.6.6** (verify 3.43×)
- [x] `pem_decode_privkey` → RSAK struct wiring — **shipped 3.6.6**
- [x] cyrius-native-TLS closeout — **shipped 3.6.8** (Closeout Pass; 3.5.6 audit doc done 3.6.5)

**v3.7 — perf (OPEN; un-gated 2026-06-04)**
- [x] Solinas reduction for P-256 — **shipped 3.7.0** (verify 147→26 ms, 5.65×)
- [x] Solinas reduction for P-384 — **shipped 3.7.1** (verify 339→55 ms, 6.21×)
- [x] Unified `_into`-shape API — **shipped 3.7.3** (caller-scratch arena; **audit floor 8 LOW → 0**: 4 drift findings resolved, 4 reclassified as correct init-once)
- [ ] Re-run full crypto bench suite
- [ ] **EC scalar-mult speedup** (fixed-base comb for G + wNAF for Q) — **next (3.7.4)**; carries the **≤10 ms ecdsa_p256_verify** target that Solinas-reduction alone did not reach (26 ms); the scalar-mult, not the reduction, is now the dominant cost

**Backlog — unscheduled**
- [ ] Retire the per-thread bank-indexing workaround if cyrius gains native thread-local arrays
- [x] x509 P-384 chain-link verify (non-P256 issuers) — **shipped 3.6.7** (`ecdsa-with-SHA384` issuers → `ecdsa_p384_verify`)
- [x] x509 RSA chain-link verify — **shipped 3.6.5** (RSA-SHA256/384 issuers)
- [x] AES-GCM arbitrary-length IVs (non-96-bit, via GHASH) — **shipped 3.7.2** (`*_iv` entries, SP 800-38D §7.1; OpenSSL/McGrew-Viega-verified). *Un-buried 3.6.5, folded into the v3.7 arc.*
- [x] AES-128 seal keys (parameterise `SGX_SEAL_KEY_SIZE`) — **shipped 3.6.7** (`sgx_derive_seal_key_n`, 16/32-byte width)
- [x] Reconcile the stale "`_into` lands in 3.6" comments in `src/sgx.cyr` / `src/tdx.cyr` — **fixed 3.6.8** (point at the gated v3.7 `_into` cycle); the stale `benches/sigil.bcyr` path in CLAUDE.md fixed too
- [ ] Scatter-store for the fixed-base comb (cache-timing)
- [ ] CLMUL-assisted GHASH (gated on cyrius asm pseudo)
- [ ] NI dispatch structural fix (gated on cyrius asm pseudo)

**Possible future surfaces (consumer-demand-gated)**
- [ ] ML-KEM-768 (PQC KEM)
- [ ] PQC-default builds (drop `-D SIGIL_PQC` when the preprocessor cap lifts)

**Open audit findings** — **NONE.** The audit floor was **cleared at
3.7.3**: 4 genuine per-call-drift LOWs resolved via the `_into`
caller-scratch API, 4 reclassified as correct init-once singletons. Zero
findings of any severity outstanding (see `state.md` "Audit floor").

## Closed cycles

- [`3.0-scope.md`](3.0-scope.md) — 3.0 cycle history.
- [`3.2-scope.md`](3.2-scope.md) / [`3.2-tee-arc.md`](3.2-tee-arc.md)
  — 3.2.0 cycle + the 3.2.x TEE attestation sub-arc.
- **3.4** — TEE attestation completion (PEM decoder, SGX/TDX/SEV-SNP
  `*_verify_full`, x509 P-384 SPKI).
- **3.5** — modern AEAD + key agreement and the first cyrius-native-TLS
  crypto: Poly1305 / ChaCha20 / ChaCha20-Poly1305 / X25519,
  HMAC-/HKDF-SHA384, AES-128-GCM, EC + Ed25519 private-key parsers,
  ECDSA P-256/P-384 deterministic signing.
- **3.6 — cyrius-native-TLS arc (CLOSED at 3.6.8)** — parallel batch
  verify (dropped `_sigil_batch_mutex` via per-thread crypto banks,
  3.42×); TLS 1.2 PRF; the full RSA PKCS#1 v1.5 surface (verify +
  DER/PEM key parsing + sign) on a new general bignum/modexp engine,
  hardened with a constant-time Montgomery ladder, base blinding, CRT,
  and verify-after-sign; RSA-PSS; x509 RSA + P-384 chain-link verify;
  Montgomery-on-verify (3.43×); `pem_decode_privkey`→RSAK; AES-128 seal
  keys. Closed out at 3.6.8 (Closeout Pass + the overdue 3.5.6 audit
  doc + un-burying three hidden deferrals).

**Cyrius pin:** `6.0.58` (synced across `cyrius.cyml` and CI).

## v3.6.x — cyrius native-TLS arc (CLOSED at 3.6.8)

The cyrius native-TLS arc delivered sigil-side crypto one slot at a time
([`issues/2026-05-28-cyrius-tls-arc-full-audit.md`](issues/2026-05-28-cyrius-tls-arc-full-audit.md)).
**All items shipped (3.6.0–3.6.8)**: parallel verify, TLS 1.2 PRF, the
complete RSA PKCS#1 v1.5 + PSS surface, RSA + P-384 x509 chain-link,
Montgomery-on-verify, `pem_decode_privkey`→RSAK, AES-128 seal. The
per-item detail below is retained for history.

### 3.6.5+ — remaining items

- [x] **RSA-PSS** (MGF1) verify + sign, SHA-256/384 —
      `rsa_pss_{sign,verify}_sha{256,384}`. **Shipped 3.6.5.** The modern
      TLS 1.3 RSA signature scheme (`rsa_pss_rsae_*`); built on the
      bignum engine + the PKCS#1 v1.5 surface (shared `_rsa_recover_em`
      / `_rsa_raw_sign` cores). Per-bite audit:
      `docs/audit/2026-06-04-3.6.5-pss-x509-rsa-audit.md`.

- [x] **x509 RSA chain-link verify.** **Shipped 3.6.5.** RSA SPKI parse
      (`X509_CURVE_RSA`), rsa-with-SHA256/384 sig-algo dispatch, RSA
      issuer routing in `_x509_verify_link` → `rsa_pkcs1v15_verify_*`.
      (Was a Backlog item; pulled forward with the PSS bite.)

- [x] **Montgomery on the verify path + RSA benches.** **Shipped 3.6.6.**
      Switched the three public-exponent modexp sites (`_rsa_recover_em`
      RSAVP1 verify; `r^e` blinding; `s^e` verify-after-sign) from
      schoolbook `bn_modexp` to `bn_mont_modexp` — verify **3.43×**
      (11.68→3.40 ms). New `tests/bcyr/rsa.bcyr`; `history.csv` row
      `v3.6.6-rsa-montgomery` (verify + sign + CRT-vs-full-width). A
      review-found odd-modulus precondition was enforced at the verify
      boundary. (General Barrett/Montgomery for arbitrary public moduli
      remains a possible 3.7 perf item, not needed for RSA.)

- [x] **`pem_decode_privkey` → RSAK struct.** **Shipped 3.6.6.** The RSA
      branches now emit the RSAK struct into `key_out` when `key_max >=
      RSAK_SIZE` (one auto-detecting entry point; the `SIG_PRIVKEY_RSA`
      sentinel is now only the buffer-too-small signal). EC/Ed25519
      scalar contract unchanged.

- [ ] **cyrius-native-TLS closeout (last 3.6.x tag).** Full CLAUDE.md
      Closeout Pass over the whole 3.6.x delta. The overdue **3.5.6
      HMAC/HKDF-SHA384 audit doc** is **done** (3.6.5:
      `docs/audit/2026-06-04-3.5.6-hmac-hkdf-sha384-audit.md`). Closeout
      still owes the downstream-consumer check, dead-code + stale-comment
      sweep (incl. the `_into`-in-3.6 comment fix), security re-scan,
      clean-from-scratch build, and version verify.

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

3.7 **closed** the bump-allocator-lifetime LOW findings (3.7.3, audit
floor 8 → 0) and landed Solinas reduction for both curves (3.7.0/3.7.1). (The general bignum modexp from 3.6 could also gain
Barrett/Montgomery here — cross-reference the 3.6.5+ RSA bench item.)

### 3.7 work items

- [x] **Solinas reduction for P-256.** **Shipped 3.7.0.** Word-level
      reduction against `p256 = 2^256 − 2^224 + 2^192 + 2^96 − 1` (FIPS
      186-4 App. D / GECC Alg. 2.29): `_p256_solinas_reduce` replaces the
      bit-by-bit `_p256_long_div_reduce` (kept as the differential-KAT
      reference). `ecdsa_p256_verify` **147.5 → 26.1 ms (5.65×)** on
      6.0.61 (CSV row `v3.7.0-p256-solinas`). **The ≤ 10 ms target was
      NOT reached by reduction alone** — with the reduction fast, the
      schoolbook `u256_mul_full` and especially the double-and-add
      scalar multiplication now dominate. The ≤ 10 ms target carries to
      the new **EC scalar-mult speedup** item below.

- [ ] **EC scalar-mult speedup (carries the ≤ 10 ms target).** The
      `ecdsa_p256_verify` cost is now dominated by the two double-and-add
      scalar multiplications (`u1·G + u2·Q`, ~6000 field-muls). A
      fixed-base comb for `G` (like ed25519 already uses) + a wNAF /
      windowed ladder for the variable `Q`, and optionally a Karatsuba
      `u256_mul_full`, are the path to ≤ 10 ms. Distinct from the Solinas
      reduction (which is done). Cross-reference the "scatter-store for
      the fixed-base comb" backlog item (cache-timing) if the comb is
      adopted on a secret path.

- [x] **Solinas reduction for P-384.** **Shipped 3.7.1.** Same shape
      against `p384 = 2^384 − 2^128 − 2^96 + 2^32 − 1`; the 11-term
      layout was derived from the prime's folding relation and verified
      5000/5000 vs `x mod p` before coding (`_p384_reduce_longdiv` kept
      as the differential-KAT reference). `ecdsa_p384_verify` **339.2 →
      54.6 ms (6.21×)** (CSV row `v3.7.1-p384-solinas`, new
      `tests/bcyr/ecdsa_p384.bcyr`).

- [ ] **Solinas reduction for P-384.** Same shape against
      `p384 = 2^384 − 2^128 − 2^96 + 2^32 − 1`. The P-384
      Solinas decomposition is wider (more word-level
      shuffles) but the structure is identical. CSV row
      `v3.7-p384-solinas`.

- [x] **Unified `_into`-shape API.** **Shipped 3.7.3** —
      caller-provides-scratch (the chosen shape, matching the
      `sv_verify_artifact_into` / `pem_decode_certs_into` precedent).
      Added `x509_parse_into` / `x509_cert_alloc_into` +
      `sgx`/`tdx`/`snp` `*_verify_full_into`, drawing per-call scratch
      from a stdlib arena (`arena_new` / `arena_reset`). The original
      entries are byte-for-byte `arena==0` wrappers.
      **Investigation finding:** only 4 of the 8 floor LOWs were genuine
      per-call drift (`x509_parse` raw_sig + RSA block; the SGX/TDX/SNP
      orchestrator drift) — resolved here. The other 4 (`_snp_v_init`,
      `_sgxv_init`, `_tdxv_init`, `_pem_init` tables) are correct
      init-once singletons (CLAUDE.md quirk #2), reclassified, not
      churned. **Audit floor: 8 → 0.**

- [ ] **Re-run the full crypto bench suite.** Capture before /
      after rows for every verify-path bench. The ≤ 10 ms /
      verify ship target for `ecdsa_p256_verify` /
      `ecdsa_p384_verify` now depends on the **EC scalar-mult
      speedup** item above (Solinas reduction alone reached
      26 ms for P-256). SEV-SNP / TDX verify rows benefit
      transitively; cross-check the deltas are clean.

**Sequencing decision:** ~~open 3.7 only if a downstream consumer
surfaces a latency complaint~~ — **3.7 was opened 2026-06-04** (Robert's
call), starting with Solinas P-256 (3.7.0). The remaining items
(Solinas P-384, the EC scalar-mult speedup that carries ≤ 10 ms, the
unified `_into` API) sequence as 3.7.x tags.

## Backlog — unscheduled

Items with a clear shape but no forcing function. Land
in-place when an adjacent edit touches the relevant module.

- [ ] **Retire the per-thread bank-indexing workaround if cyrius
      grows native thread-local arrays.** The 3.6 bank scheme
      (`src/crypto_scratch.cyr`) exists only because `var X[N]` is a
      static function-scope global and cyrius TLS is slot-based (no
      `threadlocal var X[N]` qualifier). If a future cyrius lands a
      true stack-local / thread-local *array* qualifier, collapse the
      `[N*8]` banks back to plain `var X[N]` and drop the module.
      Check the cyrius language on each toolchain bump; adopt if the
      bank approach proves inadequate (e.g. the `.bss` growth becomes a
      real cost, or a consumer wants parallel *signing*, which would
      need the `secret var` paths banked too — unsafe under the current
      scope-exit-zeroizes-all-lanes shape).

- [x] **x509 chain-link verify for non-ECDSA-P256 issuers.** Both
      follow-ups are now shipped:
      - **P-384 chain-link verify** — **shipped 3.6.7.**
        `_x509_verify_link` dispatches `ecdsa-with-SHA384`
        (`X509_SIG_ECDSA_SHA384`, OID `06 08 2A 86 48 CE 3D 04 03 03`)
        to `ecdsa_p384_verify`; the sig-value parse selects field width
        32/48 via `_ecdsa_der_int_w`.
      - **RSA chain-link verify** — **shipped 3.6.5.**
        `_x509_verify_link` dispatches RSA-with-SHA256/384 issuers to
        `rsa_pkcs1v15_verify_*` (real AMD ARK/ASK are RSA-4096+SHA-384).

- [x] **AES-GCM arbitrary-length IVs.** **Shipped 3.7.2.**
      `_gcm_compute_j0` (`src/aes_gcm.cyr`) adds the SP 800-38D §7.1
      GHASH-based J0 for the `iv_len != 12` branch; new
      `aes_gcm_encrypt_iv` / `_decrypt_iv` + AES-128 variants take an
      `iv_len`. Interop-verified vs OpenSSL (AES-256/128 at 60/8/1-byte
      IVs; the 60-byte cases match McGrew-Viega TC6/TC18). The 8-arg
      96-bit entries stay byte-for-byte 12-byte wrappers (API-additive).
      *(Un-buried 3.6.5 from a stale `aes_gcm.cyr` comment; folded into
      the v3.7 arc.)*

- [x] **AES-128 seal keys.** **Shipped 3.6.7.** `sgx_derive_seal_key_n`
      / `sgx_seal_key_n` / `sgx_unseal_key_n` take a 16- or 32-byte width
      (`SGX_SEAL_KEY_SIZE_128` / `_256`); the original 7-arg fns stay
      byte-for-byte 256-bit wrappers. (Un-buried 3.6.5 from a `src/seal.cyr`
      comment that read "a future bite can parameterise".)

- [x] **Reconcile the stale "`_into` lands in 3.6" comments.** **Fixed
      3.6.8.** `src/sgx.cyr` and `src/tdx.cyr` now point at the gated v3.7
      `_into` cycle (not "3.6"); the stale `benches/sigil.bcyr` path in
      CLAUDE.md was corrected to `tests/bcyr/sigil.bcyr` in the same
      closeout sweep. *(Original note retained below for history.)*
      `src/sgx.cyr` and `src/tdx.cyr` both carried "closes when the unified
      `_into` API lands in 3.6" — but that work was moved to **v3.7**
      (see the perf cycle below). *Surfaced 2026-06-04; the comments were
      promising a version that shipped without the work.* Fix the comment
      text (or land the work) as part of the 3.7 `_into` cycle so the
      source stops claiming a closed-out 3.6 delivery.

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

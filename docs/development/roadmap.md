# Sigil Roadmap

Forward-looking work only. For shipped items and per-version detail
see [CHANGELOG.md](../../CHANGELOG.md).

## Outstanding work — full inventory

Every open item, in one place, so nothing hides in a lower section.
Detail for each is in its section below.

**3.6.x — cyrius native-TLS tail**
- [ ] RSA-PSS (MGF1) verify + sign, SHA-256/384
- [ ] Montgomery on the verify path + RSA verify/sign benches
- [ ] `pem_decode_privkey` → RSAK struct wiring
- [ ] cyrius-native-TLS closeout (Closeout Pass + deferred 3.5.6 HMAC/HKDF-SHA384 audit doc)

**v3.7 — perf (gated on a latency complaint)**
- [ ] Solinas reduction for P-256
- [ ] Solinas reduction for P-384
- [ ] Unified `_into`-shape API (closes the 7 open bump-allocator LOWs)
- [ ] Re-run full crypto bench suite

**Backlog — unscheduled**
- [ ] Retire the per-thread bank-indexing workaround if cyrius gains native thread-local arrays
- [ ] x509 P-384 chain-link verify (non-P256 issuers)
- [ ] x509 RSA chain-link verify (now unblocked — sigil has RSA verify)
- [ ] Scatter-store for the fixed-base comb (cache-timing)
- [ ] CLMUL-assisted GHASH (gated on cyrius asm pseudo)
- [ ] NI dispatch structural fix (gated on cyrius asm pseudo)

**Possible future surfaces (consumer-demand-gated)**
- [ ] ML-KEM-768 (PQC KEM)
- [ ] PQC-default builds (drop `-D SIGIL_PQC` when the preprocessor cap lifts)

**Open audit findings** — 7 LOW (bump-allocator lifetime), tracked in
`state.md` "Audit floor," cleared by the v3.7 `_into` work. Zero
CRITICAL / HIGH / MEDIUM outstanding.

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
- **3.6.0–3.6.4** — parallel batch verify (dropped `_sigil_batch_mutex`
  via per-thread crypto banks, 3.42×); TLS 1.2 PRF; the full RSA
  PKCS#1 v1.5 surface (verify + DER/PEM key parsing + sign) on a new
  general bignum/modexp engine, hardened with a constant-time
  Montgomery ladder, base blinding, CRT, and verify-after-sign.

**Cyrius pin:** `6.0.53` (synced across `cyrius.cyml` and CI).

## v3.6.x — cyrius native-TLS arc (in progress)

The cyrius native-TLS arc needs sigil-side crypto one slot at a time
([`issues/2026-05-28-cyrius-tls-arc-full-audit.md`](issues/2026-05-28-cyrius-tls-arc-full-audit.md)).
Shipped so far: parallel verify, the TLS 1.2 PRF, and the complete RSA
PKCS#1 v1.5 surface (see CHANGELOG / `state.md`). Remaining items
carry as **3.6.5+** tags.

### 3.6.5+ — remaining items

- [ ] **RSA-PSS** (MGF1) verify + sign, SHA-256/384 —
      `rsa_pss_{sign,verify}_sha{256,384}`. The modern TLS 1.3 RSA
      signature scheme (`rsa_pss_rsae_*`); builds on the shipped
      bignum engine + the PKCS#1 v1.5 surface. Per-bite audit covering
      MGF1, salt handling, and EMSA-PSS-Verify consistency. SHA-512-RSA
      stays backlog (rare in 1.3).

- [ ] **Montgomery on the verify path + RSA benches.** Switch the
      verify-side / public-exponent modexp from the schoolbook
      `bn_modexp` to `bn_mont_modexp` (no secret, so the residual
      timing paths are irrelevant), and add `benches/history.csv` rows
      for RSA verify and sign (CRT vs full-width). Optional general
      Barrett/Montgomery for the public path.

- [ ] **`pem_decode_privkey` → RSAK struct.** It currently returns the
      `SIG_PRIVKEY_RSA` sentinel; wire it to base64-decode the body and
      call `rsa_privkey_from_der`, emitting an RSAK struct. Needs a
      small API-shape decision — its EC/Ed25519 contract decodes into a
      single scalar buffer, whereas RSA needs the multi-field struct.

- [ ] **cyrius-native-TLS closeout (last 3.6.x tag).** Full CLAUDE.md
      Closeout Pass over the whole 3.6.x delta + the deferred
      **3.5.6 HMAC/HKDF-SHA384 audit doc**
      (`docs/audit/<date>-3.5.6-hmac-hkdf-sha384-audit.md`: constant-time
      review, buffer sizes, `secret var`/`memset` zeroization, the
      255×48 OKM cap). Includes the downstream-consumer check, dead-code
      + stale-comment sweep, security re-scan, clean-from-scratch build,
      and version verify.

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
both curves. (The general bignum modexp from 3.6 could also gain
Barrett/Montgomery here — cross-reference the 3.6.5+ RSA bench item.)

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
      - **RSA chain-link verify**: now *unblocked* — sigil has
        RSA PKCS#1 v1.5 verify (3.6.2). Wire `_x509_verify_link`
        to dispatch RSA-with-SHA256/384 issuers (real AMD ARK/ASK
        links are RSA-4096 + SHA-384) to `rsa_pkcs1v15_verify_*`
        once the cert parser tags RSA SPKIs + sig algorithms.
        Surfaces when a consumer integrates real AMD KDS chains
        end-to-end via sigil.

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

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

**Cyrius pin:** `6.0.14` (synced across `cyrius.cyml` and CI).

## Road to v3.5 — modern AEAD + key agreement primitives

The cyrius v6.2.x native-TLS arc (`lib/tls_native.cyr`, replacing
the `libssl`/fdlopen wrapper in `lib/tls.cyr`) needs pure-Cyrius
AEAD + key agreement for the kernel + sandhi consumers — a
bare-metal AGNOS kernel has no `libssl.so.3` to dlopen, so the
protocol layer must drive sigil-owned primitives. This cycle lands
the TLS 1.3 `ChaCha20-Poly1305 + X25519` suite. (AES-256-GCM +
ECDSA-P256/P384 + X.509 already ship in 3.4.x, so the AES suite is
already covered for the native stack.)

**Correction (carried from the backlog promotion):** the earlier
backlog note claimed "Poly1305 already ships." It does not — the
only `poly1305` reference in the tree was a descriptive comment in
`src/aes_gcm.cyr` (the GCM tag length). Both Poly1305 and ChaCha20
are greenfield in this cycle.

### 3.5 work items

- [x] **3.5.0 — Poly1305 one-time MAC (RFC 8439 §2.5).**
      *Shipped 2026-05-27.* Standalone authenticator in `src/poly1305.cyr`:
      `poly1305_mac(out, msg, msg_len, key)` over the 32-byte
      one-time key. **Ships ahead of the TLS arc** — a MAC
      primitive needs no forcing function. Implemented as the
      26-bit-limb (`poly1305-donna`) reduction so every
      intermediate product stays inside a signed i64 (no 128-bit
      path), with constant-time final reduction (mask-select, no
      branch on the key-derived accumulator). One-shot first;
      streaming `init`/`update`/`finish` deferred to the AEAD bite
      that needs it. Key caveat documented in the module header:
      **one-time key — never reuse across two messages.**

- [x] **ChaCha20 stream cipher (RFC 8439 §2.4).** *Shipped 3.5.1,
      2026-05-27.* `src/chacha20.cyr`: `chacha20_block` +
      `chacha20_xor`, 20-round ARX permutation + counter-mode
      keystream. RFC §2.3.2 / §2.4.2 vectors pass. Audit:
      `docs/audit/2026-05-27-3.5-arc-audit.md`.

- [x] **ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).** *Shipped 3.5.2,
      2026-05-27.* `src/chacha20poly1305.cyr`:
      derive the Poly1305 one-time key from the ChaCha20 keystream
      (counter 0), authenticate `AAD || pad16 || ciphertext ||
      pad16 || len(AAD)_le64 || len(ct)_le64`. Resolved the
      "streaming vs contiguous-buffer" choice in favour of a
      per-call `fl_alloc` mac-data buffer (correct allocator for
      per-call scratch; does not touch the bump-allocator audit
      floor). A streaming Poly1305 remains a future optimization
      for very large messages. RFC §2.8.2 vector passes.

- [x] **X25519 key agreement (RFC 7748).** *Shipped 3.5.3,
      2026-05-27.* `src/x25519.cyr`: Montgomery-ladder ECDH reusing
      the Curve25519 field arithmetic in `src/bigint_ext.cyr`
      (`fp_add/sub/mul`, mod 2^255−19); clamped scalar × base/peer
      point → shared secret. RFC §5.2 + §6.1 vectors pass. Audit:
      `docs/audit/2026-05-27-3.5-arc-audit.md`.

**Sequencing decision (closed):** Poly1305 (3.5.0) shipped as a
self-contained primitive; ChaCha20 (3.5.1), the AEAD (3.5.2), and
X25519 (3.5.3) followed in the same cycle on the maintainer's
go-ahead (the native-TLS forcing function was treated as firm).
The TLS 1.3 `ChaCha20-Poly1305 + X25519` suite is now
feature-complete and shipped in sigil. **3.5.4 closeout (shipped
2026-05-27)** ran the CLAUDE.md Closeout Pass (full suite + bench,
dead-code audit, stale-comment sweep, security re-scan, downstream
check, doc sync, clean build) and consolidated the four per-bite
audits into `docs/audit/2026-05-27-3.5-arc-audit.md`. The 3.5 cycle
is closed; next minor is 3.6 (parallel verify), then 3.7 (perf).

**3.5.6 — HMAC-SHA384 + HKDF-SHA384 (shipped 2026-05-28).** A
post-closeout forcing-function patch: the cyrius native-TLS arc held
its v6.0.13 (Mini-arc A.4, TLS 1.3 key schedule) because the
`TLS_AES_256_GCM_SHA384` (0x1302) ciphersuite drives its RFC 8446
§7.1 key schedule off HKDF-SHA384, which sigil had not yet exposed
(only the SHA-256 variants). Added `hmac_sha384` (`src/hmac_sha384.cyr`)
+ `hkdf_extract_sha384` / `hkdf_expand_sha384` / `hkdf_sha384`
(`src/hkdf_sha384.cyr`) — pure additive surface, RFC 4231 §4 + 3
cross-verified HKDF vectors (+19 assertions). Toolchain pin bumped
6.0.3 → 6.0.12. Resolves
`docs/development/issues/2026-05-28-cyrius-tls-native-needs-hkdf-sha384.md`.

## Planned — v3.5.7 → v3.5.12 (cyrius native-TLS arc support)

The 3.5.6 HKDF-SHA384 ship closed the **first** cyrius native-TLS
forcing function. A follow-on filing —
[`issues/2026-05-28-cyrius-tls-arc-full-audit.md`](issues/2026-05-28-cyrius-tls-arc-full-audit.md)
— cross-walks the **remaining** sigil-side gaps the cyrius arc hits
one slot at a time across cyrius v6.0.14 → .34. Rather than file each
at its forcing slot (the per-slot-piecemeal pattern the issue itself
calls out), sigil schedules the five line items as separate, ordered
3.5.x bites; cyrius bumps its pin and resumes the held slot at each
tag.

The five items are independent and additive (existing-shape surface,
**except RSA** — line item 2 — which needs a general bignum modexp
engine sigil does not have yet; `src/bigint_ext.cyr` is Curve25519
field arithmetic mod 2²⁵⁵−19 only, not a general RSA modulus engine.
See the 3.5.10 note). They are sequenced by (a) cyrius
forcing-function order and (b) internal dependency — the private-key
parsers (3.5.8) land **before** the sign paths (3.5.9/3.5.10) that
consume their opaque handles.

**Each crypto bite carries its own per-bite security audit doc**
(`docs/audit/YYYY-MM-DD-*.md`, Work Loop step 7). The cycle-wide
**Closeout Pass is held as the last 3.5.x tag (3.5.12)** — it ships
only after every other item lands, and is the last patch of the 3.5
minor before 3.6 (parallel verify) opens. The 3.5.5/3.5.6 retro-audit
+ bench + doc-health items (previously scoped to a standalone 3.5.7)
fold into that final closeout's delta.

> **Catch-all slot:** if cyrius (or any consumer) surfaces another
> small additive/repair need against the modern-crypto surface before
> 3.6 opens, fold it into the nearest unshipped bite or insert a new
> 3.5.x slot **ahead of** the closeout — never after it. Promote to
> 3.6 only when the parallel-verify forcing function is firm.

### 3.5.7 — AES-128-GCM (issue line item 1)

- [ ] **`aes_128_key_expand` / `aes_128_gcm_encrypt` /
      `aes_128_gcm_decrypt`.** `TLS_AES_128_GCM_SHA256` (0x1301) is
      the RFC 8446 §9.1 **mandatory** TLS 1.3 ciphersuite; also
      unblocks the four `TLS_*_WITH_AES_128_GCM_SHA256` 1.2 suites.
      AES-128 differs from AES-256 only in the key schedule (10
      rounds / 176-byte round-key table vs 14 / 240); the block
      encrypt/decrypt walk the table by round count and are shared.
      16-byte block in both variants. Mirrors the existing
      AES-256-GCM surface byte-for-byte. Per-bite audit doc + bench
      rows (`benches/sigil.bcyr`, `history.csv` row `v3.5.7-aes128-gcm`).
      **Cyrius forcing slot:** v6.0.14 (Mini-arc A.5, ciphersuite
      negotiation — ships 2/3 suites without it).

### 3.5.8 — Private-key parsers, PEM + DER (issue line item 4)

- [ ] **`rsa_privkey_from_der` (PKCS#1 / PKCS#8),
      `ecdsa_p256_privkey_from_der` / `ecdsa_p384_privkey_from_der`
      (SEC1 / PKCS#8), `ed25519_privkey_from_der` (PKCS#8 / RFC 8410),
      `pem_decode_privkey` (auto-detect algo from header).** Produces
      opaque private-key handles the 3.5.9/3.5.10 sign fns accept.
      Reuses the existing `der_walk` / `der_skip` + `pem_decode_certs`
      shapes. Needed before any server-side key can come online
      (`tls_native_new_server(cert_chain, …, key, key_len)`). Both
      PEM (Let's Encrypt + CA tooling) and raw DER (embedded) paths
      required. `secret var` on all parsed key material; per-bite
      audit doc. **Cyrius forcing slots:** v6.0.15 (client cert,
      optional) / v6.0.23 (server state machine — load cert + key).

### 3.5.9 — ECDSA P-256 + P-384 sign (issue line item 3)

- [ ] **`ecdsa_p256_sign` / `_der`, `ecdsa_p384_sign` / `_der`.**
      Deterministic-k (RFC 6979) for side-channel hygiene; raw
      `r||s` (64 / 96 byte) + DER-encoded forms. TLS 1.3
      CertificateVerify uses the DER form. cyrius hashes the
      transcript with `sha256`/`sha384` before calling sign. Consumes
      the ECDSA handles from 3.5.8; pairs with the existing
      `ecdsa_p256_verify` / `ecdsa_p384_verify`. Constant-time review
      of the nonce path is the load-bearing audit item; per-bite
      audit doc + bench rows. **Cyrius forcing slots:** v6.0.17
      (CertificateVerify path) / v6.0.25 (server ServerHello + key
      share).

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
      `3.5.10` general big-integer modexp engine + PKCS#1 v1.5 verify
      (the most interop-load-bearing path), then `3.5.10a/.11`-shaped
      follow-ons for PSS (MGF1) + the sign paths. Each sub-bite gets
      its own audit doc (Montgomery/modexp constant-time, padding
      oracle hygiene on verify, blinding on sign). Consumes the RSA
      handle from 3.5.8. **Cyrius forcing slots:** v6.0.17 / v6.0.25
      (verify + sign for CertificateVerify) and v6.0.29–.34 (1.2 RSA
      suites).

### 3.5.11 — TLS 1.2 PRF (issue line item 5, optional)

- [ ] **`tls12_prf_sha256` / `tls12_prf_sha384` — ship-or-decline
      decision.** TLS 1.2's key schedule is `P_hash(secret, label ||
      seed)` with `A(i+1) = HMAC_hash(secret, A(i))` — buildable from
      the existing `hmac_sha256` / `hmac_sha384` in ~15-20 LoC.
      **Not blocking:** cyrius keeps it inline in `tls_native.cyr` if
      sigil declines. Decide ship-vs-decline (ship favours symmetry
      with the HKDF surface; decline keeps the protocol-only/crypto
      boundary clean — cf. [[feedback_tls_protocol_stays_in_cyrius]]);
      **flag the choice to cyrius either way** so its wrapper knows
      which path. If shipped: per-bite audit doc + RFC 5246 §5 / RFC
      7627 vectors. **Cyrius forcing slots:** v6.0.29–.34 (1.2
      backport).

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

## Road to v3.6 — caller-provided scratch for parallel verify

Drop `_sigil_batch_mutex` by threading caller-provided scratch
through every crypto primitive. The 3.3 cleanup cycle confirmed
that in-function `var X[N]` declarations are **static
function-scope globals**, not per-call stack arrays (see
`tests/tcyr/var_array_semantics.tcyr` and the CHANGELOG 3.3.0
entry); concurrent workers therefore race on shared module state
unless scratch is threaded through explicitly.

### 3.6 work items

- [ ] **Caller-provided crypto scratch.** Top-level entry
      points (`sha256`, `sha512`, `ed25519_verify`,
      `ed25519_sign`, `aes_gcm_encrypt`, `aes_gcm_decrypt`,
      `hash_file_into`) gain a scratch-buffer parameter
      sized to the deepest call-chain working-set (rough
      estimate ~3 KB per concurrent caller). Each function
      slices its working buffers out of the scratch by
      documented offset; the offset layout lives in a header
      comment in each module.

- [ ] **Thread scratch through the call chain.** Every
      `fp_mul`, `fp_pow`, `fp_inv`, `u512_mod_p`,
      `u256_mul_full`, `ge_add`, `ge_double`,
      `ge_scalarmult`, `ge_scalarmult_base`,
      `_ge_table_select`, `sha256_transform`,
      `sha512_transform`, `sc_reduce`, `sc_muladd` signature
      gains a scratch parameter. This is mechanical but
      invasive — each fn signature changes, each caller
      updates.

- [ ] **Per-worker scratch pool in `sv_verify_batch`.**
      Pre-allocate `workers * CRYPTO_SCRATCH_SIZE` bytes on
      the main thread before fan-out, same shape as the
      existing `count * _VSC_SIZE` artifact-scratch pool.
      Pass the per-worker scratch pointer to `_batch_worker`
      via the args struct.

- [ ] **Drop `_sigil_batch_mutex`.** Run
      `batch_parallel.tcyr` mutex-off — must stay 228/228.
      Re-bench `sv_verify_batch_64` against the
      `v3.2.0-allocfree` baseline (422.867 ms @ 64
      artifacts). Target ≥ 3× at 4 workers. Add CSV row
      `v3.6-parallel-crypto`.

- [ ] **Inverse pass on the 3.3 in-function arrays.** Every
      `var X[N]` added in 3.3 becomes either a slice of the
      scratch buffer or, where the array is truly read-only
      after init, lifts back to a module global. The 3.3
      form had no functional advantage over named globals
      under concurrent access; 3.4 closes the loop.

**Sequencing decision:** open 3.6 when there's a forcing
function — a downstream consumer hitting the serialised batch
on the mutex's lock contention, or an AGNOS roadmap milestone
that requires the parallel speedup. The refactor is invasive
enough that it should be done in one focused sprint, not
incrementally.

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

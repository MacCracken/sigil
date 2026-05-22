# Sigil Roadmap

Forward-looking work only. For shipped items and version history
see [CHANGELOG.md](../../CHANGELOG.md). Closed cycles:

- [`3.2-tee-arc.md`](3.2-tee-arc.md) — 3.2.x TEE attestation
  sub-arc, complete 2026-05-21 → 2026-05-26 (6 bites: ECDSA →
  X.509 → SGX → SEV-SNP → TDX → SGX seal).
- [`3.2-scope.md`](3.2-scope.md) — 3.2.0 cycle history.
- [`3.0-scope.md`](3.0-scope.md) — 3.0 cycle history.
- **3.4 — TEE attestation completion** (shipped 2026-05-22). PEM
  decoder + `sgx_quote_verify_full` + `tdx_quote_verify_full` +
  TDX `att_key_type=3` (P-384/SHA-384) dispatch. Deferred:
  `snp_report_verify_full` (carries the AMD VCEK P-384 SPKI
  blocker — see "Backlog" below). See CHANGELOG 3.4.0 entry for
  the full ship summary; `docs/audit/2026-05-22-3.4.0-audit.md`
  for the audit pass.

**Cyrius pin:** `6.0.1` (synced across `cyrius.cyml` and CI).

## Road to v3.5 — caller-provided scratch for parallel verify

(Renumbered from "Road to v3.4" when 3.4 shipped TEE completion
ahead of the parallel-verify work. Content unchanged.)

3.3 attempted to lift per-call working state out of module
globals so the `_sigil_batch_mutex` could drop. The
implementation swapped explicit named globals (`_sha_a..h`,
`_sha256_W`, `_ga_*`, `_fpi_*`, etc.) for in-function
`var X[N]` array declarations under the hypothesis (drawn
from CLAUDE.md quirk #1's prior wording) that cycc 6 had
fixed local clobbering and these would be per-call stack
arrays.

The hypothesis was wrong. Cyrius's `parse_fn.cyr:2886`
("DON'T restore VCNT — arrays inside functions are globals
that persist") and the probe at
`tests/tcyr/var_array_semantics.tcyr` establish that **array
declarations inside a function are static function-scope
globals**, not stack arrays. Storage is unchanged from the
3.2.x named-global form; concurrent workers still race.
Scalar `var x = ...` locals ARE per-call (the scalar
clobbering quirk that motivated the cc3-era globals is gone
under cc6 — that part of the refactor stuck).

The 3.3 ship therefore kept the batch mutex and shipped as a
cleanup/refactor: -190 LOC net across `sha256.cyr`,
`sha512.cyr`, `ed25519.cyr`, `aes_gcm.cyr`, `bigint_ext.cyr`,
`sha_ni.cyr`, `verify.cyr`. The proper mutex-drop architecture
is queued here.

### 3.5 work items (renumbered from 3.4)

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
      `v3.5-parallel-crypto`.

- [ ] **Inverse pass on the 3.3 in-function arrays.** Every
      `var X[N]` added in 3.3 becomes either a slice of the
      scratch buffer or, where the array is truly read-only
      after init, lifts back to a module global. The 3.3
      form had no functional advantage over named globals
      under concurrent access; 3.4 closes the loop.

**Sequencing decision:** open 3.5 when there's a forcing
function — a downstream consumer hitting the serialised batch
on the mutex's lock contention, or an AGNOS roadmap milestone
that requires the parallel speedup. The refactor is invasive
enough that it should be done in one focused sprint, not
incrementally.

## Road to v3.6 — perf tuning: field arithmetic + alloc-free

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

3.6 closes the bump-allocator-lifetime LOW findings (now six
across the 3.2.x + 3.4 cycles) and lands Solinas reduction for
both curves.

### 3.6 work items

- [ ] **Solinas reduction for P-256.** Word-level reduction
      against `p256 = 2^256 − 2^224 + 2^192 + 2^96 − 1` per
      FIPS 186-4 Appendix D / NIST SP 800-186. Replace
      `_p256_long_div_reduce` with the new pipeline.
      Re-bench against the `v3.2.1` baseline; target ≤ 10 ms
      / verify. CSV row `v3.6-p256-solinas`.

- [ ] **Solinas reduction for P-384.** Same shape against
      `p384 = 2^384 − 2^128 − 2^96 + 2^32 − 1`. The P-384
      Solinas decomposition is wider (more word-level
      shuffles) but the structure is identical. CSV row
      `v3.6-p384-solinas`.

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
      patterns. Closes six LOWs across the 3.2.2, 3.2.4, and
      3.4 cycles.

- [ ] **Re-run the full crypto bench suite.** Capture before /
      after rows for every verify-path bench. The 3.6 ship
      target: `ecdsa_p256_verify` and `ecdsa_p384_verify`
      both ≤ 10 ms / verify on the dev host. SEV-SNP / TDX
      verify rows benefit transitively from the P-256 /
      P-384 speedup; cross-check the deltas are clean.

**Sequencing decision:** open 3.6 only if a downstream
consumer surfaces a latency complaint (kavach's batch-
attestation flow, ark's signature-heavy publisher workflow).
Until then, the verify path is fast enough for one-shot
checks. Cache the open audit follow-ups via this cycle's
INFO docs.

## Backlog — unscheduled

Items with a clear shape but no forcing function. Land
in-place when an adjacent edit touches the relevant module.

- [ ] **`snp_report_verify_full` + x509 P-384 SPKI extraction.**
      Deferred from 3.4. Sigil's x509 parser is P-256-only —
      `_xp_parse_spki` accepts only `id-ecPublicKey +
      prime256v1` and stores a 64-byte pubkey at cert offset
      +96. AMD's real VCEK leaf cert is P-384 (96-byte pubkey),
      which `snp_report_verify` needs. Closure requires:
      (a) parse `secp384r1` (OID `1.3.132.0.34`) in
      `_xp_parse_spki` and BIT-STRING-decode the 97-byte
      uncompressed point; (b) track pubkey width per cert
      (struct slot + accessor `x509_cert_pubkey_len`);
      (c) dispatch `_x509_verify_link` on the issuer's pubkey
      width (still requires the issuer cert to be P-256 for
      ECDSA-SHA256 chain signatures — RSA-signed ARK/ASK links
      are a separate scope item). Then a thin
      `snp_report_verify_full(report, vcek_chain_pem,
      vcek_chain_pem_len, ark_root_der, ark_root_der_len,
      now_unix)` wrapper. Test fixture requires regenerating
      a P-384-leaf test chain via openssl.

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

- [ ] **`secret var` ambient adoption.** ~20 `memset(..., 0,
      ...)` sites across `src/hkdf.cyr` / `src/aes_gcm.cyr` /
      `src/mldsa.cyr` (counted post-3.0 merge); roughly 8 are
      true private-key / PRK / round-key / GHASH-state
      buffers, the rest intermediate scratch. `secret var`
      (cyrius 5.3.5) gives compiler-guaranteed zeroization.
      Land in-place when a future edit touches one of those
      call sites — no separate pass.

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

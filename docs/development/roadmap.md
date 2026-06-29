# Sigil Roadmap

Forward-looking work only. For shipped items and per-version detail see
[CHANGELOG.md](../../CHANGELOG.md) and [state.md](state.md) ("Recently
shipped").

## Outstanding work

The only open items. The 3.6 cyrius-native-TLS arc and most of the v3.7
perf cycle have shipped — see "Closed cycles" below + CHANGELOG.

> **3.8.0 — opened 2026-06-16 (housekeeping bookend to 3.7.x).** The
> `docs/development/issues/` folder is now **CLEAR** (all 12 archived): the
> Windows-entropy issue was archived after **wine/ProcessPrng runtime
> verification** (sigil-side done; `cass` + cyrius `tls_native` residual tracked
> below). 3.8.0 ships the **ChaCha20 + X25519 parallel-path banking** (the one
> real buildable Backlog item, now done + race-tested) and a **backlog-accuracy
> sweep**: the TDX/SGX in-quote PCK walk was found already-shipped (stale note →
> marked DONE), `bn_modexp` resolved (KEEP as the modexp test-oracle), and the
> scatter-store comb re-scoped as MOOT/parked (it guards a public value). The
> **3.7.x EC-squeeze perf cycle is closed** — all levers shipped, ≤ 10 ms not
> reached (~10.9 ms floor); the target was **closed 2026-06-16 as
> "not reachable with current approaches"** (ADR 0006), with exotic levers parked
> to Backlog (not a current priority).

**Thread-safety follow-up (🔴 HIGH)**

- [x] **Concurrent TLS handshakes race sigil's crypto scratch → server crash.**
      ✅ **DONE (3.9.6).** Root cause was two-fold: the per-worker banks existed
      but only the batch-verify path ever activated them (concurrent TLS workers
      all collided on bank 0), and the handshake/AEAD primitives the TLS 1.3 key
      schedule drives were unbanked or used non-thread-safe `fl_alloc`. Fixed by
      making `cbank()` **auto-assign** a per-thread lane (no consumer cooperation)
      + banking HKDF/HMAC/`ed25519_sign`/one-shot-SHA-2/`sha384_finalize`/the full
      AES-GCM AEAD path + ChaCha20-Poly1305/Poly1305, and CAS-guarding the NI
      self-test. `SIGIL_CRYPTO_BANKS` 8→64. New race-detector
      `tests/tcyr/concurrent_tls_handshake.tcyr` (16 auto-banked workers, stable
      30/30). [ADR 0007](../adr/0007-auto-banking-for-concurrent-tls.md); audit
      [`2026-06-29-3.9.6-…-banking`](../audit/2026-06-29-3.9.6-concurrent-tls-handshake-banking-audit.md).
      Issue:
      [`…concurrent-tls-handshake-global-scratch-race`](issues/2026-06-28-concurrent-tls-handshake-global-scratch-race.md).

**Thread-safety follow-up → 3.9.7 ✅ DONE (3.9.7)**

The 3.9.6 fix covered the reproduced crash path (Ed25519-cert + both AEAD suites'
handshake/record crypto). 3.9.7 banked every remaining unbanked concurrent site,
so **every reachable concurrent crypto path is now race-free**:

- [x] **ChaCha20-Poly1305 `_cp_tag` `fl_alloc` mac_data buffer**
      (`src/chacha20poly1305.cyr`). ✅ **DONE (3.9.7).** Added a streaming
      Poly1305 (`poly1305_init`/`update`/`finalize`); `_cp_tag` streams the
      RFC 8439 §2.8 segments in place — the last concurrent-path `fl_alloc` is
      gone. AEAD encrypt marginally faster.
- [x] **ECDSA P-256/P-384 sign+verify banking** (`src/ecdsa_p256.cyr`,
      `src/ecdsa_p384.cyr`, `src/ecdsa_sign.cyr`). ✅ **DONE (3.9.7).** ~150
      scratch buffers lane-sliced + the RFC 6979 DRBG + the per-sign `k·G` + the
      sign secret scratch banked; P-384's `_p384_mul64` return slots restructured;
      `ecdsa_p256_warm()`/`ecdsa_p384_warm()` main-thread prewarm added.
      **Also fixed a latent race in the DER wrappers** (`*_sign_der`/`verify_der`):
      `secret var` ARRAYS are shared statics (proven by probe), so the TLS
      CertificateVerify path was racing — now banked.
- [x] **`bignum` + `tls12_prf` (+ `rsa`) statics** (`src/bignum.cyr`,
      `src/tls12_prf.cyr`, `src/rsa.cyr`). ✅ **DONE (3.9.7).** Banked the
      Montgomery modexp scratch, the `_mul64` output locals, the RSA verify/sign/
      blind/CRT workspaces, and the P_hash PRF buffers; **closed a pre-existing
      RSA-sign secret-residue gap**. Off the TLS 1.3 path — done for completeness.

**Verification follow-up**

- [ ] **Windows entropy (3.7.15) — `cass` acceptance + cyrius `tls_native`
      re-fold.** sigil-side is **DONE and runtime-verified**: cross-compiled to
      Windows PE (`cyrius build --win`) and run under wine (ProcessPrng) —
      `random.tcyr`, `ed25519.tcyr`, and `programs/win_entropy_probe.cyr` (the
      consumer `dist` + opt-in-libs shape) all exit 0 with fresh, unique entropy +
      a working ed25519 keygen; the same probe is green on Linux. Residual is **NOT
      sigil source work**: a real-Windows (`cass`) confirmation run, and the
      cyrius-owned `tls_native` client-nonce half (re-fold `lib/sigil.cyr` +
      re-verify the native-TLS handshake). Archived issue:
      [`…windows-entropy…`](issues/archive/2026-06-15-sigil-windows-entropy-not-via-getrandom.md).

**Decomposition follow-up (post-3.8.1)**

- [x] **(P2) Promote the trust API to first-class in `dist/sigil.cyr`.** ✅ **DONE (3.9.0).**
      3.8.1 internalized the trust primitives (`certpin`/`tpm`/`ima`/`secureboot` `*_core`
      + `dmverity`/`luks` + `sys_error`/`sys_util`/`sysinfo`) and dropped
      `[deps.agnosys]`, clearing the blocker that kept the wrappers out of the dist
      bundle. 3.9.0 adds all 13 modules (3 support + 6 cores + 4 wrappers) to the
      `[lib]` list and the `scripts/regen-dist.sh` `MODULES` list (both in
      `src/lib.cyr` src-include order: support+cores before `types`, wrappers after
      `audit` before `verify`). Result: **105 trust fns** now in `dist/sigil.cyr`
      (`tpm_seal`/`tpm_unseal`/`tpm_detect`/`tpm_verify_measured_boot`, IMA,
      SecureBoot, cert-pin, `dmverity_verify`, `luks_format`). Verified: **no
      duplicate-fn definitions**, bundle compiles clean (`tpm_detect` resolves from
      the dist), self-containment intact, full suite green (1475/0). **Unblocks the
      downstream tpm rewire** (libro/kybernet) — see the decomposition plan.
- [ ] **Retire the interim `src/sysinfo.cyr` (uname)** when the sysinfo value-add
      lands in cyrius's syscall layer (decomposition decision 1) — switch
      `secureboot_core` to cyrius's portable uname. Part of the `agnosys → agnodrm`
      decomposition (plan: `agnosys/docs/development/2026-06-18-agnosys-to-agnodrm-decomposition-plan.md`).

**Backlog — gated / parked** (open, but not actionable until the gate lifts)

- [ ] **EC scalar-mult sub-10 ms via an exotic lever** — *possible future,
      **not a current priority.*** The ≤ 10 ms P-256 verify target was **closed
      2026-06-16 as "not reachable with current approaches"** (option A, ADR 0006):
      all portable levers shipped across 3.7.8–3.7.17 took `ecdsa_p256_verify`
      24.7 → **~10.9 ms** (~2.3×), but the verify is doubling/inversion-bound and
      Karatsuba caps at ~3–4%, so crossing 10 ms needs an exotic lever — a
      hand-written asm multiply (gated on the upstream cyrius `asm`-block
      global-symbol pseudo), a batched-affine GLV endomorphism, or a redesigned
      doubling, none scoped. **Revisit only if a consumer surfaces a hard latency
      requirement.** Lever analysis preserved in
      [ADR 0006](../adr/0006-park-ec-scalarmul-10ms-target.md) + the 3.7
      closed-cycle summary.

- [ ] **Switch hand-rolled JSON serializers to `#derive(Serialize)`** once
      cyrius's `#derive(Serialize)` supports cstring-pointer fields.
      `certpin_info_to_json` (`src/certpin_core.cyr`) is hand-rolled *only*
      because the derive macro cannot yet emit cstring-pointer fields; drop the
      hand-rolled path and re-`#derive` the type when the toolchain gains it.
      Gated on cyrius. Re-check on each toolchain bump.

- [ ] **Retire the per-thread bank-indexing workaround** if cyrius gains
      a native thread-local *array* qualifier (`threadlocal var X[N]`).
      The 3.6 bank scheme (`src/crypto_scratch.cyr`) exists only because
      `var X[N]` is a static function-scope global and cyrius TLS is
      slot-based. If a true thread-local array qualifier lands, collapse
      the `[N*8]` banks back to `var X[N]` and drop the module. Check on
      each toolchain bump. *(6.0.62 added real per-thread TLS slots — not
      arrays — so this stays gated.)*

- [ ] **Scatter-store for the fixed-base comb** (cache-timing) — **parked;
      currently MOOT.** Would distribute the comb's affine entries (64 B since
      3.7.16, not the old 128) across cache lines so a same-host attacker can't
      recover the selected nibble. But `p256_scalarmul_base` only ever processes
      the **public** scalar `u1 = e·s⁻¹` (verify data); the secret signing nonce
      stays on the CT ladder `pt_scalarmul` and never touches the comb — so this
      protects an already-public value. Becomes relevant only if a secret scalar
      ever reaches the comb AND the deployment goes multi-tenant (neither holds
      for AGNOS). Kept parked, not dropped.

- [ ] **CLMUL-assisted GHASH** — gated on the cyrius `asm`-block
      global-symbol pseudo (filed upstream:
      [`asm-block-global-symbol-pseudo`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md)).
      AES-GCM 1 KB sits ~700 µs after AES-NI; GHASH (bit-by-bit
      GF(2^128) multiply) now dominates. PCLMULQDQ/VPCLMULQDQ closes the
      gap, same byte-encoding pattern as the SHA-NI/AES-NI dispatchers.

**Possible future surfaces** (consumer-demand-gated)

- [ ] **ML-KEM-768** (PQC KEM) — belongs in a sibling `kem.cyr` if an
      AGNOS consumer needs key agreement. (ML-DSA-65 PQC sign ships
      default-on since 3.7.6.)

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
  [`issues/archive/2026-05-28-cyrius-tls-arc-full-audit.md`](issues/archive/2026-05-28-cyrius-tls-arc-full-audit.md)
  (all five line items delivered).
- **3.7 — perf + x509 (CLOSED at 3.7.17)** — Solinas reduction for P-256
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
  `ecdsa_p384_verify` 54.6 → 26.3 ms (2.08×) (3.7.8); the **attestation
  cert-pointer-array byte-vs-slot OOB fix** + pin → 6.2.1 + `json`/`bigint`→`bayan`
  (3.7.13); a toolchain/dependency refresh, pin → 6.2.11 (3.7.14); the
  **Windows-entropy single-boundary fix** — all keygen/nonce/blinding (6 sites,
  incl. AGNOS-only `tpm_random`) routed through `_sigil_random_fill` / stdlib
  `random_bytes`, fail-closed, pin → 6.2.12 (3.7.15); and the **EC-squeeze levers**
  — inversion addition-chains + affine-comb mixed-add (3.7.16) and the `u2·Q`-window
  batch-inversion mixed-add + **Karatsuba `u256_mul_full`** (3.7.17), taking
  `ecdsa_p256_verify` 12.50 → **~10.9 ms** (~13% cumulative). **≤ 10 ms not reached
  (~10.9 ms floor; closed 2026-06-16 as not-reachable-with-current-approaches —
  ADR 0006; exotic levers parked to Backlog).** The buried-deferral gate is done
  (cyrlint-native) and the full bench re-run was captured at the 3.8.0 close; the
  Windows `cass` acceptance + cyrius `tls_native` re-fold are the only residual
  (verification-only, tracked in Outstanding).
- **3.8 — OPEN (housekeeping bookend to 3.7.x).** ChaCha20 + X25519 per-worker
  banking (race-validated; plain `var` + per-lane wipe, not `secret var`); a
  backlog-accuracy sweep (TDX/SGX in-quote PCK walk found already-shipped;
  `bn_modexp` kept as the modexp test-oracle; scatter-store re-scoped MOOT/parked);
  the Windows-entropy issue archived after wine/ProcessPrng runtime verification;
  the issues folder cleared (all 12 archived). See CHANGELOG `[3.8.0]`.

**Cyrius pin:** `6.2.12` (synced across `cyrius.cyml` and CI).

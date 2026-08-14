# Sigil Roadmap

Forward-looking work only. For shipped items and per-version detail see
[CHANGELOG.md](../../CHANGELOG.md) and [state.md](state.md) ("Recently
shipped").

## Outstanding work

The only open items — all parked / gated or verification-only. The 3.6 TLS arc,
the 3.7 perf cycle, and the 3.8 / 3.9 thread-safety + decomposition cycles have
all shipped — see "Closed cycles" below + [CHANGELOG](../../CHANGELOG.md).
**As of 3.9.7 every reachable concurrent crypto path is race-free**
([ADR 0007](../adr/0007-auto-banking-for-concurrent-tls.md)) — the
concurrent-TLS-handshake crash (3.9.6) and the full thread-safety banking (3.9.7)
are done; see the **3.9** closed-cycle entry below.

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

**Decomposition follow-up (post-3.8.1)** — the (P2) trust-API-in-`dist` item
**shipped at 3.9.0** (105 trust fns now bundled; see the 3.9 closed-cycle entry).

- [ ] **Retire the interim `src/sysinfo.cyr` (uname)** when the sysinfo value-add
      lands in cyrius's syscall layer (decomposition decision 1) — switch
      `secureboot_core` to cyrius's portable uname. Part of the `agnosys → agnodrm`
      decomposition (plan: `agnosys/docs/development/2026-06-18-agnosys-to-agnodrm-decomposition-plan.md`).

**Backlog — gated / parked** (open, but not actionable until the gate lifts)

- [ ] **EC scalar-mult ≤ 10 ms — DECISION NEEDED: the target is now met.**
      **Changed at 3.12.2 and awaiting the maintainer's call.** ADR 0006 closed this
      2026-06-16 as "not reachable with current approaches", naming a hand-written
      asm multiply as an exotic lever *"gated on the upstream cyrius `asm`-block
      global-symbol pseudo"*. **That gate turned out not to exist** for a leaf
      function — `param_load` + raw opcode bytes is enough, and a plain `MUL r/m64`
      needs neither MULX nor ADX. 3.12.2 shipped it (`src/mul64.cyr`) and
      `ecdsa_p256_verify` measures **9.732 ms**, against 10.539 ms on the same host
      at the same pin — **below the 10 ms target**.
      **ADR 0006 was deliberately NOT closed by that**: the crossing is narrow
      (~7 %) and single-host, and the disposition was the maintainer's decision, so it
      should not be inherited from a performance side-effect. Open question is
      therefore: *declare the target met, re-measure on a second host first, or
      set a new one?* See [ADR 0008](../adr/0008-native-asm-multiply-and-public-modexp.md).
      Remaining unexplored levers if a new target is set: a full `asm{}` CIOS inner
      loop, a batched-affine GLV endomorphism, or a redesigned doubling.

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

- [ ] **CLMUL-assisted GHASH** — **the gate is weaker than recorded; re-scope.**
      This was parked as "gated on the cyrius `asm`-block global-symbol pseudo"
      ([filed upstream](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md)).
      3.12.2's `src/mul64.cyr` showed a leaf `asm{}` block needs no such pseudo, so
      the question is now whether *GHASH specifically* needs global-symbol access
      (it may, for a precomputed H-table — unlike a leaf multiply, which needs
      none). Not yet investigated. AES-GCM 1 KB still sits ~690 µs after AES-NI,
      with GHASH (bit-by-bit GF(2^128) multiply) dominating; PCLMULQDQ/VPCLMULQDQ
      closes the gap, same byte-encoding pattern as the SHA-NI/AES-NI dispatchers.
      **Unlike the multiply, PCLMULQDQ IS an optional ISA extension**, so it needs
      the full CPUID probe + self-test + dispatch machinery that `mul64.cyr` was
      able to skip.

**Opened by 3.12.2** (named here so they are not buried in a CHANGELOG entry)

- [ ] **UEFI Secure Boot firmware-interop gate** — boot a sigil-signed EFI under
      OVMF with AGNOS-owned PK/KEK/db enrolled. The *only* remaining item from the
      now-archived
      [`authenticode-pe-signing`](issues/archive/2026-07-03-authenticode-pe-signing.md)
      issue (P1–P4 all shipped: 3.10.0, 3.11.1, 3.12.2). Needs key-enrollment
      tooling not present on the dev host; sigil-side work is complete and
      openssl-validated. **Moved here from the issue file so it survives archival.**
- [ ] **`benches/history.csv` has no 3.10 / 3.11 rows.** Those runs were never
      recorded, and fabricating them would corrupt the history, so the gap is left
      honest. 3.12.2 rows are present. Fill forward only.
- [ ] **One standing `cyrlint` line-length warning, deliberately exempted.**
      `src/mldsa_ntt.cyr:41` exceeds 120 characters — it is the 2048-char
      `_mldsa_zetas_hex` NTT twiddle-factor constant, and
      `.github/workflows/ci.yml` carves it out by name alongside
      `src/aes_gcm.cyr`'s FIPS 197 S-box. The CI comment states the exit
      condition: drop the carve-out and add an inline allow **when cyrius
      cyrlint gains a per-line `# cyrlint: allow line-length` annotation**.
      Until then, splitting the literal would be strictly worse. Not a defect.
      *(3.12.2 cleared the other two: the three raw `sys_open` sites in
      `src/secureboot_core.cyr` now go through `io.cyr`'s namelen-bridged
      `xopen` / `file_exists`, and an untracked-deferral false positive in
      `src/crypto_scratch.cyr` — "not yet allocated" describing a sentinel —
      was reworded rather than `#skip-lint`-suppressed.)*
- [ ] **A full `asm{}` CIOS inner loop** for `_bn_mont_mul` — would remove the
      per-product call overhead and the `_bn_m64` memory round-trip that 3.12.2's
      leaf multiply still pays. Deliberately not scoped in 3.12.2: substantially
      larger audit surface on the most correctness-critical loop in the library,
      for a fraction of the remaining win. Only if a consumer needs it.

**Opened by 3.12.8** (named here so they are not buried in a CHANGELOG entry)

- [ ] **Catch-up audit for 3.12.3 → 3.12.7 — five releases filed no audit report.**
      CLAUDE.md § "Security Hardening (before release)" is unconditional, and the
      lapse spans **3.12.6, which fixed an RSA-PSS authentication bypass**.
      3.12.8's audit
      ([`2026-08-14-3.12.8-err-namespace-toolchain-audit.md`](../audit/2026-08-14-3.12.8-err-namespace-toolchain-audit.md))
      re-established the practice but **explicitly does not cover that range**.
      Whether to run a retroactive pass is not decided here.
- [ ] **`cyrius.lock` no longer self-refreshes — sigil has zero git deps.**
      `cmd_deps_lock()` (cyrius `cbt/deps.cyr:1916`) writes the lock only when
      `cyrius deps` actually copied a dep. Since sakshi moved into
      `[deps].stdlib` at 3.12.7 nothing is ever copied, so the lock silently
      drifts against `lib/` on every toolchain bump and must be hand-refreshed
      (as it was at 3.12.8: 10 of 107 hashes). For a trust-verification library
      a tamper-detection record that stops tracking its own inputs deserves an
      upstream fix in cyrius — either lock-on-`lib sync`, or lock the resolved
      stdlib snapshot. Not actioned; the fix could land in cyrius `cbt/deps.cyr` or as a sigil-side check.
- [ ] **3.12.7's CHANGELOG assertion count (1,730) does not reproduce.**
      Measured at 3.12.8 two independent ways — `scripts/check.sh` and CLAUDE.md's
      canonical per-file `cyrius test` loop — both give **1,665 across 65 files**,
      and no test was removed. Recorded so the number is not silently carried
      forward; worth one pass to confirm nothing regressed at 3.12.3–3.12.7
      rather than being miscounted.

**Possible future surfaces** (consumer-demand-gated)

- [ ] **ML-KEM-768** (PQC KEM) — belongs in a sibling `kem.cyr` if an
      AGNOS consumer needs key agreement. (ML-DSA-65 PQC sign ships
      default-on since 3.7.6.)

**Open audit findings — NONE.** 3.12.2's audit found 1 HIGH (the
`authenticode_pe_sign` pad-in-hash defect), 1 LOW and 4 hardenings — **all fixed
in the same release**, none carried forward. See
[`docs/audit/2026-07-30-3.12.2-asm-multiply-authenticode-verify-audit.md`](../audit/2026-07-30-3.12.2-asm-multiply-authenticode-verify-audit.md).
The audit floor was **cleared at 3.7.3**
(4 genuine per-call-drift LOWs resolved via the `_into` caller-scratch
API; 4 reclassified as correct init-once singletons). See state.md
"Audit floor".

## Closed cycles

Per-version detail in [CHANGELOG.md](../../CHANGELOG.md); per-cycle
audits in [`docs/audit/`](../audit/).

- **3.12 — password hashing, then the perf + Authenticode-verify cycle.**
  3.12.0 BLAKE2b (RFC 7693) + Argon2id/i/d (RFC 9106), verified against the RFC
  9106 §5 vectors and OpenSSL 3.6's providers. 3.12.1 moved the crypto-bank
  thread-local slot onto cyrius's slot allocator. **3.12.2** landed the native
  `asm{}` 64×64→128 multiply (`src/mul64.cyr`, [ADR 0008](../adr/0008-native-asm-multiply-and-public-modexp.md),
  [note 002](../architecture/002-native-asm-multiply.md)), the public-exponent
  `bn_mont_modexp_pub`, Authenticode **verification** + the P-256 signer (closing
  P4), and a HIGH-severity fix to `authenticode_pe_sign`'s hash range. RSA verify
  2.78×, RSA sign 1.70×, Ed25519 verify 1.25×; `ecdsa_p256_verify` crossed below
  ADR 0006's parked 10 ms. Toolchain 6.4.65 → 6.5.3.
- **3.11 — UEFI Secure Boot enrollment.** `src/efi_sigdb.cyr`:
  `efi_signature_list_from_cert` (byte-identical to efitools'
  `cert-to-efi-sig-list`) + `efi_auth_from_esl` / `efi_time`, i.e. P3 of the
  Authenticode arc.
- **3.10 — native UEFI Authenticode PE signing.** `src/authenticode.cyr`: a DER
  encoder, PKCS#7 `SignedData`, `SpcIndirectDataContent`, the PE Authenticode
  hash, and the attribute-cert-table embed — the sovereign `sbsign`. P1 + P2 of
  the Authenticode arc.
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
- **3.8 — housekeeping bookend to 3.7.x (CLOSED at 3.8.1).** ChaCha20 + X25519
  per-worker banking (race-validated; plain `var` + per-lane wipe, not
  `secret var`); a backlog-accuracy sweep (TDX/SGX in-quote PCK walk found
  already-shipped; `bn_modexp` kept as the modexp test-oracle; scatter-store
  re-scoped MOOT/parked); the Windows-entropy issue archived after wine/ProcessPrng
  runtime verification; **3.8.1 dropped the `agnosys` dependency** (trust
  primitives internalized as `*_core.cyr` + `sys_error`/`sys_util`). See
  CHANGELOG `[3.8.0]`/`[3.8.1]`.
- **3.9 — trust-API in `dist` + concurrent-crypto thread-safety (CLOSED at 3.9.7).**
  **3.9.0** promoted the full trust API into `dist/sigil.cyr` (105 trust fns —
  TPM/IMA/SecureBoot/cert-pin/dm-verity/LUKS). **3.9.6** fixed the
  concurrent-TLS-handshake crash: `cbank()` now **auto-assigns** a per-thread lane
  (no `crypto_bank_set` call), `SIGIL_CRYPTO_BANKS` 8→64, with HKDF/HMAC/
  `ed25519_sign`/one-shot-SHA-2/AES-GCM/ChaCha-Poly banked + the NI self-test
  CAS-guarded ([ADR 0007](../adr/0007-auto-banking-for-concurrent-tls.md)).
  **3.9.7** completed the banking across **every reachable concurrent crypto
  path**: streaming Poly1305 (last `fl_alloc` gone), full ECDSA P-256/P-384
  sign+verify (incl. RFC 6979 DRBG + the DER wrappers + `*_warm` prewarm),
  bignum/RSA/TLS-1.2-PRF, and closed a pre-existing RSA-sign secret-residue gap.
  Security finding: `secret var X[N]` arrays are shared statics that race (fixed a
  latent DER-wrapper race). Audits `2026-06-29-3.9.6-…` + `2026-06-29-3.9.7-…`.
  See CHANGELOG `[3.9.0]`/`[3.9.6]`/`[3.9.7]`.

**Cyrius pin:** see `cyrius.cyml` `[package].cyrius` (the single source of truth).

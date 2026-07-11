# Sigil — Live State

> **Refresh cadence**: every release. Per agnosticos
> [first-party-documentation § state.md](https://github.com/MacCracken/agnosticos/blob/main/docs/development/planning/first-party-documentation.md),
> this file holds volatile data that would rot if inlined in
> CLAUDE.md. Historical release narrative lives in
> [`CHANGELOG.md`](../../CHANGELOG.md); forward-looking work
> lives in [`roadmap.md`](roadmap.md); per-cycle audit findings
> live in [`docs/audit/`](../audit/).

## Version

| Field | Value |
|---|---|
| Current version | **3.11.0** (`VERSION`) |
| Cyrius toolchain pin | **6.4.45** (`cyrius.cyml [package].cyrius`) |
| Dependencies | sakshi **2.4.3** (agnosys dropped — trust primitives internalized at 3.8.1) |
| Last release date | 2026-07-10 |
| Last release audit | [`2026-06-29-3.9.7-ecdsa-bignum-banking-audit.md`](../audit/2026-06-29-3.9.7-ecdsa-bignum-banking-audit.md) (3.9.7 thread-safety banking completion — ECDSA/bignum/PRF/AEAD; F1 MEDIUM latent DER-wrapper race fixed, F2 LOW RSA-sign residue gap closed, F3 `secret var` arrays = shared statics documented; red→green race-detectors). Prior: `2026-06-29-3.9.6-concurrent-tls-handshake-banking-audit.md`. |

> ⚠️ **State drift note (2026-06-29):** the volatile fields above and the
> Phase headline are now current at **3.11.0**. The per-version Phase **prose
> stack** (the historical 3.8.0 / 3.7.x narrative below the headline) is still
> hand-maintained — the release post-hook refreshes the volatile fields but
> does not regenerate that prose, so it remains a manual carry-forward (across
> 3.9.0–3.9.5 the hook also did not refresh state.md; those shipped per
> CHANGELOG: dist via `cyrius distlib`, trust-API bundling, CVE-20/21
> trust-chain work). Per CLAUDE.md ("if the hook doesn't, fix the hook — don't
> hand-maintain state") the prose-refresh gap stays flagged for Robert.
| Phase | Released. **3.9.7 — thread-safety banking completed (follow-up to 3.9.6).** Banked every remaining concurrent-path crypto scratch, so **every reachable concurrent crypto path is now race-free**: ChaCha20-Poly1305 `_cp_tag` (new streaming `poly1305_init`/`update`/`finalize` — last `fl_alloc` gone), ECDSA P-256/P-384 sign+verify (~150 buffers + RFC 6979 DRBG + per-sign `k·G` + sign secret scratch; P-384 `_p384_mul64` return-slot restructure; `ecdsa_p256_warm`/`ecdsa_p384_warm` main-thread prewarm), and `bignum`/`rsa`/`tls12_prf` (off-TLS-1.3, for completeness). **Security:** fixed a latent race in the ECDSA DER wrappers (`*_sign_der`/`verify_der`) — `secret var X[N]` ARRAYS are shared statics that race (proven by probe; the v6.2.25 "arena fix" only stopped a heap leak), and these are the TLS CertificateVerify path; closed a pre-existing RSA-sign secret-residue gap. New `ecdsa_concurrent.tcyr` + `bignum_tls12_concurrent.tcyr` race-detectors (red→green); extended `poly1305.tcyr` + `banking_concurrent.tcyr`. Suite **1576/0 across 60 files**. 64-lane banking grew static `.bss` ~14 MB (lazy zero-pages; informational). ——— *(historical below)* **3.9.6 — concurrent-TLS-handshake crash fixed (🔴 HIGH).** A multi-worker TLS 1.3 server crashed (SIGSEGV/ECONNRESET) on the second simultaneous handshake: the per-worker crypto banks (`crypto_scratch.cyr`) existed but only the batch-verify path ever activated them, so concurrent TLS workers all collided on bank 0; and the handshake/AEAD primitives the key schedule drives (HKDF, HMAC, `ed25519_sign`, one-shot SHA-2, both AEAD suites) were unbanked or used non-thread-safe `fl_alloc`. Fixed: **`cbank()` now auto-assigns a per-thread lane** (atomic counter → lanes 1..63, bank 0 = main; no consumer `crypto_bank_set` needed), `SIGIL_CRYPTO_BANKS` 8→64, and banked HKDF/HKDF-SHA384 (rewritten allocation-free, streaming segments), HMAC/HMAC-SHA384, `ed25519_sign`/`sc_muladd`, the one-shot `sha256/512/384` (→ banked `_into`, no fl_alloc), `sha384_finalize`, the full AES-GCM AEAD path (GHASH/CTR/encrypt/decrypt + banked round-key schedule), and ChaCha20-Poly1305/Poly1305. NI self-test CAS-guarded. New `concurrent_tls_handshake.tcyr` race-detector (16 auto-banked workers, stable 30/30; caught 2 races live). Toolchain pin 6.2.48→**6.3.5**. No perf regression (`ecdsa_p256_verify` ~10.66 ms vs ~10.89 baseline). **Deferred → 3.9.7 (tracked, not dropped):** ChaCha `_cp_tag` fl_alloc (needs streaming Poly1305), ECDSA P-256/P-384 banking (latent), bignum/tls12_prf statics (off TLS-1.3 path). [ADR 0007](../adr/0007-auto-banking-for-concurrent-tls.md). ——— *(historical, stale below)* Released. **3.8.0** opens the 3.8.x cycle as a **housekeeping bookend to 3.7.x**: **ChaCha20 + X25519 per-worker banking** (st/ws/ks, W/ub/base widened to `SIGIL_CRYPTO_BANKS` lanes via `cbank()`; plain `var` + per-lane zeroize — a `secret var` whole-array wipe would clobber concurrent lanes, a bug caught by the new `banking_concurrent.tcyr` race-detector, 5/5 clean post-fix). **Backlog-accuracy sweep**: TDX/SGX in-quote PCK walk found already-shipped (stale note → DONE), `bn_modexp` RESOLVED-keep (modexp test-oracle), scatter-store re-scoped MOOT/parked (guards a public value). **Windows-entropy issue archived** after **wine/ProcessPrng runtime verification** (Windows-PE via `cyrius build --win`, run under wine: `random`/`ed25519`/`win_entropy_probe` all exit 0 — fresh unique entropy + keygen; same probe green on Linux); the `docs/development/issues/` folder is now **clear** (12 archived). **3.7.x EC-squeeze cycle closed** (all 4 levers shipped; ≤ 10 ms not reached, ~10.9 ms floor, parked; full bench re-run captured, no regressions). Defensive: no concurrent ChaCha20/X25519 caller exists yet. Audit: `docs/audit/2026-06-16-3.8.0-chacha-x25519-banking-audit.md`. **3.7.17** closes the EC-squeeze perf cycle with **levers 2b + 3**: **Karatsuba `u256_mul_full`** (the 256×256→512 multiply under all of Ed25519/X25519/ECDSA, schoolbook → 3-mul Karatsuba; **~3–4% across the board** — Ed25519 verify 6.90 → 6.63 ms, P-256 verify ~11.58 → ~11.25 ms; thread-safe, schoolbook retained as oracle) + the marginal `u2·Q`-window mixed add. **≤ 10 ms is NOT reached — `ecdsa_p256_verify` floors at ~10.9 ms (12.50 → ~10.9, ~13% cumulative across the cycle); the known levers are exhausted** (at 256-bit, fast hardware multiply caps Karatsuba). Karatsuba is **conclusively verified** (KAT 200 random + 14 adversarial edges + full RFC-vector suite + concurrent batch path + a 5-lens adversarial carry review over millions of differential cases; CT posture unchanged from the schoolbook). **≤ 10 ms item closed 2026-06-16 (Robert) as "not reachable with current approaches" (ADR 0006); exotic levers (asm / alt-representation) parked to Backlog — not a current priority.** Audit: `docs/audit/2026-06-16-3.7.17-karatsuba-multiply-audit.md`. **3.7.16** ships **P-256 verify EC-squeeze levers 1 + 2a** (+ the cyrlint gate-retirement): both modular inversions moved off generic Fermat — field `fp_p256_inv` → fixed `2^k-1` addition chain, scalar `fn_p256_inv` → 4-bit window — and the fixed-base `u1·G` comb table is now **affine** with a new `pt_add_mixed` (Jacobian+affine, madd-2007-bl) on its 64 adds. `ecdsa_p256_verify` **12.50 → ~11.00 ms (~12%)**, clean A/B on 6.2.12. **Verify-only / non-CT** (public data; the secret-nonce signing path stays on the CT ladder). KAT-conclusive (`a*inv≡1`, `pt_add_mixed==pt_add` + double/−Q edges); +10 assertions. **≤ 10 ms still open (~11.0 ms)** — verify is doubling/inversion-bound, so the remaining levers (2b `u2·Q`-window batch-inversion mixed-add; 3 Karatsuba `u256_mul_full` with a security re-review) land in **3.7.17**. The buried-deferral gate is now enforced by `cyrlint` natively (every AGNOS repo), with the 2 `\uXXXX` false positives `#skip-lint`-suppressed. Audit: `docs/audit/2026-06-16-3.7.16-ec-inversion-mixedadd-audit.md`. **3.7.15** was the **Windows-entropy fix**: sigil keygen / nonce / blinding no longer open `/dev/urandom` directly (non-functional on Windows even after the v6.2.12 ProcessPrng CSPRNG) — all entropy now routes through a single boundary, `_sigil_random_fill` (`src/random.cyr`), over the stdlib `random_bytes` (per-target getrandom / getentropy / ProcessPrng). Fail-closed preserved verbatim (no weak fallback; CVE-19 invariant intact). 5 dist sites converted (`generate_keypair`, `ed25519_generate_keypair`, `mldsa65_keypair`, `_rsa_gen_blind`, `_rsa_pss_rand`); new `lib/random.cyr` opt-in include (now **five** required; README "Usage" updated); pin `6.2.11` → `6.2.12`; +9 assertions (new `random.tcyr`). `src/tpm.cyr` `tpm_random` also converted (a 6th, AGNOS-only / off-dist site) — **zero raw `/dev/urandom` opens remain in `src/`**. **Linux verified; Windows ProcessPrng path pending verification on `cass` (cannot run on Linux dev host).** Issue stays open until `cass` confirms. Issue: `docs/development/issues/archive/2026-06-15-sigil-windows-entropy-not-via-getrandom.md`. **3.7.14** was a toolchain/dependency refresh: cyrius pin `6.2.1` → `6.2.11` (manifest aligned to the already-installed `cycc`), agnosys `1.3.2` → `1.4.3`, sakshi `2.2.6` → `2.3.0`. No `src/*.cyr` edits; clean `cyrius deps` + smoke build + 55/55 `.tcyr` + healthy bench, dist regenerated self-contained (doc-check 0 undocumented). **3.7.13** bumped the pin `6.1.20` → `6.2.1`, fixed the attestation cert-pointer-array daimon byte-vs-slot class (`var name: i64[4]`), and dropped `json` / replaced `bigint` with `bayan` in `[deps]`. **3.7.8 resolved the cyrius-6.1.20 bundle-consumer SIGILL** reported as an NI re-break. Root cause was NOT the asm `[rbp-N]` param-load drift but **missing opt-in stdlib deps in bundle builds**: cyrius stdlib is opt-in, and a consumer including only `dist/sigil.cyr` leaves `thread_local_*` / `ct_eq_bytes_lens` / `shake256` undefined → cyrius 6.1.x emits `ud2` → SIGILL on the first banked crypto call (`sha256`/`ed25519`/`aes`). Fixed by documenting all four required includes (`lib/ct.cyr`, `lib/keccak.cyr`, `lib/thread.cyr`, `lib/thread_local.cyr`) in the README "Usage" section. Belt-and-suspenders: the long-queued NI structural fix landed — `sha_ni.cyr`/`aes_ni.cyr` migrated off hardcoded `mov r__, [rbp-N]` loads to the `param_load(reg, idx)` pseudo (cyrius 6.0.67+). Pin 6.0.87 → 6.1.20. **3.7.7 was a buried-deferral sweep** — triaged all 19 deferral-vocabulary hits in `src/`: genuine pending work (ChaCha20/X25519 parallel-path, TDX chain walk, scalar-inversion addition-chain, `bn_modexp` dead-code) **promoted to the roadmap Backlog, not deleted**; stale comments referencing shipped work (Solinas, RSA sign, Montgomery, `_into`, `pem_decode_privkey`) updated; false positives reduced to a `\uXXXX` allowlist. Comment-only; no behavior change. **3.7.6** made ML-DSA-65 post-quantum signing default-on (dropped `#ifdef SIGIL_PQC`; 6.0.87 cap raise; +~40 KB smoke). **3.7.5** closed the P1 off-diagonal ECDSA chain-link verification + bumped the pin 6.0.62 → 6.0.87. **Remaining v3.7:** EC scalar-mult speedup (≤ 10 ms) + full bench re-run. (The buried-deferral *gate* is **done — superseded by `cyrlint`'s native untracked-deferral check**, which covers every AGNOS repo; the 2 `\uXXXX` false positives in `src/policy.cyr` are now `#skip-lint`-suppressed.) |

## Test surface

| Metric | Value |
|---|---|
| `.tcyr` test files | 60 (`ls tests/tcyr/*.tcyr`) — +2 @3.9.7 (`ecdsa_concurrent.tcyr`, `bignum_tls12_concurrent.tcyr`) |
| Total assertions | **1576** / 0 failures @3.9.7 across all 60 files (scripted-sum 1532 + 44 for the 3 tty-only `*_verify_full` summaries). |
| Fuzz harnesses | 3 (`fuzz/*.fcyr`) — `fuzz_ed25519`/`fuzz_integrity`/`fuzz_revocation`, all build + run clean @3.9.7. |
| Benchmark suite | `benches/` — `history.csv`; RSA via `tests/bcyr/rsa.bcyr`, P-256/P-384 verify via `tests/bcyr/ecdsa_p256.bcyr` / `ecdsa_p384.bcyr` |

> Counting note: the 3 `*_verify_full.tcyr` tests (sgx 17 + tdx 16 +
> snp 11 = 44) emit their `N passed` summary in a tty-sensitive way that
> is dropped under any pipe or file redirect, so a scripted `grep`-sum of
> `cyrius test` output yields **1532** across the other 57 files and
> silently omits those 44. Add them back for the true total: **1576**.
> (Each verify_full still prints its summary on an interactive run; it's
> only the redirected/scripted sum that loses them.)

Per-cycle assertion delta:

- **3.9.7 ship**: +new race-detectors & streaming/AEAD coverage (thread-safety
  banking completion). New `ecdsa_concurrent.tcyr` (concurrent P-256/P-384
  sign+verify incl. the DER wrappers — caught the latent `secret var`-array
  DER-wrapper race, red→green) + `bignum_tls12_concurrent.tcyr` (concurrent
  bignum/rsa/tls12_prf race-detector, red→green); extended `poly1305.tcyr`
  (streaming `poly1305_init`/`update`/`finalize`) + `banking_concurrent.tcyr`
  (ChaCha20-Poly1305 streaming AEAD coverage). Running total → **1576 / 60
  files** (+2 files since 3.9.6: `ecdsa_concurrent.tcyr`,
  `bignum_tls12_concurrent.tcyr`).
- **3.9.6 ship**: +concurrent-TLS race-detector (concurrent-TLS-handshake crash
  fix). New `concurrent_tls_handshake.tcyr` — 16 auto-banked TLS workers
  (`cbank()` auto-assign, banks 8→64) vs the serial path, stable 30/30; caught
  2 live races (HKDF/AEAD bank-0 collision). +1 test file (→ 58 files).
- **3.9.0–3.9.5 ships**: +0 net new `.tcyr` assertions on the housekeeping/
  bundling/CVE-trust-chain bites (dist via `cyrius distlib`, trust-API bundling,
  CVE-20/21 trust-chain work — correctness covered by the existing trust/x509/
  ed25519 KATs); suite held at the 3.8.x basis across the run. See CHANGELOG.
- **3.8.0 ship**: +2 (ChaCha20 + X25519 banking — new `banking_concurrent.tcyr`
  race-detector: 4 concurrent workers on banks 1–4 vs serial, validating the
  `cbank()` lane isolation. Caught a cross-lane `secret var` clobber bug, fixed
  with plain `var` + per-lane zeroize. +1 test file.)
- **3.7.17 ship**: +2 (EC-squeeze lever 3 — Karatsuba `u256_mul_full` —
  `ecdsa_p256.tcyr`: `u256_mul_full == _u256_mul_full_schoolbook` over 200 random
  256×256 + 14 carry-boundary/adversarial edges. The crown-jewel multiply under
  Ed25519/X25519/ECDSA; conclusively verified (KAT + full sig suite + a 5-lens
  adversarial carry review over millions of differential cases). ~3–4% across all
  256-bit ECC; ≤ 10 ms still not reached (~10.9 ms floor, levers exhausted).)
- **3.7.17 ship**: +1 (EC-squeeze lever 2b — `ecdsa_p256.tcyr`:
  `p256_scalarmul_var == pt_scalarmul` over 16 random `(k,Q)`, validating the
  `u2·Q`-window affine table + Montgomery batch inversion against the CT ladder.
  `ecdsa_p256_verify` ~11.00 → ~10.89 ms — marginal; batch-inversion overhead
  nearly cancels the mixed-add win.)

- **3.7.16 ship**: +3 (P-256 verify mixed Jacobian+affine
  addition — `ecdsa_p256.tcyr`: `pt_add_mixed == pt_add` over 24 (P,Q) pairs +
  the `P==Q` double / `P==-Q` infinity edges. Affine comb-G table; isolated A/B
  general-add 11.32 → mixed 11.00 ms. Verify-path / non-CT.)
- **3.7.16 ship**: +7 (P-256 verify inversion speedup —
  `ecdsa_p256.tcyr`: the fixed-chain field inverse `fp_p256_inv` and 4-bit-window
  scalar inverse `fn_p256_inv` each KAT-gated `chain/window == generic` + `a*inv ≡ 1`
  over 64 random field elems / scalars + edges. `ecdsa_p256_verify` 12.50 → 11.37 ms,
  clean A/B on 6.2.12.)
- 3.7.15 ship: +9 (new `random.tcyr` — entropy-boundary regression for the
  Windows `/dev/urandom`→`random_bytes` fix: full-fill success, fresh entropy,
  two-draw uniqueness, the `n == 0` no-op edge, and the > 256-byte
  internal-loop / no-truncation path. The 5 converted keygen/sign sites stay
  correctness-covered by the existing ed25519/rsa/mldsa/sigil/verify KATs,
  which now also include `lib/random.cyr` + `src/random.cyr`.)
- 3.7.8 ship: +0 (two items, both correctness-covered by existing KATs — no new `.tcyr` assertions. **(a) cyrius-6.1.20 bundle-consumer SIGILL fix** — README docs for the four required opt-in stdlib includes + NI `param_load` structural migration + pin 6.0.87→6.1.20. **(b) EC scalar-mult speedup** — fixed-base comb for `u1·G` + windowed `u2·Q`, verify-only / non-CT (signing stays on the CT ladder): `ecdsa_p256_verify` 24.675→11.600 ms (2.13×), `ecdsa_p384_verify` 54.6→26.263 ms (2.08×), `history.csv` row `v3.7.8-ec-comb-window`. Suite unchanged at 53 files / 1459 assertions, 0 failures; the ecdsa/x509/sgx/tdx/snp KATs validate the new verify paths, signing KATs byte-identical)
- 3.7.7 ship: +0 (buried-deferral sweep — comment-only; genuine deferrals promoted to the roadmap Backlog, stale comments marked shipped, false positives allowlisted; no source-logic or test change)
- 3.7.6 ship: +0 (PQC default-on — build-config change, no new `.tcyr` assertions; the 8 `mldsa*.tcyr` suites were already counted, and `programs/smoke.cyr` gained a runtime ML-DSA round-trip that is not a `.tcyr` assertion)
- 3.7.5 ship: +28 (off-diagonal ECDSA chain-link verify — `ecdsa_p256.tcyr` +4 / `ecdsa_p384.tcyr` +4: OpenSSL-ground-truth off-diagonal primitive KATs (P-256 key/SHA-384, P-384 key/SHA-256), each `openssl dgst -verify`-confirmed, incl. leftmost-bits truncation; `x509_offdiag.tcyr` +20, new — two real off-diagonal OpenSSL cert chains (`openssl verify` OK): link-verify, full-chain, issuer-curve `sig_len` 96/64, tamper + cross-issuer width rejects)
- 3.7.4 ship: +0 (x509 off-diagonal **parse**-side fix — `ec_fw` widened to 48 on r,s overflow so a P-384/SHA-256 self-signed anchor (SSL.com Root ECC class) parses; verified against existing `x509`/`x509_p384`/`snp_verify_full` suites, no new assertions)
- 3.7.3 ship: +14 (`_into` arena no-drift tests with a **global-heap witness** (`alloc_used()` delta == 0 across 50 reset+parse iterations): `sgx_verify_full.tcyr` +6 (orchestrator path), `x509_rsa.tcyr` +4 (RSA 544-byte block arena-routing), `x509_p384.tcyr` +4 (P-384 raw_sig arena-routing); proves no residual global-bump alloc)
- 3.7.2 ship: +24 (`aes_gcm_iv.tcyr` +24, new — AES-256/128 GCM arbitrary-IV KATs vs OpenSSL at 60/8/1-byte IVs (60-byte = McGrew-Viega TC6/TC18), decrypt roundtrips, tamper reject, 12-byte consistency, iv_len validation)
- 3.7.1 ship: +3 (`ecdsa_p384.tcyr` +3 — Solinas-vs-long-div differential KAT over 64 SHA-384-seeded random 768-bit inputs + 2^768−1 / high-half-all-ones edges)
- 3.7.0 ship: +3 (`ecdsa_p256.tcyr` +3 — Solinas-vs-long-div differential KAT over 64 SHA-256-seeded random 512-bit inputs + 2^512−1 / high-half-all-ones edges)
- 3.6.8 ship: +0 (closeout — stale-comment/doc fixes only; no source-logic or test change)
- 3.6.7 ship: +18 (`x509_p384.tcyr` +9 — P-384 CA→leaf SHA-384 chain verify, tamper reject, SHA256-vs-P384-issuer regression; `seal.tcyr` +9 — AES-128 derive/seal/unseal, width validation, 256-bit back-compat)
- 3.6.6 ship: +5 (`rsa.tcyr` +1 — even-modulus reject for the Montgomery verify precondition; `privkey.tcyr` +4 — PEM RSA → RSAK struct emit + modulus match)
- 3.6.5 ship: +30 (`rsa.tcyr` +10 — RSA-PSS: external pure-Python PSS KAT verify SHA-256/384, sign→verify roundtrips, tamper/wrong-message/wrong-length/cross-hash/cross-scheme rejects. `x509_rsa.tcyr` +20, new — OpenSSL RSA-2048 CA signing SHA-256 + SHA-384 leaves, green chain + tamper/wrong-key/DN-mismatch rejects)
- 3.6.4 ship: +5 (`bignum.tcyr` +5 — `bn_modinv` self-check `r·r^-1 ≡ 1 mod n` at 256/2048-bit + the non-coprime `-1` path; the blinded+CRT signer reuses the existing `rsa.tcyr` deterministic-KAT assertions)
- 3.6.3 ship: +24 (`rsa.tcyr` +21 — pubkey/privkey DER parse incl. p·q==n, deterministic PKCS#1 v1.5 sign matching an external Python RSA byte-for-byte SHA-256/384, sign→verify roundtrips; `bignum.tcyr` +3 — CT Montgomery modexp == schoolbook at 256/2048-bit)
- 3.6.2 ship: +12 (`bignum.tcyr` 6 — modexp KATs incl. full RSA-2048-size `s^65537 mod n`, all vs Python `pow`; serialize round-trip; `base^0`/`0^e` edges. `rsa.tcyr` 6 — real RSA-2048 PKCS#1 v1.5 SHA-256/384 verify accept + tamper/wrong-message/wrong-length/hash-mismatch reject)
- 3.6.1 ship: +9 (`tls12_prf.tcyr` 9 — canonical RFC 5246 §5 PRF vectors: P_SHA256 100-byte + P_SHA384 148-byte (Python `hmac`/`hashlib`-reproduced; SHA-256 matched the published vector), truncation prefixes (12 + 48 byte), determinism, over-cap guard)
- 3.6.0 ship: +0 (parallel-verify refactor — no new test assertions; correctness is covered by the full suite at bank 0 plus `batch_parallel.tcyr` (228 assertions) run **mutex-off as the race detector**: 35/35 consecutive clean runs. The first mutex-off run failed and surfaced the un-banked `fp_inv` / `hash_file_into` buffers.)
- ≤ 3.5.9 and earlier: trimmed — see [`CHANGELOG.md`](../../CHANGELOG.md) (3.5 modern-crypto arc + 3.4.x TEE arc + 3.3.0).

## Consumers (AGNOS first-party)

Consumers that link or rely on sigil for trust verification:

- `daimon` — daemon supervisor + signing
- `kavach` — TEE attestation backend
- `ark` — package publisher / repository
- `aegis` — runtime trust enforcement
- `phylax` — anomaly detection
- `mela` — package archive verification
- `stiva` — secure boot orchestrator
- `argonaut` — agent identity / signing

## Recently shipped

| Version | Date | Headline |
|---|---|---|
| 3.9.7 | 2026-06-29 | **Thread-safety banking completed (3.9.6 follow-up).** Banked every remaining concurrent-path crypto scratch → every reachable concurrent crypto path is race-free. **ChaCha20-Poly1305:** new streaming `poly1305_init`/`update`/`finalize`; `_cp_tag` streams the mac_data in place — last concurrent `fl_alloc` gone (AEAD encrypt marginally faster). **ECDSA P-256/P-384 sign+verify:** ~150 scratch buffers + RFC 6979 DRBG + per-sign `k·G` + sign secret scratch banked (plain `var` + per-lane wipe, quirk #9); P-384 `_p384_mul64` return slots restructured; `ecdsa_p256_warm`/`ecdsa_p384_warm` main-thread prewarm (quirk #7). **bignum/rsa/tls12_prf:** banked for completeness (off TLS-1.3 path). **Security:** latent race fixed in the ECDSA DER wrappers (`*_sign_der`/`verify_der` — `secret var X[N]` arrays are shared statics that race, proven by probe; this is the TLS CertificateVerify path); closed a pre-existing RSA-sign secret-residue gap. New `ecdsa_concurrent.tcyr` + `bignum_tls12_concurrent.tcyr` race-detectors (red→green); +streaming/AEAD coverage. Suite **1576/0 across 60 files**. Static `.bss` +~14 MB from 64-lane banking (lazy zero-pages; informational). Pin **6.3.5** (unchanged). |
| 3.8.0 | 2026-06-16 | **3.8.x open — housekeeping bookend to 3.7.x.** **ChaCha20 + X25519 per-worker banking**: their static working arrays (chacha20 st/ws/ks, x25519 W/ub/base) are banked via `cbank()` lanes so concurrent callers can't race; plain `var` + **per-lane** zeroize (a `secret var` whole-array wipe clobbers concurrent lanes — bug caught by the new `banking_concurrent.tcyr` race-detector, 5/5 clean post-fix). Defensive (no concurrent caller yet). **Backlog-accuracy sweep**: TDX/SGX in-quote PCK walk already-shipped (stale note → DONE); `bn_modexp` KEEP (modexp test-oracle); scatter-store MOOT/parked (public-data). **Windows-entropy issue archived** after **wine/ProcessPrng runtime verification** (Windows-PE via `--win`, run under wine: entropy + ed25519 keygen + the consumer `dist` probe all exit 0); issues folder **clear** (12 archived). 3.7.x EC-squeeze closed (≤10ms unreached, parked; bench re-run clean). +2 assertions. Audit: `docs/audit/2026-06-16-3.8.0-chacha-x25519-banking-audit.md`. |
| 3.7.17 | 2026-06-16 | **EC-squeeze close — Karatsuba `u256_mul_full` (lever 3) + `u2·Q`-window mixed add (lever 2b).** The 256×256→512 multiply under all 256-bit ECC (Ed25519/X25519/ECDSA) moved schoolbook → Karatsuba (12 × 64×64): **~3–4% across the board** (Ed25519 verify 6.90 → 6.63 ms, P-256 verify ~11.58 → ~11.25 ms) — not the hoped ~15–25%, because at 256-bit fast hardware multiply caps Karatsuba. Thread-safe (scalar-local, batch-path safe); schoolbook retained as the KAT oracle. **Conclusively verified** (differential KAT 200 random + 14 carry-boundary/adversarial edges + full RFC-vector suite + concurrent batch path + a **5-lens adversarial carry-propagation review** over millions of differential cases vs arbitrary-precision multiply + structural proofs — zero discrepancies). CT posture unchanged from the schoolbook (no new side-channel class). Lever 2b (`u2·Q`-window batch-inversion mixed add) was marginal (~11.00 → ~10.89 ms; kept). **≤ 10 ms NOT reached — ~10.9 ms floor (12.50 → ~10.9, ~13% cumulative); known levers exhausted.** +3 assertions. Audit: `docs/audit/2026-06-16-3.7.17-karatsuba-multiply-audit.md`. |
| 3.7.16 | 2026-06-16 | **P-256 verify EC-squeeze (levers 1 + 2a) — `ecdsa_p256_verify` 12.50 → ~11.00 ms (~12%).** Both verify-path modular inversions moved off generic Fermat: field `fp_p256_inv` (`a^(p-2)`) → fixed `2^k-1`-block addition chain (~255 sq + 12 mul), scalar `fn_p256_inv` (`a^(n-2)`) → 4-bit fixed window (each saved mul avoids an expensive long-division `n_reduce`). The fixed-base `u1·G` comb table is now **affine** with a new `pt_add_mixed` (Jacobian+affine, madd-2007-bl, ~7M+4S vs ~11M+5S) on its 64 adds; isolated A/B 11.32 → 11.00 ms. **Verify-only / non-CT** (public data; signing untouched). **≤ 10 ms still open** — verify is doubling/inversion-bound; lever 2b (`u2·Q` batch-inversion mixed-add) + lever 3 (Karatsuba, security-reviewed) → 3.7.17. +10 assertions (`a*inv≡1` + `pt_add_mixed==pt_add`, both over random inputs + edges). Also: the buried-deferral gate is now `cyrlint`-native. Audit: `docs/audit/2026-06-16-3.7.16-ec-inversion-mixedadd-audit.md`. |
| 3.7.15 | 2026-06-15 | **Windows entropy fix — keygen/nonce/blinding route through the stdlib CSPRNG, not `/dev/urandom`.** sigil opened `/dev/urandom` directly at every entropy site (`generate_keypair`, `ed25519_generate_keypair`, `mldsa65_keypair`, `_rsa_gen_blind`, `_rsa_pss_rand`); on Windows there is no `/dev/urandom`, so those paths fell **closed** (fail-CLOSED, not fail-weak — CVE-19 invariant held) and sigil RSA/Ed25519/ML-DSA keygen + RSA-PSS salt/blinding + (transitively) `tls_native` nonces were **unusable** on Windows. **Medium, Windows-only** (Linux/macOS/aarch64/AGNOS unaffected). Fixed by funneling all entropy through one boundary — `_sigil_random_fill` (`src/random.cyr`) over the stdlib `random_bytes` (per-target getrandom/getentropy/**ProcessPrng**, cyrius 6.2.12). Fail-closed preserved verbatim (no weak fallback; `secret var` seed zeroization intact). New required opt-in include `lib/random.cyr` (now five; README "Usage"). Pin 6.2.11→6.2.12. +9 assertions (new `random.tcyr`). `tpm.cyr` `tpm_random` also converted (a 6th, AGNOS-only / off-dist site) — **zero raw `/dev/urandom` opens remain in `src/`**. **Linux green; Windows path pending `cass` verification** (issue stays open until confirmed). Issue: `docs/development/issues/archive/2026-06-15-sigil-windows-entropy-not-via-getrandom.md`. |
| 3.7.8 | 2026-06-09 | **EC scalar-mult speedup (~2× both curves) + cyrius-6.1.20 bundle-consumer SIGILL fix.** **EC:** verify's `R = u1·G + u2·Q` now uses a fixed-base 4-bit comb for `u1·G` (precomputed table, zero hot-path doublings) + a 4-bit windowed double-and-add for the variable `u2·Q`, both **verify-only / non-CT** (verify is public data; secret-nonce signing stays on the CT Montgomery ladder). `ecdsa_p256_verify` 24.675→11.600 ms (2.13×), `ecdsa_p384_verify` 54.6→26.263 ms (2.08×); transitively speeds the SEV-SNP/TDX/SGX chains. ≤ 10 ms P-256 target still open (tracked: inversion-chain / mixed-add / Karatsuba). **SIGILL:** reported NI re-break was mis-diagnosed — A downstream hit SIGILL/exit-132 on `sha256`/`ed25519_*` (software `sha1` fine) building against `dist/sigil.cyr` under cycc 6.1.x. gdb proved the fault is a cyrius `ud2`, not asm `[rbp-N]` drift: the banked crypto hot path runs `cbank()`→`thread_local_*` on every call, verify runs `ct_eq_bytes_lens`, ML-DSA runs `shake256` — all **opt-in** cyrius stdlib the bundle doesn't carry, so a bundle-only consumer leaves them undefined and cyrius 6.1.x compiles each to `ud2`. **Fix: README "Usage" now documents all four required includes** (`lib/ct.cyr`, `lib/keccak.cyr`, `lib/thread.cyr`, `lib/thread_local.cyr`) and warns it's a runtime crash, not a build error. Belt-and-suspenders: the queued NI structural fix landed — `sha_ni.cyr`/`aes_ni.cyr` moved off hardcoded `mov r__, [rbp-N]` loads to the `param_load(reg,idx)` pseudo (6.0.67+). Pin 6.0.87→6.1.20. Suite 1459/1459, bundle repro exits 0 with correct digests. Issue: `docs/development/issues/archive/2026-06-09-cyrius-6120-rebreaks-ni-paths-sigill.md`. |
| 3.7.7 | 2026-06-07 | **Buried-deferral sweep.** Triaged all 19 deferral-vocabulary hits in `src/`. Genuine pending work **surfaced to the roadmap Backlog (not deleted)**: ChaCha20/X25519 parallel-path banking, the TDX/SGX in-quote PCK X.509 chain walk, the scalar-inversion addition-chain, and a `bn_modexp` dead-code decision. Stale comments referencing shipped work (Solinas, RSA sign, Montgomery, `_into`, `pem_decode_privkey`) updated to mark them shipped. False positives reduced to a documented `\uXXXX` allowlist for the future buried-deferral gate. Comment-only — no code change, suite unchanged at 53 files / 1459 assertions. |
| 3.7.6 | 2026-06-07 | **ML-DSA-65 post-quantum signing is now default-on.** Dropped the `#ifdef SIGIL_PQC` gate in `src/lib.cyr` — cyrius 6.0.87 raised the 1 MB preprocessor cap that had forced the `-D SIGIL_PQC` opt-in. The `dist` bundle already bundled mldsa (via `[lib].modules`), so this only changed the `src/lib.cyr` build path; `-D SIGIL_PQC` is now a back-compat no-op. +~40 KB smoke binary (mldsa code + `.bss` NTT tables, retained under DCE). `programs/smoke.cyr` gains an ML-DSA keygen→sign→verify round-trip. No mldsa code change; the 8 `mldsa*.tcyr` suites unchanged. Closes the roadmap "PQC-default builds" item; updates CLAUDE.md quirk #8. |
| 3.7.5 | 2026-06-07 | **Off-diagonal ECDSA chain-link verification (P1 complete) + toolchain pin 6.0.62 → 6.0.87.** `_x509_verify_link` decouples the signature hash (child sig-algo OID) from the issuer curve, verifying all four `{P-256, P-384} × {SHA-256, SHA-384}` combos — off-diagonal links included (P-384 issuer + SHA-256 child, P-256 issuer + SHA-384 child). New `_ecdsa_p{256,384}_verify_digest` cores apply the FIPS 186-4 §6.4 leftmost-bits digest→scalar mapping; the public 4-arg `ecdsa_p{256,384}_verify` entries stay byte-for-byte hashing wrappers (sgx/tdx/snp/dist unchanged). `x509_parse_into` sizes `sig_len` by the issuer curve (64/96), not the hash, and reuses one 96-byte scratch across the widen retry (no drift). +28 assertions (off-diagonal primitive KATs + new `x509_offdiag.tcyr` with two real OpenSSL cert chains). 4-lens adversarial review: no false-accept, diagonals byte-identical. Pin 6.0.62→6.0.87. Audit: `docs/audit/2026-06-07-3.7.5-offdiag-ecdsa-audit.md`. |
| 3.7.4 | 2026-06-06 | **x509 off-diagonal ECDSA parse-side fix.** `x509_parse_into` derived the ECDSA signature width `ec_fw` from the signature *hash*, but the r,s width is the *issuer key's curve* — so a P-384 key self-signing with ecdsa-with-SHA256 (the **SSL.com Root ECC CA** + ~12 OS-trust-store roots, which root Cloudflare's `one.one.one.one` chain) overflowed `ec_fw=32` and was silently dropped from the trust store. Fixed by starting at the hash-derived width and retrying once at 48 on r,s overflow — discovering the issuer curve from the signature itself (not the cert's own key, which would mis-size the SEV-SNP VCEK). The off-diagonal **verify** side remained a P1 follow-up (shipped 3.7.5). +0 assertions (Fixed-only; verified against existing x509/x509_p384/snp suites). Issue: `docs/development/issues/archive/2026-06-06-x509-off-diagonal-ecdsa-verify.md`. |
| 3.7.3 | 2026-06-04 | **Caller-scratch `_into` API — audit floor cleared (8 LOW → 0).** `x509_parse_into`/`x509_cert_alloc_into` + `sgx`/`tdx`/`snp` `*_verify_full_into` draw per-call scratch from a caller arena (stdlib `arena_new`; `arena_reset` between calls) — drift-free for a looping consumer; the original entries are byte-for-byte `arena==0` wrappers. 4 genuine-drift LOWs resolved via `_into`; 4 init-once LOWs reclassified as correct. +14 assertions (50× no-drift loops with `alloc_used()` global-heap witness across the orchestrator + RSA + P-384 paths). Audit: `docs/audit/2026-06-04-3.7.3-into-api-audit.md`. |
| 3.7.2 | 2026-06-04 | **AES-GCM arbitrary-length IVs** (backlog cleanup in the v3.7 arc). `_gcm_compute_j0` adds the NIST SP 800-38D §7.1 GHASH-based J0 for non-96-bit IVs; new `aes_gcm_encrypt_iv`/`_decrypt_iv` + AES-128 variants take `iv_len`; the 8-arg entries stay byte-for-byte 12-byte wrappers. Interop-verified vs OpenSSL (AES-256/128 at 60/8/1-byte IVs; 60-byte = McGrew-Viega TC6/TC18). +24 assertions (new `aes_gcm_iv.tcyr`). Pin 6.0.61→6.0.62. Audit: `docs/audit/2026-06-04-3.7.2-gcm-arbitrary-iv-audit.md`. |
| 3.7.1 | 2026-06-04 | **Solinas reduction for P-384.** `_p384_solinas_reduce` (FIPS 186-4 App. D, `p384 = 2^384−2^128−2^96+2^32−1`), the mirror of the 3.7.0 P-256 work; the 11-term layout was derived from the prime's folding relation + verified 5000/5000 vs `x mod p`. **`ecdsa_p384_verify` 339.2 → 54.6 ms (6.21×)** (`history.csv` row `v3.7.1-p384-solinas`, new `tests/bcyr/ecdsa_p384.bcyr`), transitively speeding the SEV-SNP P-384 chain. +3 assertions (differential KAT). Audit: `docs/audit/2026-06-04-3.7.1-p384-solinas-audit.md`. |
| 3.7.0 | 2026-06-04 | **Opens v3.7 perf — Solinas reduction for P-256.** `_p256_solinas_reduce` (FIPS 186-4 App. D) replaces the bit-by-bit long division on the field reduction (`_p256_reduce_longdiv` retained as the differential-KAT reference). **`ecdsa_p256_verify` 147.5 → 26.1 ms (5.65×)** on 6.0.61 (`history.csv` row `v3.7.0-p256-solinas`), transitively speeding all P-256 chain verifies. The ≤ 10 ms target needs the (carried-forward) EC scalar-mult speedup — reduction alone reached 26 ms. Pin 6.0.58→6.0.61. +3 assertions. Audit: `docs/audit/2026-06-04-3.7.0-p256-solinas-audit.md`. |
| 3.6.8 | 2026-06-04 | **cyrius-native-TLS arc closeout** (last 3.6.x tag). CLAUDE.md Closeout Pass over 3.6.0–3.6.7: full suite green, bench baseline re-captured (no regressions), dead-code + security re-scan clean, stale-comment/doc sweep. Fixed the `_into`-in-3.6 comments (`sgx.cyr`/`tdx.cyr` → gated v3.7) and the stale `benches/sigil.bcyr` path in CLAUDE.md. No functional change; 3.6.x verified API-additive. +0 assertions. Audit: `docs/audit/2026-06-04-3.6.8-closeout-audit.md`. |
| 3.6.7 | 2026-06-04 | **x509 P-384 chain-link verify + AES-128 seal keys.** `_x509_verify_link` dispatches `ecdsa-with-SHA384` issuers (`X509_SIG_ECDSA_SHA384`, `X509_CURVE_P384`) to `ecdsa_p384_verify`; width-parameterized `_ecdsa_der_int_w` (32/48). `sgx_derive_seal_key_n`/`sgx_seal_key_n`/`sgx_unseal_key_n` add a 16-byte AES-128 option (`SGX_SEAL_KEY_SIZE_128`); the 7-arg fns stay byte-for-byte 256-bit wrappers. Cut after a 29-agent adversarial review; its real finding (a latent pre-3.6.7 DER-strictness `sb_np` clobber on the shared ECDSA parse) fixed in-cycle for both curves. +18 assertions. Audit: `docs/audit/2026-06-04-3.6.7-p384-chainlink-aes128-seal-audit.md`. |
| 3.6.6 | 2026-06-04 | **Montgomery on the public-exponent modexp + pem→RSAK.** `bn_modexp`→`bn_mont_modexp` at the verify RSAVP1 + sign-path `r^e`/`s^e` (verify **3.43×**: 11.68→3.40 ms; new `tests/bcyr/rsa.bcyr`, `history.csv` row `v3.6.6-rsa-montgomery`). `pem_decode_privkey` now emits the RSAK struct into `key_out` when `key_max>=RSAK_SIZE` (sentinel = buffer-too-small). Cut after a 24-agent adversarial review; its 1 confirmed LOW (unenforced odd-modulus precondition on the verify ladder) fixed in-cycle (even/zero `n` rejected). +5 assertions. Audit: `docs/audit/2026-06-04-3.6.6-montgomery-pem-rsak-audit.md`. |
| 3.6.5 | 2026-06-04 | **RSA-PSS + x509 RSA chain-link verify.** `rsa_pss_{verify,sign}_sha{256,384}` (RFC 8017 §8.1/§9.1 — MGF1, salt=hLen sign, salt-agnostic verify; shares `_rsa_recover_em`/`_rsa_raw_sign` with the v1.5 surface). `x509_parse` now handles rsaEncryption SPKI (`X509_CURVE_RSA`) + rsa-with-SHA256/384, and `_x509_verify_link` dispatches RSA issuers to `rsa_pkcs1v15_verify_*` (unblocks AMD ARK/ASK RSA-4096+SHA-384). Debt pass: wrote the overdue **3.5.6 audit doc**; surfaced 3 deferrals prior cycles buried in source comments into the roadmap. +30 assertions (rsa +10, new `x509_rsa.tcyr` +20). Pin 6.0.53→6.0.58. Audit: `docs/audit/2026-06-04-3.6.5-pss-x509-rsa-audit.md` (+ retrospective `2026-06-04-3.5.6-hmac-hkdf-sha384-audit.md`). |
| 3.6.4 | 2026-06-03 | **RSA sign hardening + security audit pass.** Base **blinding** (`s=(m·rᵉ)ᵈ·r⁻¹ mod n`, fresh `/dev/urandom` `r`; `bn_modinv` via binary inversion) + **CRT** (Garner, ~4×) on top of the CT Montgomery ladder + verify-after-sign. Signatures unchanged (still match the external Python ref byte-for-byte). Consolidated audit over verify+keys+sign; resolves 3.6.3 LOW-1; caught+fixed a `bn_modinv` non-coprime infinite loop. +5 assertions. Audit: `docs/audit/2026-06-03-3.6.4-rsa-hardening-audit.md`. |
| 3.6.3 | 2026-06-03 | **RSA key parsing + PKCS#1 v1.5 sign** (`src/rsa.cyr`, `src/bignum.cyr`). `rsa_pubkey_from_der` (PKCS#1 + SPKI) + `rsa_privkey_from_der` (PKCS#1 + PKCS#8, reusing x509's audited `der_walk`); `bn_mont_modexp` (constant-time Montgomery/CIOS, == schoolbook KAT); `rsa_pkcs1v15_sign_sha256/384` (CT ladder for secret `d` + verify-after-sign/Bellcore; matches an external Python RSA byte-for-byte). +24 assertions. **CRT + base blinding + security audit pass → 3.6.4.** Audit: `docs/audit/2026-06-03-3.6.3-rsa-keys-sign-audit.md`. |
| 3.6.2 | 2026-06-03 | **RSA PKCS#1 v1.5 verify** (`src/rsa.cyr`, RFC 8017) + general big-integer/modexp engine (`src/bignum.cyr`). `rsa_pkcs1v15_verify_sha256/384`: `m=s^e mod n` via square-and-multiply modexp, then full-EM reconstruction + compare (defeats the Bleichenbacher/BERserk forgery class). Verify-only, public-data (no CT/zeroization need); not on the batch path so unbanked. modexp KAT-validated to RSA-2048 size vs Python `pow`; verify validated vs a real RSA-2048 key (SHA-256/384) + negative cases. +12 assertions. Audit: `docs/audit/2026-06-03-3.6.2-rsa-verify-audit.md`. |
| 3.6.1 | 2026-06-03 | **TLS 1.2 PRF** (`src/tls12_prf.cyr`, RFC 5246 §5) — `tls12_prf_sha256` / `tls12_prf_sha384` (`PRF = P_hash(secret, label‖seed)`) on the existing HMAC primitives. Resolves the cyrius-native-TLS "ship-or-decline" PRF item on the **ship** side. +9 assertions (canonical IETF PRF vectors, Python-reproduced). Pin bump 6.0.52→6.0.53. Audit: `docs/audit/2026-06-03-3.6.1-tls12-prf-audit.md`. |
| 3.6.0 | 2026-06-03 | **Parallel batch verify** — `sv_verify_batch` drops `_sigil_batch_mutex`; crypto runs concurrently across workers. **3.42×** at 64 artifacts / 4 workers (422.867 → 123.563 ms vs `v3.2.0-allocfree`). New `src/crypto_scratch.cyr` gives each worker a private *bank* (lane) of every racing crypto working array (sha256/512 schedules, SHA-NI block scratch, Ed25519 field/group/verify temporaries, `fp_*`/`u512_mod_p` incl. `fp_inv`, `hash_file_into` buffers) via cyrius 6.0.52 thread-local storage — no signature churn. `ge_identity` made alloc-free. Maintenance bump: cyrius 6.0.14→6.0.52, agnosys 1.2.7→1.3.2, sakshi 2.2.5→2.2.6. Race surface verified closed (`batch_parallel.tcyr` mutex-off 35/35). Audit: `docs/audit/2026-06-03-3.6.0-parallel-verify-audit.md`. |
| ≤ 3.5.9 | 2026-05-28 ↓ | **Trimmed** — the 3.5 modern-crypto arc (Poly1305 / ChaCha20 / ChaCha20-Poly1305 / X25519, HMAC-/HKDF-SHA384, AES-128-GCM, EC + Ed25519 key parsers, ECDSA P-256/P-384 sign) and the 3.4.x / 3.3.0 cycles. See [`CHANGELOG.md`](../../CHANGELOG.md) for per-version detail. |

See [`CHANGELOG.md`](../../CHANGELOG.md) for the full history
back to v2.0.0.

## In-flight slots

Open slots only. Shipped 3.5.x / 3.6.0–3.6.5 bites are trimmed here on
completion — see "Recently shipped" above, CHANGELOG, and the roadmap's
"Outstanding work — full inventory" block (the authoritative remaining
list).

| Slot | State | Notes |
|---|---|---|
| 3.9.x — thread-safety banking arc | **COMPLETED at 3.9.7** | Every reachable concurrent crypto path is now race-free. 3.9.6 fixed the concurrent-TLS-handshake crash (`cbank()` auto-assigns a per-thread lane, `SIGIL_CRYPTO_BANKS` 8→64; banked HKDF/HMAC/`ed25519_sign`/one-shot-SHA/AES-GCM/Poly1305) — see [ADR 0007](../adr/0007-auto-banking-for-concurrent-tls.md). 3.9.7 closed out the carried items: streaming Poly1305 (`_cp_tag` last `fl_alloc` gone), ECDSA P-256/P-384 sign+verify incl. DER wrappers + RFC 6979 DRBG, bignum/rsa/tls12_prf; fixed the latent `secret var`-array DER-wrapper race (TLS CertificateVerify path) + closed an RSA-sign secret-residue gap. Audits: `2026-06-29-3.9.6-…` + `2026-06-29-3.9.7-…`. |
| 3.8.x — housekeeping bookend | **CLOSED at 3.8.1** | 3.8.0 ChaCha20 + X25519 per-worker banking + backlog-accuracy sweep + Windows-entropy issue archived. **3.8.1 dropped the `agnosys` dependency** — trust primitives internalized as `src/*_core.cyr` + `src/sys_error.cyr` / `src/sys_util.cyr`; `cyrius.cyml [deps]` now lists **only sakshi (2.3.0)**. |
| 3.7.x — EC scalar-mult ≤ 10 ms squeeze | **CLOSED 2026-06-16 — not reachable with current approaches ([ADR 0006](../adr/0006-park-ec-scalarmul-10ms-target.md))** | Levers 1 (inversion chains), 2a (comb-G mixed add), 2b (`u2·Q` batch-inv mixed add), 3 (Karatsuba `u256_mul_full`, ~3–4% across all 256-bit ECC) all shipped. `ecdsa_p256_verify` 12.50 → **~10.9 ms** (~13% cumulative). **≤ 10 ms unreached — known approaches exhausted** (verify is doubling/inversion-bound; Karatsuba caps at ~3–4% at 256-bit). **Closed (Robert, 2026-06-16) as "not reachable with current approaches."** Exotic levers (asm multiply / alt point representation) **parked to the roadmap Backlog, not a current priority** (revisit only on a hard consumer latency requirement). |
| 3.7.x — buried-deferral gate | **completed (superseded by `cyrlint`)** | Built natively into `cyrlint` instead of a sigil-local script — covers every AGNOS repo. Flags any untracked deferral (must cross-reference a CHANGELOG/issue/roadmap entry, or carry `#skip-lint`). The 2 `\uXXXX` false positives (`src/policy.cyr`) are `#skip-lint`-suppressed; `cyrlint src/*.cyr` = 0 untracked deferrals. |

**No open in-flight slots.** The 3.6.x cyrius-native-TLS arc **closed**
(3.6.0–3.6.8); the v3.7 EC-squeeze cycle **closed** at 3.7.17 (≤ 10 ms not
reached, ~10.9 ms floor, parked per ADR 0006); the 3.8.x housekeeping bookend
**closed** at 3.8.1 (ChaCha20/X25519 banking, backlog-accuracy sweep,
Windows-entropy issue archived, **agnosys dependency dropped**); and the 3.9.x
thread-safety-banking arc **completed** at 3.9.7 — **every reachable concurrent
crypto path is race-free** (concurrent-TLS crash fixed at 3.9.6 via auto-lane
banking; streaming Poly1305 / ECDSA P-256/P-384 sign+verify+DER / bignum / rsa /
tls12_prf banked at 3.9.7; latent DER-wrapper race + RSA-sign residue closed).

**Carried-forward roadmap Backlog (genuinely open — do NOT bury):**
the EC ≤ 10 ms exotic levers (asm multiply / alt point representation, per
ADR 0006), the TDX/SGX in-quote PCK X.509 chain walk, retire-bank-indexing,
scatter-store, CLMUL-GHASH, ML-KEM-768, the `#derive(Serialize)` completeness
backlog, the Windows-entropy `cass` ProcessPrng runtime confirmation, and
retire-sysinfo — several remain blocked on cyrius `asm` global-symbol /
thread-local-array features. See [`roadmap.md`](roadmap.md) "Outstanding work —
full inventory" for the authoritative list.

When a cycle is opened, list each work-item bite here as it
moves through `pending → in_progress → completed`. The release
post-hook (or release author) trims the rows on minor close.

## Bootstrap / verification hosts

Sigil currently has no dedicated verification hosts beyond the
dev host (Linux 7.0.9-arch1-1, x86_64). Cross-host smoke
wrapper is not yet scaffolded — when AGNOS gains a cross-host
CI fleet, list the hosts here.

## Audit floor

**EMPTY — cleared at 3.7.3, holds through 3.9.7.** Zero findings of any
severity outstanding. The 3.9.6 and 3.9.7 banking audits resolved **every**
finding in-cycle: 3.9.6 (`2026-06-29-3.9.6-concurrent-tls-handshake-banking-audit.md`)
closed the concurrent-TLS-handshake crash via auto-lane banking; 3.9.7
(`2026-06-29-3.9.7-ecdsa-bignum-banking-audit.md`) found and fixed **F1 MEDIUM**
(latent `secret var`-array race in the ECDSA `*_sign_der`/`verify_der` wrappers —
the TLS CertificateVerify path) and **F2 LOW** (pre-existing RSA-sign
secret-residue gap), both **fixed before ship**, with F3 (`secret var` arrays =
shared statics) documented; red→green race-detectors. Earlier, the 3.7.5
off-diagonal ECDSA change passed a 4-lens adversarial review with no
false-accept and only one confirmed finding (a stale `dist/` bundle) + one LOW
(parse scratch reuse), **both resolved in-cycle** — see
`docs/audit/2026-06-07-3.7.5-offdiag-ecdsa-audit.md`. The eight prior LOWs (all
bump-allocator-lifetime shape) were resolved as follows:

**Resolved via the `_into` caller-scratch API (3.7.3)** — genuine
per-call drift, now with a drift-free path (the one-shot bump wrappers
remain, documented as one-shot-suitable):

- 3.2.2 LOW-1: `x509_parse` raw_sig alloc → `x509_parse_into`
- 3.6.5 LOW-1: `x509_parse` RSA pubkey side block → `x509_parse_into`
- 3.4.0 LOW-1: `sgx`/`tdx_quote_verify_full` drift → `*_verify_full_into`
- 3.4.1 LOW-1: `snp_report_verify_full` drift → `snp_report_verify_full_into`

**Reclassified as correct (3.7.3)** — init-once-guarded singletons, the
`alloc()`-for-init-once-tables pattern CLAUDE.md endorses (quirk #2);
they were over-conservatively flagged and never drifted:

- 3.2.4 LOW-1: `_snp_v_init` (init-once, guarded)
- 3.4.0 LOW-2: `_pem_init` lookup tables (init-once, guarded)
- 3.2.3 / 3.2.5: `_sgxv_init` / `_tdxv_init` (init-once, guarded)

Zero CRITICAL / HIGH / MEDIUM / LOW findings outstanding.

## Open architectural blockers

**None on the critical path.** The modern-crypto surface that was once
"gated on the cyrius native-TLS slot" — Poly1305, ChaCha20, ChaCha20-Poly1305
AEAD, X25519 — has all **shipped** (3.5 arc), and the concurrent-crypto banking
arc (3.6 parallel verify → 3.9.7 full thread-safety) is **complete**: every
reachable concurrent crypto path is race-free. The remaining items are roadmap
**Backlog**, not blockers — the exotic EC ≤ 10 ms levers (asm / alt point
representation, ADR 0006) and the TDX/SGX in-quote PCK X.509 chain walk, plus
retire-bank-indexing / scatter-store / CLMUL-GHASH / ML-KEM-768, several still
blocked on absent cyrius `asm` global-symbol / thread-local-array features. See
[`roadmap.md`](roadmap.md) for the full Backlog inventory.

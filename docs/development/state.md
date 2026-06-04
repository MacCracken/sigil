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
| Current version | **3.7.3** (`VERSION`) |
| Cyrius toolchain pin | **6.0.62** (`cyrius.cyml [package].cyrius`) |
| Dependencies | agnosys **1.3.2**, sakshi **2.2.6** |
| Last release date | 2026-06-04 |
| Last release audit | [`2026-06-04-3.7.3-into-api-audit.md`](../audit/2026-06-04-3.7.3-into-api-audit.md) |
| Phase | Released. **3.7.3 added the caller-scratch `_into` API and cleared the audit floor (8 LOW → 0).** New `x509_parse_into` / `x509_cert_alloc_into` + `sgx`/`tdx`/`snp` `*_verify_full_into` draw all per-call scratch from a caller arena (stdlib `arena_new`; `arena_reset` between verifications) — drift-free for a looping consumer; the original entries stay byte-for-byte `arena==0` wrappers. Of the 8 audit-floor LOWs: 4 genuine per-call-drift findings (x509 raw_sig, RSA block, SGX/TDX/SNP orchestrator drift) are **resolved** via the `_into` path; 4 (`_sgxv_init`/`_tdxv_init`/`_snp_v_init`/`_pem_init` tables) are **reclassified as correct** init-once singletons (never drifted). **Remaining v3.7:** EC scalar-mult speedup (carries ≤ 10 ms) + full bench re-run. |

## Test surface

| Metric | Value |
|---|---|
| `.tcyr` test files | 52 |
| Total assertions | **1431**, 0 failures |
| Benchmark suite | `benches/` — `history.csv`; RSA via `tests/bcyr/rsa.bcyr`, P-256/P-384 verify via `tests/bcyr/ecdsa_p256.bcyr` / `ecdsa_p384.bcyr` |

> Counting note: the 3 `*_verify_full.tcyr` tests (sgx 17 + tdx 16 +
> snp 11 = 44) emit their `N passed` summary in a tty-sensitive way that
> is dropped under any pipe or file redirect, so a scripted `grep`-sum of
> `cyrius test` output yields **1387** across the other 49 files and
> silently omits those 44. Add them back for the true total: **1431**.
> (Each verify_full still prints its summary on an interactive run; it's
> only the redirected/scripted sum that loses them.)

Per-cycle assertion delta:

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
| 3.7.4 — EC scalar-mult speedup | pending (next) | Fixed-base comb for `G` + wNAF for `Q`; **carries the ≤ 10 ms `ecdsa_p256_verify` target** (Solinas reduction alone reached 26 ms P-256 / 55 ms P-384). |
| 3.7.x — full crypto bench re-run | pending | Capture before/after rows for every verify-path bench at the cycle close. |

The 3.6.x cyrius-native-TLS arc is **closed** (3.6.0–3.6.8). The **v3.7
perf cycle is OPEN**: Solinas P-256 (3.7.0), Solinas P-384 (3.7.1),
AES-GCM arbitrary IVs (3.7.2), and the caller-scratch `_into` API +
audit-floor clear (3.7.3) shipped. **Next: 3.7.4 = EC scalar-mult
speedup.** Backlog: the one ungated item (AES-GCM IVs) is done; the
bank-retire / CLMUL-GHASH / NI-dispatch items remain blocked on cyrius
features absent in 6.0.62.

When a cycle is opened, list each work-item bite here as it
moves through `pending → in_progress → completed`. The release
post-hook (or release author) trims the rows on minor close.

## Bootstrap / verification hosts

Sigil currently has no dedicated verification hosts beyond the
dev host (Linux 7.0.9-arch1-1, x86_64). Cross-host smoke
wrapper is not yet scaffolded — when AGNOS gains a cross-host
CI fleet, list the hosts here.

## Audit floor

**EMPTY — cleared at 3.7.3.** Zero findings of any severity outstanding
(first time since the 3.2.x TEE arc). The eight prior LOWs (all
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

None on the critical path. Roadmap cycles 3.6 (parallel verify)
and 3.7 (perf tuning) both have explicit "open when forcing
function arrives" sequencing decisions; neither has triggered
as of the 3.5 open. The 3.5 cycle itself (modern AEAD + key
agreement) is open: Poly1305 lands standalone now, while
ChaCha20 / AEAD / X25519 stay gated on the cyrius v6.2.x
native-TLS slot.

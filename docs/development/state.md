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
| Current version | **3.6.4** (`VERSION`) |
| Cyrius toolchain pin | **6.0.53** (`cyrius.cyml [package].cyrius`) |
| Dependencies | agnosys **1.3.2**, sakshi **2.2.6** |
| Last release date | 2026-06-03 |
| Last release audit | [`2026-06-03-3.6.4-rsa-hardening-audit.md`](../audit/2026-06-03-3.6.4-rsa-hardening-audit.md) |
| Phase | Released. **3.6.4 hardened the RSA signer** — **base blinding** (`bn_modinv` + `/dev/urandom`) + **CRT** (~4×) on top of the CT Montgomery ladder + verify-after-sign — plus a consolidated **security audit pass** over the whole RSA surface (resolves the 3.6.3 blinding LOW). The RSA PKCS#1 v1.5 surface (verify + keys + sign) is now complete. 3.6.x history: 3.6.3 RSA key parse + v1.5 sign; 3.6.2 RSA v1.5 verify + bignum engine; 3.6.1 TLS 1.2 PRF; 3.6.0 parallel verify (mutex drop, 3.42×). **Remaining 3.6.x (3.6.5+):** **PSS** (verify+sign), Montgomery-on-verify + bench, `pem_decode_privkey` RSAK wiring, and the **cyrius-native-TLS closeout** (was 3.5.12). 3.7 (EC Solinas + bignum Barrett/Montgomery perf) gated on a forcing function. |

## Test surface

| Metric | Value |
|---|---|
| `.tcyr` test files | 50 |
| Total assertions | **1334**, 0 failures |
| Benchmark suite | `benches/` — see `benches/history.csv` |

> Counting note: the 3 `*_verify_full.tcyr` tests (sgx 11 + tdx 16 +
> snp 11 = 38) emit their `N passed` summary in a tty-sensitive way
> that is dropped under any pipe or file redirect, so a scripted
> `grep`-sum of `cyrius test` output yields **1255** across the 48
> files and silently omits those 38. Add them back for the true
> total: **1293**. (Each verify_full still prints its summary on an
> interactive run; it's only the redirected/scripted sum that loses
> them.)

Per-cycle assertion delta:

- 3.6.4 ship: +5 (`bignum.tcyr` +5 — `bn_modinv` self-check `r·r^-1 ≡ 1 mod n` at 256/2048-bit + the non-coprime `-1` path; the blinded+CRT signer reuses the existing `rsa.tcyr` deterministic-KAT assertions)
- 3.6.3 ship: +24 (`rsa.tcyr` +21 — pubkey/privkey DER parse incl. p·q==n, deterministic PKCS#1 v1.5 sign matching an external Python RSA byte-for-byte SHA-256/384, sign→verify roundtrips; `bignum.tcyr` +3 — CT Montgomery modexp == schoolbook at 256/2048-bit)
- 3.6.2 ship: +12 (`bignum.tcyr` 6 — modexp KATs incl. full RSA-2048-size `s^65537 mod n`, all vs Python `pow`; serialize round-trip; `base^0`/`0^e` edges. `rsa.tcyr` 6 — real RSA-2048 PKCS#1 v1.5 SHA-256/384 verify accept + tamper/wrong-message/wrong-length/hash-mismatch reject)
- 3.6.1 ship: +9 (`tls12_prf.tcyr` 9 — canonical RFC 5246 §5 PRF vectors: P_SHA256 100-byte + P_SHA384 148-byte (Python `hmac`/`hashlib`-reproduced; SHA-256 matched the published vector), truncation prefixes (12 + 48 byte), determinism, over-cap guard)
- 3.6.0 ship: +0 (parallel-verify refactor — no new test assertions; correctness is covered by the full suite at bank 0 plus `batch_parallel.tcyr` (228 assertions) run **mutex-off as the race detector**: 35/35 consecutive clean runs. The first mutex-off run failed and surfaced the un-banked `fp_inv` / `hash_file_into` buffers.)
- 3.5.9 ship: +20 (`ecdsa_sign.tcyr` 20 — exact RFC 6979 A.2.5/A.2.6 (r‖s) for P-256/P-384 "sample"/"test", determinism, sign→verify roundtrips raw + DER, DER structure)
- 3.5.8 ship: +33 (`privkey.tcyr` 33 — Ed25519 PKCS#8 seed parse + derive + sign/verify, ECDSA P-256/P-384 SEC1 + PKCS#8 scalar parse, curve/OID/truncation rejection, and the `pem_decode_privkey` label+algo dispatch for all 5 EC/Ed25519 forms + RSA sentinel)
- 3.5.7 ship: +15 (`aes128_gcm.tcyr` 15 — canonical GCM AES-128 Test Cases 1–4 (empty / single-block / 4-block / AAD+partial) + decrypt roundtrip + one-bit tag-flip rejection with pt_out-zeroed checks + empty roundtrip)
- 3.5.6 ship: +19 (`hkdf_sha384.tcyr` 19 — RFC 4231 §4 HMAC-SHA384 TC1–4/6/7 + 3 HKDF-SHA384 vectors cross-verified vs Python `hmac`/`hashlib` and `openssl kdf` + cap/zero-length edges)
- 3.5.5 ship: 0 (doc-comment pass — 76 bundle-API functions documented; `cyrius doc --check dist/sigil.cyr` 76→0; no test surface change)
- 3.5.4 ship: 0 (closeout — arc-audit consolidation + bench cases + doc sync; no test surface change)
- 3.5.3 ship: +6 (`x25519.tcyr` 6 — RFC 7748 §5.2 vectors 1-2 + §6.1 Diffie-Hellman)
- 3.5.2 ship: +5 (`chacha20poly1305.tcyr` 5 — RFC 8439 §2.8.2 ciphertext + tag, round-trip, tamper-reject)
- 3.5.1 ship: +3 (`chacha20.tcyr` 3 — RFC 8439 §2.3.2 keystream + §2.4.2 sunscreen + round-trip)
- 3.5.0 ship: +5 (`poly1305.tcyr` 5 — RFC 8439 §2.5.2 canonical vector + all-zero + r=0 property + constant-time verify)
- 3.4.0 ship: +66 (`pem.tcyr` 39, `sgx_verify_full.tcyr` 11, `tdx_verify_full.tcyr` 16)
- 3.4.1 ship: +23 (`x509_p384.tcyr` 12, `snp_verify_full.tcyr` 11)
- 3.4.2 ship: 0 (packaging-fix release; no source changes)
- 3.4.3 ship: 0 (defense-in-depth refactor; `secret var` adoption on 12 aes_gcm stack locals — no test surface change)

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
| 3.6.4 | 2026-06-03 | **RSA sign hardening + security audit pass.** Base **blinding** (`s=(m·rᵉ)ᵈ·r⁻¹ mod n`, fresh `/dev/urandom` `r`; `bn_modinv` via binary inversion) + **CRT** (Garner, ~4×) on top of the CT Montgomery ladder + verify-after-sign. Signatures unchanged (still match the external Python ref byte-for-byte). Consolidated audit over verify+keys+sign; resolves 3.6.3 LOW-1; caught+fixed a `bn_modinv` non-coprime infinite loop. +5 assertions. Audit: `docs/audit/2026-06-03-3.6.4-rsa-hardening-audit.md`. |
| 3.6.3 | 2026-06-03 | **RSA key parsing + PKCS#1 v1.5 sign** (`src/rsa.cyr`, `src/bignum.cyr`). `rsa_pubkey_from_der` (PKCS#1 + SPKI) + `rsa_privkey_from_der` (PKCS#1 + PKCS#8, reusing x509's audited `der_walk`); `bn_mont_modexp` (constant-time Montgomery/CIOS, == schoolbook KAT); `rsa_pkcs1v15_sign_sha256/384` (CT ladder for secret `d` + verify-after-sign/Bellcore; matches an external Python RSA byte-for-byte). +24 assertions. **CRT + base blinding + security audit pass → 3.6.4.** Audit: `docs/audit/2026-06-03-3.6.3-rsa-keys-sign-audit.md`. |
| 3.6.2 | 2026-06-03 | **RSA PKCS#1 v1.5 verify** (`src/rsa.cyr`, RFC 8017) + general big-integer/modexp engine (`src/bignum.cyr`). `rsa_pkcs1v15_verify_sha256/384`: `m=s^e mod n` via square-and-multiply modexp, then full-EM reconstruction + compare (defeats the Bleichenbacher/BERserk forgery class). Verify-only, public-data (no CT/zeroization need); not on the batch path so unbanked. modexp KAT-validated to RSA-2048 size vs Python `pow`; verify validated vs a real RSA-2048 key (SHA-256/384) + negative cases. +12 assertions. Audit: `docs/audit/2026-06-03-3.6.2-rsa-verify-audit.md`. |
| 3.6.1 | 2026-06-03 | **TLS 1.2 PRF** (`src/tls12_prf.cyr`, RFC 5246 §5) — `tls12_prf_sha256` / `tls12_prf_sha384` (`PRF = P_hash(secret, label‖seed)`) on the existing HMAC primitives. Resolves the cyrius-native-TLS "ship-or-decline" PRF item on the **ship** side. +9 assertions (canonical IETF PRF vectors, Python-reproduced). Pin bump 6.0.52→6.0.53. Audit: `docs/audit/2026-06-03-3.6.1-tls12-prf-audit.md`. |
| 3.6.0 | 2026-06-03 | **Parallel batch verify** — `sv_verify_batch` drops `_sigil_batch_mutex`; crypto runs concurrently across workers. **3.42×** at 64 artifacts / 4 workers (422.867 → 123.563 ms vs `v3.2.0-allocfree`). New `src/crypto_scratch.cyr` gives each worker a private *bank* (lane) of every racing crypto working array (sha256/512 schedules, SHA-NI block scratch, Ed25519 field/group/verify temporaries, `fp_*`/`u512_mod_p` incl. `fp_inv`, `hash_file_into` buffers) via cyrius 6.0.52 thread-local storage — no signature churn. `ge_identity` made alloc-free. Maintenance bump: cyrius 6.0.14→6.0.52, agnosys 1.2.7→1.3.2, sakshi 2.2.5→2.2.6. Race surface verified closed (`batch_parallel.tcyr` mutex-off 35/35). Audit: `docs/audit/2026-06-03-3.6.0-parallel-verify-audit.md`. |
| 3.5.9 | 2026-05-28 | ECDSA P-256/P-384 deterministic signing (`src/ecdsa_sign.cyr`) — `ecdsa_p256_sign` / `ecdsa_p384_sign` (+`_der`), RFC 6979 §3.2 HMAC_DRBG nonce (HMAC-SHA256/384). Raw `r‖s` + DER (TLS 1.3 CertificateVerify). Consumes the 3.5.8 scalars; pairs with verify. Exact RFC 6979 A.2.5/A.2.6 vectors (+20 assertions). Benches: P-256 74 ms / P-384 179 ms. Pin unchanged (6.0.14). Audit: `docs/audit/2026-05-28-3.5.9-ecdsa-sign-audit.md`. |
| 3.5.8 | 2026-05-28 | EC + Ed25519 private-key parsers (`src/privkey.cyr`) — `ed25519_privkey_from_der` (PKCS#8/RFC 8410), `ecdsa_p256_privkey_from_der` / `ecdsa_p384_privkey_from_der` (SEC1 + PKCS#8 → big-endian scalar), `pem_decode_privkey` (auto-detect label + algo, reuses the `pem.cyr` base64 decoder). RSA label recognized → `0 - SIG_PRIVKEY_RSA` sentinel (the RSA DER parser `rsa_privkey_from_der` shipped 3.6.3). First half of issue line item 4. +33 assertions. Pin unchanged (6.0.14). Audit: `docs/audit/2026-05-28-3.5.8-privkey-parsers-audit.md`. |
| 3.5.7 | 2026-05-28 | AES-128-GCM (`src/aes_gcm.cyr` + `src/aes_ni.cyr`) — `aes_128_key_expand` (16-byte key → 176-byte / 11-key schedule, Nk=4/Nr=10) + `aes_128_gcm_encrypt` / `aes_128_gcm_decrypt`, mirroring the AES-256 surface; 10-round `aes128_encrypt_block_ni` AES-NI path gated by a FIPS 197 §C.1 boot self-test. RFC 8446 §9.1 mandatory `TLS_AES_128_GCM_SHA256` (0x1301) + the four TLS 1.2 `*_WITH_AES_128_GCM_SHA256` suites. Block/CTR/GCM machinery parametrized on round count; AES-256 path unchanged. +15 assertions. Cyrius pin 6.0.12 → 6.0.14. First of the 5 line items in `docs/development/issues/2026-05-28-cyrius-tls-arc-full-audit.md`. Audit: `docs/audit/2026-05-28-3.5.7-aes128-gcm-audit.md`. |
| 3.5.6 | 2026-05-28 | HMAC-SHA384 + HKDF-SHA384 (`src/hmac_sha384.cyr`, `src/hkdf_sha384.cyr`) — `hmac_sha384` (FIPS 198-1 / RFC 4231, 128-byte block / 48-byte digest) + `hkdf_extract_sha384` / `hkdf_expand_sha384` / `hkdf_sha384` (RFC 5869, max OKM 255×48). Forcing-function for the cyrius native TLS 1.3 arc — unblocks held cyrius v6.0.13 `TLS_AES_256_GCM_SHA384` (0x1302) key schedule. +19 assertions (RFC 4231 §4 + 3 cross-verified HKDF vectors). Cyrius pin 6.0.3 → 6.0.12. Resolves `docs/development/issues/2026-05-28-cyrius-tls-native-needs-hkdf-sha384.md`. |
| 3.5.5 | 2026-05-27 | Bundle-API doc-comment pass — `cyrius doc --check dist/sigil.cyr` 76 undocumented → 0 (88 public fns). Doc comments added across `types`/`sha256`/`error`/`hex`/`hkdf`/`hmac`/`sha_ni`; dist regenerated. Prerequisite for upstreaming sigil into the main Cyrius language. No source-logic change. |
| 3.5.4 | 2026-05-27 | Closeout of the 3.5 cycle — consolidated the four per-bite audits into `docs/audit/2026-05-27-3.5-arc-audit.md`; added ChaCha20/Poly1305/AEAD/X25519 bench cases (`history.csv` row `v3.5.4-modern-crypto`); refreshed `doc-health.md` + `overview.md` map + ADR 0001/0003 renumber amendments. No source change. |
| 3.5.3 | 2026-05-27 | X25519 key agreement (RFC 7748) — `src/x25519.cyr`: `x25519` + `x25519_base`, Montgomery ladder over the `bigint_ext` Curve25519 field arithmetic, constant-time `cswap`. Closes the 3.5 cycle; the TLS 1.3 `ChaCha20-Poly1305 + X25519` suite is now sigil-native. Audit: `docs/audit/2026-05-27-3.5-arc-audit.md`. |
| 3.5.2 | 2026-05-27 | ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) — `src/chacha20poly1305.cyr`: `chacha20poly1305_encrypt` + constant-time-verifying `chacha20poly1305_decrypt`. Composes the 3.5.1 cipher + 3.5.0 MAC into TLS 1.3's `TLS_CHACHA20_POLY1305_SHA256`. Audit: `docs/audit/2026-05-27-3.5-arc-audit.md`. |
| 3.5.1 | 2026-05-27 | ChaCha20 stream cipher (RFC 8439 §2.3/§2.4) — `src/chacha20.cyr`: `chacha20_block` + `chacha20_xor`, 20-round ARX, constant-time by construction. Second bite of the 3.5 cycle; prereq for the ChaCha20-Poly1305 AEAD. Audit: `docs/audit/2026-05-27-3.5-arc-audit.md`. |
| 3.5.0 | 2026-05-27 | Poly1305 one-time MAC (RFC 8439 §2.5) — `src/poly1305.cyr`: `poly1305_mac` + constant-time `poly1305_verify`, 26-bit-limb donna form (no 128-bit path), constant-time freeze. Opens the 3.5 AEAD + key-agreement cycle; ships standalone ahead of the cyrius native-TLS arc. Cyrius pin bumped 6.0.1 → 6.0.3. Audit: `docs/audit/2026-05-27-3.5-arc-audit.md`. |
| 3.4.3 | 2026-05-23 | `secret var` adoption sweep on `src/aes_gcm.cyr` — 12 stack-local secret buffers (GHASH H/state, AES-CTR keystream, tag, GHASH mul scratch) gain compiler-emitted zeroization on every return including early-exit errors. Closes the "secret var ambient adoption" backlog item. |
| 3.4.2 | 2026-05-22 | Packaging fix — `dist/sigil.cyr` regenerated from current source (was frozen at 3.2.0 era); `scripts/regen-dist.sh` shipped to replace the retired `cyrius distlib` subcommand. Doc-tree restructure rides along. |
| 3.4.1 | 2026-05-22 | SEV-SNP attestation completion (x509 P-384 SPKI + `snp_report_verify_full`) |
| 3.4.0 | 2026-05-22 | TEE attestation completion (PEM decoder, `sgx`/`tdx_quote_verify_full`, TDX `att_key_type=3`) |
| 3.3.0 | 2026-05-22 | Cleanup / refactor cycle (−190 LOC; mutex-drop deferred to 3.5 after `var X[N]` static-array discovery) |

See [`CHANGELOG.md`](../../CHANGELOG.md) for the full history
back to v2.0.0.

## In-flight slots

Open slots only. Shipped 3.5.x / 3.6.0–3.6.4 bites are trimmed here on
completion — see "Recently shipped" above, CHANGELOG, and the roadmap's
"Outstanding work — full inventory" block (the authoritative remaining
list).

| Slot | State | Notes |
|---|---|---|
| 3.6.5+ — cyrius-native-TLS tail | pending | RSA-**PSS** (MGF1) verify+sign SHA-256/384; **Montgomery on the verify path** + RSA verify/sign benches; wire `pem_decode_privkey` → RSAK struct; **cyrius-native-TLS closeout** (full Closeout Pass + the deferred 3.5.6 HMAC/HKDF-SHA384 audit doc). |
| 3.7 — perf / Solinas | Gated | Solinas word-level reduction for P-256/P-384 + unified `_into` API (closes the 7 audit-floor LOWs). Gated on a latency forcing function per roadmap. |

When a cycle is opened, list each work-item bite here as it
moves through `pending → in_progress → completed`. The release
post-hook (or release author) trims the rows on minor close.

## Bootstrap / verification hosts

Sigil currently has no dedicated verification hosts beyond the
dev host (Linux 7.0.9-arch1-1, x86_64). Cross-host smoke
wrapper is not yet scaffolded — when AGNOS gains a cross-host
CI fleet, list the hosts here.

## Audit floor

Seven open LOW findings of the same shape (bump-allocator
lifetime across per-call init paths) carry forward to the v3.7
unified `_into` API cycle:

- 3.2.2 LOW-1: `x509_parse` raw_sig alloc
- 3.2.4 LOW-1: `_snp_v_init` alloc
- 3.4.0 LOW-1: `sgx_quote_verify_full` / `tdx_quote_verify_full` drift
- 3.4.0 LOW-2: `_pem_init` lookup-table alloc
- 3.4.1 LOW-1: `snp_report_verify_full` drift
- (and the two from `_sgxv_init` / `_tdxv_init` audited at 3.2.3 / 3.2.5)

Zero CRITICAL / HIGH / MEDIUM findings outstanding.

## Open architectural blockers

None on the critical path. Roadmap cycles 3.6 (parallel verify)
and 3.7 (perf tuning) both have explicit "open when forcing
function arrives" sequencing decisions; neither has triggered
as of the 3.5 open. The 3.5 cycle itself (modern AEAD + key
agreement) is open: Poly1305 lands standalone now, while
ChaCha20 / AEAD / X25519 stay gated on the cyrius v6.2.x
native-TLS slot.

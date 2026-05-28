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
| Current version | **3.5.8** (`VERSION`) |
| Cyrius toolchain pin | **6.0.14** (`cyrius.cyml [package].cyrius`) |
| Last release date | 2026-05-28 |
| Last release audit | [`2026-05-28-3.5.8-privkey-parsers-audit.md`](../audit/2026-05-28-3.5.8-privkey-parsers-audit.md) |
| Phase | Released; **3.5 cycle CLOSED** (3.5.0–3.5.4). 3.5.5 doc-comment patch. 3.5.6 added HMAC-SHA384 + HKDF-SHA384 (first cyrius native-TLS forcing function). **3.5.7 (current) added AES-128-GCM** (`aes_128_key_expand` / `aes_128_gcm_encrypt` / `aes_128_gcm_decrypt` + 10-round AES-NI path) — RFC 8446 §9.1 mandatory `TLS_AES_128_GCM_SHA256` (0x1301); issue `2026-05-28-cyrius-tls-arc-full-audit.md` line item 1. **3.5.x line continues for the rest of the cyrius native-TLS arc**: **3.5.8** private-key parsers (PEM+DER) → **3.5.9** ECDSA P-256/P-384 sign → **3.5.10** RSA sign+verify (Large/splittable) → **3.5.11** TLS 1.2 PRF (optional) → **3.5.12** closeout (last 3.5.x tag; Closeout Pass over the whole 3.5.5–3.5.11 delta + the deferred 3.5.6 audit). Then 3.6 (parallel verify) / 3.7 (perf), both gated on forcing functions. |

## Test surface

| Metric | Value |
|---|---|
| `.tcyr` test files | 46 |
| Total assertions | **1264**, 0 failures |
| Benchmark suite | `benches/` — see `benches/history.csv` |

> Counting note: 3 `*_verify_full.tcyr` tests print their
> `N passed` line to stderr; capture with `2>&1` or the total
> undercounts by 38 (sgx 11 + tdx 16 + snp 11). 1216 is the
> stderr-inclusive total across all 44 files.

Per-cycle assertion delta:

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
| 3.5.8 | 2026-05-28 | EC + Ed25519 private-key parsers (`src/privkey.cyr`) — `ed25519_privkey_from_der` (PKCS#8/RFC 8410), `ecdsa_p256_privkey_from_der` / `ecdsa_p384_privkey_from_der` (SEC1 + PKCS#8 → big-endian scalar), `pem_decode_privkey` (auto-detect label + algo, reuses the `pem.cyr` base64 decoder). RSA label recognized → `0 - SIG_PRIVKEY_RSA` sentinel (parser lands in 3.5.10). First half of issue line item 4. +33 assertions. Pin unchanged (6.0.14). Audit: `docs/audit/2026-05-28-3.5.8-privkey-parsers-audit.md`. |
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

| Slot | State | Notes |
|---|---|---|
| 3.5 cycle (3.5.0–3.5.4) | **Closed** 2026-05-27 | Modern-crypto arc — Poly1305, ChaCha20, ChaCha20-Poly1305 AEAD, X25519, + closeout. TLS 1.3 suite complete. Per-bite rows trimmed on minor close; see CHANGELOG + `docs/audit/2026-05-27-3.5-arc-audit.md`. |
| 3.5.6 | **Shipped** 2026-05-28 | HMAC-SHA384 + HKDF-SHA384 — first cyrius native-TLS forcing function. |
| 3.5.7 — AES-128-GCM | **Shipped** 2026-05-28 | `aes_128_key_expand` / `aes_128_gcm_encrypt` / `_decrypt` + 10-round AES-NI. RFC 8446 §9.1 mandatory `TLS_AES_128_GCM_SHA256` + 4 TLS 1.2 suites. Cyrius slot v6.0.14 unblocked. |
| 3.5.8 — EC + Ed25519 privkey parsers | **Shipped** 2026-05-28 | `src/privkey.cyr`: PEM + DER for ECDSA P-256/P-384 (SEC1/PKCS#8) + Ed25519 (PKCS#8/RFC 8410) + `pem_decode_privkey`. RSA parser deferred to 3.5.10 (no RSA key type until the engine lands). Cyrius v6.0.15 / .23 unblocked (key-loading side). |
| 3.5.9 — ECDSA sign | pending | `ecdsa_p256_sign` / `ecdsa_p384_sign` (+`_der`), RFC 6979 deterministic-k. Cyrius v6.0.17 / .25. |
| 3.5.10 — RSA engine + parser + sign/verify | pending | Bignum modexp engine + RSA key type + `rsa_privkey_from_der` (moved from 3.5.8) + PKCS#1 v1.5 + PSS, SHA-256/384. **Large/splittable** (`bigint_ext` is Curve25519-only). Cyrius v6.0.17 / .25 / .29–.34. |
| 3.5.11 — TLS 1.2 PRF | pending (optional) | `tls12_prf_sha256/384` — ship-or-decline; cyrius keeps inline if declined. Cyrius v6.0.29–.34. |
| 3.5.12 — closeout | **last 3.5.x tag** | Closeout Pass over the 3.5.5–3.5.11 delta + deferred 3.5.6 audit doc. Ships before 3.6 opens. |
| 3.6 / 3.7 | Gated | Parallel verify (3.6) and perf tuning / Solinas (3.7) remain gated on forcing functions per roadmap. |

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

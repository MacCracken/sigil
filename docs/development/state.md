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
| Current version | **3.5.2** (`VERSION`) |
| Cyrius toolchain pin | **6.0.3** (`cyrius.cyml [package].cyrius`) |
| Last release date | 2026-05-27 |
| Last release audit | [`2026-05-27-3.5.2-audit.md`](../audit/2026-05-27-3.5.2-audit.md) |
| Phase | Released; **3.5 cycle open** — Poly1305 (3.5.0) + ChaCha20 (3.5.1) + ChaCha20-Poly1305 AEAD (3.5.2) shipped; X25519 implemented in `[Unreleased]`, awaiting tag (intended 3.5.3) |

## Test surface

| Metric | Value |
|---|---|
| `.tcyr` test files | 41 |
| Total assertions | **1197**, 0 failures |
| Benchmark suite | `benches/` — see `benches/history.csv` |

Per-cycle assertion delta:

- 3.5.x (`[Unreleased]`): +6 (`x25519.tcyr` 6 — RFC 7748 §5.2/§6.1)
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
| 3.5.2 | 2026-05-27 | ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) — `src/chacha20poly1305.cyr`: `chacha20poly1305_encrypt` + constant-time-verifying `chacha20poly1305_decrypt`. Composes the 3.5.1 cipher + 3.5.0 MAC into TLS 1.3's `TLS_CHACHA20_POLY1305_SHA256`. Audit: `docs/audit/2026-05-27-3.5.2-audit.md`. |
| 3.5.1 | 2026-05-27 | ChaCha20 stream cipher (RFC 8439 §2.3/§2.4) — `src/chacha20.cyr`: `chacha20_block` + `chacha20_xor`, 20-round ARX, constant-time by construction. Second bite of the 3.5 cycle; prereq for the ChaCha20-Poly1305 AEAD. Audit: `docs/audit/2026-05-27-3.5.1-audit.md`. |
| 3.5.0 | 2026-05-27 | Poly1305 one-time MAC (RFC 8439 §2.5) — `src/poly1305.cyr`: `poly1305_mac` + constant-time `poly1305_verify`, 26-bit-limb donna form (no 128-bit path), constant-time freeze. Opens the 3.5 AEAD + key-agreement cycle; ships standalone ahead of the cyrius native-TLS arc. Cyrius pin bumped 6.0.1 → 6.0.3. Audit: `docs/audit/2026-05-27-3.5.0-audit.md`. |
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
| 3.5.0 — Poly1305 MAC | **Shipped** 2026-05-27 | `src/poly1305.cyr` + `tests/tcyr/poly1305.tcyr` (5 assertions). RFC 8439 §2.5 one-time MAC, 26-bit-limb donna form, constant-time freeze. |
| 3.5.1 — ChaCha20 | **Shipped** 2026-05-27 | `src/chacha20.cyr` (+3 tests). RFC 8439 §2.3/§2.4, 20-round ARX, constant-time. |
| 3.5.2 — ChaCha20-Poly1305 AEAD | **Shipped** 2026-05-27 | `src/chacha20poly1305.cyr` (+5 tests). RFC 8439 §2.8, constant-time tag verify, plaintext withheld until authenticated. |
| 3.5.x — X25519 | **Implemented** (in `[Unreleased]`) | `src/x25519.cyr` (+6 tests). RFC 7748 Montgomery ladder over `bigint_ext` fp arithmetic. Awaiting release tag. |
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

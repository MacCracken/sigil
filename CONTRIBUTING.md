# Contributing to Sigil

Sigil is the trust boundary for AGNOS — every cryptographic
decision lives here, and every contribution gets reviewed against
that bar. Please read `CLAUDE.md` for the full development
process before opening a PR; this file is the short version.

## Getting Started

```bash
git clone https://github.com/MacCracken/sigil.git
cd sigil
cyrius build programs/smoke.cyr build/sigil
```

## Cyrius Toolchain

Sigil pins **cyrius `6.0.3`** across `cyrius.cyml` and CI. Match
that pin locally — installing a newer cyrius is fine, but builds
should be run against the pinned version for reproducible
diagnostics. The pinned cyrius release notes are in
[`cyrius/CHANGELOG.md`](https://github.com/MacCracken/cyrius)
upstream; if the pin needs to roll, update both
`cyrius.cyml`'s `cyrius =` line AND the README/roadmap reference.

## Development Process

Sigil follows a structured work loop documented in
[`CLAUDE.md`](CLAUDE.md). The short version:

1. **P(-1)** — Research the vidya entry for any new crypto
   primitive before implementing.
2. **Work phase** — Implement in Cyrius, write tests, write
   benchmarks if the change is performance-sensitive.
3. **Verify** — `cyrius build`, then `cyrius test` on every
   relevant `.tcyr` file. Zero failures.
4. **Security check** — Any new crypto / key-handling / parser
   code gets reviewed for timing side-channels, buffer safety,
   zeroization, and input validation. File findings under
   `docs/audit/YYYY-MM-DD-audit.md` if shipping a release.
5. **Document** — Update CHANGELOG, the affected module's
   header comment, and the roadmap if a planned cycle ships.
6. **Version sync** — `VERSION` and `cyrius.cyml` versions
   must match.

### Task Sizing

- **Low / Medium**: batch freely — multiple items per work loop.
- **Large**: small bites only. Each bite ships as its own patch
  version with its own audit doc (see the 3.2.x TEE arc and the
  3.4.x TEE completion cycle for the canonical shape).
- **If unsure, treat as large.**

### TDD Discipline

- Write tests **first** for new modules and new public functions.
  The 3.4.0 PEM decoder shipped with a 39-assertion test file
  authored alongside the implementation; `snp_report_verify_full`
  (3.4.1) similarly. Match that pattern.
- Benchmarks live in `benches/` and update
  `benches/history.csv`. Regression vs the existing CSV row is a
  release blocker; performance claims in CHANGELOG must include
  the measured numbers.

## Before Submitting a PR

All changes must pass:

```bash
cyrius build programs/smoke.cyr build/sigil
for t in tests/tcyr/*.tcyr; do cyrius test "$t"; done
```

For performance-sensitive changes:

```bash
cyrius bench benches/sigil.bcyr      # or the relevant bench file
# Compare against benches/history.csv. If you're claiming a
# speedup, append a new row with the measurement.
```

## Key Design Principles

From `CLAUDE.md`:

- **Sigil IS the trust boundary** — every crypto decision lives
  here. Don't push crypto choices onto consumers.
- **Own the crypto** — Ed25519 (RFC 8032), ECDSA P-256/P-384
  (FIPS 186-4), SHA-2 family (FIPS 180-4), HMAC (RFC 2104),
  HKDF (RFC 5869), AES-256-GCM (FIPS 197 + NIST SP 800-38D),
  ML-DSA-65 (FIPS 204) — implemented in Cyrius, no external
  deps.
- **Constant-time on secret data** — bitwise-OR accumulation
  for hash/signature/MAC compares; no early-exit branches on
  key material.
- **Key zeroization** — every private key, HMAC key, PRK, and
  intermediate secret buffer overwritten before free. Prefer
  `secret var` (cyrius 5.3.5) for compiler-guaranteed
  zeroization on scope exit.
- **No external deps** — Cyrius stdlib only (plus `sakshi` for
  tracing, plus `agnosys` for kernel interfaces).
- **All types JSON-serializable** — `#derive(Serialize)` on
  every public type for cross-process logging.
- **Runtime feature detection** for hardware acceleration
  (AES-NI, SHA-NI) — never compile-time gating.

## DO NOT

- **Do not commit or push** — the user handles all git
  operations on a triggered cadence. The work loop ends at
  "audit + CHANGELOG + roadmap + VERSION updated", not at
  `git commit`.
- **Never use `gh` CLI** — use `curl` against the GitHub API
  if you need to interact with GitHub from a tool.
- Do not store private keys in plaintext.
- Do not branch on secret data in crypto paths.
- Do not use `sys_system()` with unsanitized input — command
  injection risk. Use `exec_vec()` with explicit argv.
- Do not skip key zeroization — every secret buffer
  overwritten before free.
- Do not trust external data (signatures, hashes, file
  content, keys, X.509 / PEM bytes, TEE quote bytes) without
  validation. Every length field gets bounds-checked before
  use.

## Code Style

- One module per concept; one logical surface per module.
- Header comment on every module: surface, scope, threat model
  (where applicable), reference to the audit doc.
- Function-frame `var X[N]` arrays are **static, not stack
  locals** (CLAUDE.md quirk #1). Use scalar locals for
  per-call state.
- `fl_alloc` + `fl_free` for per-call scratch; bump `alloc()`
  for init-once tables. Never `free()` a bump-allocated block.

## Documentation Discipline

See [`docs/doc-health.md`](docs/doc-health.md) for the
checklist of which docs need updating per change type. A few
quick rules:

- **CHANGELOG entry required** for every release (no "tiny
  patch, no entry needed").
- **Audit doc required** for every cycle that touches crypto,
  key handling, or attacker-controlled input parsing.
- **Roadmap update** when a planned cycle ships (move the
  entry from forward-looking to the "Closed cycles" header)
  or when a new backlog item surfaces.

## Security

If you discover a security vulnerability, please report it
privately per [`SECURITY.md`](SECURITY.md). Do not open a
public issue.

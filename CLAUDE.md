# Sigil — Claude Code Instructions

## Project Identity

**Sigil** (Latin: seal) — System-wide trust verification for AGNOS

- **Type**: Flat library (single-file compilation via `include`)
- **License**: GPL-3.0-only
- **Language**: Cyrius (ported from Rust)
- **Version**: SemVer, version file at `VERSION`
- **Status**: Released (2.x), security hardening active

## Genesis Layer

This project is part of **AGNOS** — an AI-native operating system. The genesis repo at `/home/macro/Repos/agnosticos` owns system-level docs, roadmap, and CI/CD.

- **Recipes**: `MacCracken/zugot` (Hebrew: pairs that enter the ark)
- **Standards**: `agnosticos/docs/development/applications/first-party-standards.md`
- **Shared crates**: `agnosticos/docs/development/applications/shared-crates.md`

## What Sigil Is

Sigil is the **single crypto/trust boundary** for the AGNOS operating system. It owns:
- Ed25519 signing and verification (publisher keyring)
- SHA-256 file integrity measurement and verification
- Trust chain: boot chain → agent binaries → configs → packages
- Revocation list management
- Trust levels, policies, and enforcement modes

Future: PQC (ML-KEM, ML-DSA) when Cyrius implementations mature.

## Consumers

daimon, kavach, ark, aegis, phylax, mela, stiva, argonaut, and all consumer apps that need trust verification.

## Architecture

```
src/
  lib.cyr         — public API entry point (includes all modules)
  types.cyr       — TrustLevel, TrustPolicy, TrustedArtifact, VerificationResult, enums
  error.cyr       — SigilError codes, Result pattern
  trust.cyr       — Ed25519 keyring, sign/verify, key rotation, hash_data
  integrity.cyr   — File hash measurement baselines, IntegrityVerifier
  verify.cyr      — SigilVerifier (the main trust engine)
  chain.cyr       — Boot chain verification
  policy.cyr      — RevocationEntry, RevocationList, CRL
  audit.cyr       — Structured audit event logging
  tpm.cyr         — TPM interface (when agnosys exports available)
  ed25519.cyr     — Ed25519 implementation (RFC 8032)
  ct.cyr          — Constant-time comparison utilities
```

## Development Process

### P(-1): Scaffold Hardening (before any new features)

0. Read roadmap, CHANGELOG, and open issues — know what was intended
1. Cleanliness check: `cyrius build`, `cyrlint`, all tests pass
2. Benchmark baseline: `cyrius bench`
3. Internal deep review — gaps, optimizations, correctness, docs
4. External research — vidya entry, domain completeness, crypto best practices (RFC 8032, FIPS 180-4, RFC 2104)
5. **Security audit** — review all crypto paths, key handling, constant-time comparisons, buffer sizes, pointer validation. Run against known CVE patterns for Ed25519/SHA-256/HMAC. File findings in `docs/audit/YYYY-MM-DD-audit.md`
6. Additional tests/benchmarks from findings
7. Post-review benchmarks — prove the wins (compare against `benchmarks-rust-v-cyrius.md`)
8. Documentation audit
9. Repeat if heavy

### Work Loop (continuous)

1. **P(-1)** — Research: vidya entry before implementation
2. Work phase — implement in Cyrius, test, benchmark
3. `cyrius build` — verify compilation
4. `cyrius test` — run .tcyr test files
5. `cyrius bench` — run .bcyr benchmark files
6. Internal review — performance, memory, correctness
7. **Security check** — any new crypto code, key material handling, or input parsing reviewed for timing side-channels, buffer safety, and zeroization
8. Documentation — update CHANGELOG, roadmap, docs
9. Version check — VERSION and cyrius.cyml in sync
10. Return to step 1

### Security Hardening (before release)

Run a dedicated security audit pass before any version release. Sigil IS the trust boundary — this is non-negotiable:

1. **Input validation** — every function that accepts external data (signatures, hashes, file content, keys) validates bounds, lengths, and formats before use
2. **Buffer safety** — every `var buf[N]` and `alloc(N)` verified: N is in BYTES, max access offset < N, no adjacent-variable overflow
3. **Constant-time audit** — every hash/signature/MAC comparison uses bitwise OR accumulation with no early exit; no branches on secret data
4. **Key material zeroization** — every private key, HMAC key, and intermediate secret buffer overwritten with zeros before free
5. **Syscall review** — every `syscall()` and `sys_*()` call reviewed: arguments validated, return values checked, error paths handled
6. **Pointer validation** — no raw pointer dereference of untrusted input without bounds checking
7. **No command injection** — no `sys_system()` or `exec_cmd()` with unsanitized input. Use `exec_vec()` with explicit argv instead
8. **No path traversal** — file paths from external input validated against allowed directories. No `../` escape
9. **Known CVE check** — review Ed25519, SHA-256, HMAC implementations against current CVE databases
10. **File findings** — all issues documented in `docs/audit/YYYY-MM-DD-audit.md` with severity, file, line, and fix

Severity levels:
- **CRITICAL** — exploitable immediately, remote or privilege escalation, key leakage, signature forgery
- **HIGH** — exploitable with moderate effort, timing side-channel on secret data
- **MEDIUM** — exploitable under specific conditions
- **LOW** — defense-in-depth improvement

### Closeout Pass (before every minor/major bump)

Run a closeout pass before tagging x.Y.0 or x.0.0. Ship as the last patch of the current minor (e.g. 0.3.5 before 0.4.0):

1. **Full test suite** — all .tcyr pass, zero failures
2. **Benchmark baseline** — `cyrius bench`, save CSV; compare against `benchmarks-rust-v-cyrius.md`
3. **Dead code audit** — check for unused functions, remove dead source code
4. **Stale comment sweep** — grep for old version refs, outdated TODOs
5. **Security re-scan** — grep for new `sys_system`, unchecked writes, non-constant-time compares, missing zeroization, buffer size mismatches
6. **Downstream check** — all consumers (daimon, kavach, ark, aegis, phylax, mela, stiva, argonaut) still build and pass tests with the new version
7. **CHANGELOG/roadmap sync** — all docs reflect current state, version numbers consistent
8. **Version verify** — VERSION, cyrius.cyml, CHANGELOG header all match
9. **Full build from clean** — `rm -rf build && cyrius deps && cyrius build` passes clean

### Task Sizing

- **Low/Medium**: Batch freely — multiple items per work loop cycle
- **Large**: Small bites only — break into sub-tasks, verify each before moving to the next
- **If unsure**: Treat as large

### TDD Discipline

- Write tests FIRST for new modules/features, then implement until they pass
- Benchmarks alongside, not after — regressions vs `benches/history.csv` are a release blocker
- Rust source preserved in `rust-old/` for reference during cross-checks

## Key Design Constraints

- **Sigil IS the trust boundary** — every crypto decision lives here
- **Own the crypto** — Ed25519 (RFC 8032), SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) implemented in Cyrius, no external deps
- **Inherit from libro** — SHA-256, hex encode/decode, constant_time_eq, key zeroization pattern. Improve: proper HMAC (not simplified), add Ed25519 asymmetric signing
- **Constant-time comparison** — bitwise OR accumulation for hash/signature comparison, no early exit
- **Key material zeroization** — overwrite key buffers with zeros before free
- **No timing side-channels** — crypto paths must not branch on secret data
- **Zero external dependencies** — Cyrius stdlib only (plus sakshi for tracing)
- **`fl_alloc` for structs, `alloc` for hashmaps** — freelist supports individual free; bump allocator for long-lived collections
- **Globals for cross-call state** — Cyrius single-pass compiler clobbers locals; use globals when values must survive nested calls
- **All types JSON-serializable** — `#derive(Serialize)` on all public types
- **Runtime feature detection** over compile-time gating (follow libro pattern)
- **Target size** — compiled binary contribution should be small and measurable

## Known Cyrius Compiler Constraints

1. Local variable clobbering — function parameters/locals overwritten by nested calls; workaround: save to globals
2. `map_get` after `map_set` in same call chain — lookups may fail; workaround: restructure to minimize call depth
3. No `\r` escape sequence — use raw byte 13 for carriage return
4. Fixup table limit (8192) — split into multiple compilation units if exceeded
5. `var buf[N]` is N bytes, not N elements — for 80 i64 values, declare `var buf[640]`
6. Negative literals not supported — use `(0 - N)` instead of `-N`
7. Max ~64 global vars with initializers — use enums for constants
8. `match` is a reserved keyword — do not use as variable name

## DO NOT

- **Do not commit or push** — the user handles all git operations
- **NEVER use `gh` CLI** — use `curl` to GitHub API only
- Do not add unnecessary dependencies (there should be close to zero)
- Do not skip benchmarks before claiming performance improvements
- Do not store private keys in plaintext
- Do not branch on secret data in crypto paths
- Do not use `sys_system()` with unsanitized input — command injection risk
- Do not trust external data (signatures, hashes, file content, keys) without validation
- Do not skip key zeroization — every secret buffer overwritten before free

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, LICENSE

docs/ (required):
  architecture/overview.md — module map, data flow, consumers
  development/roadmap.md — completed, backlog, future

docs/ (when earned):
  adr/ — architectural decision records
  audit/ — security audit reports (YYYY-MM-DD-audit.md)
  guides/ — usage guides, integration patterns
  sources.md — source citations for algorithms (Ed25519, SHA-256, etc.)
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). Performance claims MUST include benchmark numbers. Breaking changes get a **Breaking** section with migration guide. Security fixes get a **Security** section with CVE references where applicable.

## Current Status

- **Ported from**: Rust v1.0.0 (149 tests, 12 benchmarks)
- **Rust source**: preserved in `rust-old/`
- **Rust benchmarks**: preserved in `benchmarks-rust-v-cyrius.md`
- **Version**: 2.1.1 (Cyrius, see `VERSION` for current)
- **Phase**: Hardening — security audit workflow active

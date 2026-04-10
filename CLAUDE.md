# Sigil — Claude Code Instructions

## Project Identity

**Sigil** (Latin: seal) — System-wide trust verification for AGNOS

- **Type**: Flat library (single-file compilation via `include`)
- **License**: GPL-3.0-only
- **Language**: Cyrius (ported from Rust)
- **Version**: SemVer, version file at `VERSION`
- **Status**: Porting from Rust — TDD-first approach

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

### Work Loop

1. **P(-1)** — Research: vidya entry before implementation
2. Work phase — implement in Cyrius, test, benchmark
3. `cyrius build` — verify compilation
4. `cyrius test` — run .tcyr test files
5. `cyrius bench` — run .bcyr benchmark files
6. Documentation — CHANGELOG, roadmap
7. Version check — VERSION and cyrius.toml in sync

### Task Sizing

- **Low/Medium**: Batch freely
- **Large**: Small bites, verify each
- **If unsure**: Treat as large

### Porting Approach (TDD)

- Write tests FIRST for each module, then implement until tests pass
- Port module-by-module: types → error → trust → integrity → verify → chain → policy → audit → tpm
- Benchmarks alongside, not after — compare against Rust baselines in `benchmarks-rust-v-cyrius.md`
- Rust source preserved in `rust-old/` for reference

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

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, LICENSE

docs/ (required):
  architecture/overview.md — module map, data flow, consumers
  development/roadmap.md — completed, backlog, future

docs/ (when earned):
  adr/ — architectural decision records
  guides/ — usage guides, integration patterns
  sources.md — source citations for algorithms (Ed25519, SHA-256, etc.)
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). Performance claims MUST include benchmark numbers. Breaking changes get a **Breaking** section with migration guide.

## Current Status

- **Ported from**: Rust v1.0.0 (149 tests, 12 benchmarks)
- **Rust source**: preserved in `rust-old/`
- **Rust benchmarks**: preserved in `benchmarks-rust-v-cyrius.md`
- **Version**: 0.1.0 (Cyrius port)
- **Phase**: Porting — TDD module-by-module

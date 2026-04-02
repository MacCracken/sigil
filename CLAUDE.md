# Sigil — Claude Code Instructions

## Project Identity

**Sigil** (Latin: seal) — System-wide trust verification for AGNOS

- **Type**: Flat library crate
- **License**: GPL-3.0-only
- **MSRV**: 1.89
- **Version**: SemVer 0.1.0

## What Sigil Is

Sigil is the **single crypto/trust boundary** for the AGNOS operating system. It owns:
- Ed25519 signing and verification (publisher keyring)
- SHA-256 file integrity measurement and verification
- Trust chain: boot chain → agent binaries → configs → packages
- Revocation list management
- Trust levels, policies, and enforcement modes

Future: PQC (ML-KEM, ML-DSA) will be a `pqc` feature on sigil — no separate crate.

## Consumers

daimon, kavach, ark, aegis, phylax, mela, stiva, argonaut, and all consumer apps that need trust verification.

## Modules

- `trust.rs` — Ed25519 keyring, sign/verify, key rotation, hash_data
- `integrity.rs` — File hash measurement baselines, IntegrityVerifier
- `verify.rs` — SigilVerifier (the main trust engine)
- `chain.rs` — Boot chain verification
- `policy.rs` — RevocationEntry, RevocationList
- `types.rs` — TrustLevel, TrustPolicy, TrustedArtifact, VerificationResult, etc.

## Development Process

### P(-1): Scaffold Hardening (before any new features)

This is the first phase every extracted crate goes through. The scaffold compiles and has basic tests, but hasn't been audited, optimized, or stress-tested. P(-1) pays the debt before it compounds.

0. Read roadmap, CHANGELOG, and open issues — know what was intended before auditing what was built
1. Test + benchmark sweep of existing code — identify gaps in coverage
2. Cleanliness check: `cargo fmt --check`, `cargo clippy --all-features --all-targets -- -D warnings`, `cargo audit`, `cargo deny check`, `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`
3. Get baseline benchmarks (`./scripts/bench-history.sh`) — first CSV entry is the starting line
4. Internal deep review:
   - **Security**: Are Ed25519 operations constant-time? Key material zeroed? No timing leaks?
   - **Correctness**: Are trust levels correctly propagated? Revocations actually enforced?
   - **Performance**: Hash chain operations, signature verification hot paths
   - **Gaps**: Missing error variants, untested edge cases, incomplete API surface
   - **Patterns**: `#[non_exhaustive]` on all public enums, `#[must_use]` on pure functions, zero unwrap/panic
5. External research — Ed25519 best practices, trust chain standards, revocation patterns
6. Cleanliness check — must be clean after review
7. Additional tests/benchmarks from findings
8. Post-review benchmarks — prove the wins
9. Repeat if heavy

**Exit criteria**: Crate is audit-clean, clippy-clean, fmt-clean, security-clean, with baseline benchmarks. Ready to enter the Work Loop.

### Work Loop (continuous)

1. Work phase — new features, roadmap items, bug fixes
2. Cleanliness check: `cargo fmt --check`, `cargo clippy --all-features --all-targets -- -D warnings`, `cargo audit`, `cargo deny check`, `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`
3. Test + benchmark additions for new code
4. Run benchmarks (`./scripts/bench-history.sh`)
5. Internal review — performance, memory, security, throughput, correctness
6. Cleanliness check — must be clean after review
7. Deeper tests/benchmarks from review observations
8. Run benchmarks again — prove the wins
9. If review heavy → return to step 5
10. Documentation — update CHANGELOG, roadmap, docs
11. Version check — VERSION, Cargo.toml in sync
12. Return to step 1

### Task Sizing

- **Low/Medium effort**: Batch freely — multiple items per work loop cycle
- **Large effort**: Small bites only — break into sub-tasks, verify each before moving to the next. Never batch large items together
- **If unsure**: Treat it as large. Smaller bites are always safer than overcommitting

### Refactoring

- Refactor when the code tells you to — duplication, unclear boundaries, performance bottlenecks
- Never refactor speculatively. Wait for the third instance before extracting an abstraction
- Refactoring is part of the work loop, not a separate phase
- Every refactor must pass the same cleanliness + benchmark gates as new code

### Key Principles

- Never skip benchmarks
- Sigil IS the trust boundary — every crypto decision lives here
- `#[non_exhaustive]` on ALL public enums (forward compatibility)
- `#[must_use]` on all pure functions
- Every type must be Serialize + Deserialize (serde)
- Feature-gate optional modules — consumers pull only what they need
- Zero unwrap/panic in library code
- All types must have serde roundtrip tests
- Key material must be zeroized on drop
- No timing side-channels in crypto paths

## DO NOT

- **Do not commit or push** — the user handles all git operations
- **NEVER use `gh` CLI** — use `curl` to GitHub API only
- Do not add unnecessary dependencies
- Do not break backward compatibility without a major version bump
- Do not skip benchmarks before claiming performance improvements
- Do not implement custom crypto — use audited crates (ed25519-dalek, sha2, ml-kem, ml-dsa)
- Do not store private keys in plaintext

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, LICENSE

docs/ (required):
  architecture/overview.md — module map, data flow, consumers
  development/roadmap.md — completed, backlog, future, v1.0 criteria
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). Performance claims MUST include benchmark numbers. Breaking changes get a **Breaking** section with migration guide.

## Current Status

- **Extracted from**: agnosticos/userland/agent-runtime/src/sigil/ + integrity.rs + marketplace/trust.rs
- **Version**: 0.4.0
- **Tests**: 130 passing
- **Benchmarks**: 12 benchmarks, history in benches/history.csv
- **Phase**: Near-term roadmap complete. Ready for Advanced Trust (v0.5.0).
- **Next**: Hierarchical trust delegation, audit logging, CRL distribution

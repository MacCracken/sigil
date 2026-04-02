# Sigil Roadmap

## Completed

### P(-1): Scaffold Hardening (v0.1.0 -> v0.1.1)

- [x] Cleanliness check: fmt, clippy, audit, deny, rustdoc — all clean
- [x] `#[non_exhaustive]` on all public enums (`TrustLevel`, `TrustEnforcement`, `ArtifactType`, `MeasurementStatus`)
- [x] `#[must_use]` on all pure functions across all modules
- [x] Serde on all public types (`VerificationResult`, `SigilStats`, `IntegrityPolicy`, `IntegrityReport`)
- [x] Constant-time hash comparison via `subtle::ConstantTimeEq` (timing side-channel fix)
- [x] Streaming file hash in `IntegrityVerifier::compute_hash` (8KB buffer I/O)
- [x] `RevocationList` O(1) lookups via `HashSet` indexes
- [x] Derived `PartialEq`/`Eq` on `MeasurementStatus` (replaced redundant manual impl)
- [x] Serde roundtrip tests for all public types (11 new tests, 88 -> 99 total)
- [x] Benchmark suite: 10 benchmarks covering hash, sign, verify, keypair gen, integrity, revocation lookup
- [x] `scripts/bench-history.sh` with CSV baseline

## Backlog

### v0.2.0 — Hardening & API Cleanup

**Error handling**
- [ ] `SigilError` enum replacing `anyhow::Result` in all public API surfaces
- [ ] Typed error variants: `KeyNotFound`, `SignatureInvalid`, `RevocationViolation`, `IntegrityMismatch`, `IoError`, etc.
- [ ] Keep `anyhow` as internal convenience; public API returns `Result<T, SigilError>`

**API completeness**
- [ ] `Display` impl for `MeasurementStatus`
- [ ] Builder pattern for `TrustPolicy` (currently relies on struct literal + `Default`)
- [ ] `PublisherKeyring::save()` — persist keyring to disk (currently load-only)
- [ ] `IntegrityVerifier::remove_baseline()` — remove a file from monitoring

**Feature gates**
- [ ] `integrity` feature — `IntegrityVerifier`, `IntegrityPolicy`, `IntegrityReport`
- [ ] `chain` feature — boot chain verification (depends on `integrity`)
- [ ] `policy` feature — `RevocationList`, `RevocationEntry`
- [ ] Default: all features enabled; consumers can opt out

**Documentation**
- [ ] `docs/architecture/overview.md` — module map, data flow, consumer integration
- [ ] `CHANGELOG.md`
- [ ] `CONTRIBUTING.md`
- [ ] `SECURITY.md`
- [ ] `CODE_OF_CONDUCT.md`

### v0.3.0 — Operational Capabilities

**Key management**
- [ ] Key rotation: transition between key versions with overlap windows
- [ ] Key pinning: bind specific keys to specific artifact paths
- [ ] Keyring export: serialize full keyring state for backup/replication

**Verification**
- [ ] Batch verification: verify multiple artifacts in a single pass (parallel hash + sig verify)
- [ ] Verification caching: skip re-verification if file mtime + size unchanged since last pass
- [ ] Configurable hash algorithm (prepare for PQC transition)

**Integrity monitoring**
- [ ] Periodic re-verification scheduler (driven by `check_interval_seconds`)
- [ ] Integrity event callbacks: notify consumers on mismatch/error
- [ ] Baseline snapshot: export/import full integrity state

### v0.4.0 — Advanced Trust

**Trust chain**
- [ ] Hierarchical trust delegation: root key -> intermediate -> publisher
- [ ] Certificate-style key metadata (publisher name, contact, scope constraints)
- [ ] Cross-signing: multiple publishers co-sign an artifact

**Revocation**
- [ ] Revocation timestamps: honor "revoked after" semantics (artifacts signed before revocation remain valid)
- [ ] CRL distribution: fetch/merge remote revocation lists
- [ ] OCSP-style online revocation checking

**Audit & reporting**
- [ ] Structured verification audit log (JSON event stream)
- [ ] Trust store diff: compare two trust store snapshots
- [ ] Policy compliance report: full-system trust posture summary

## Future

### v1.0.0 Criteria

- All public API is stable and documented
- Error types are comprehensive and non-exhaustive
- Feature gates are well-tested in isolation and combination
- Benchmark regression suite in CI
- Security audit by third party
- No `unsafe` code
- All CLAUDE.md key principles enforced

### Post-Quantum Cryptography

- [ ] `pqc` feature gate on sigil (no separate crate)
- [ ] ML-DSA (FIPS 204) for signatures alongside Ed25519
- [ ] ML-KEM (FIPS 203) for key encapsulation (if needed for key exchange)
- [ ] Hybrid mode: Ed25519 + ML-DSA dual signatures during transition
- [ ] Migration path: re-sign existing trust store with PQC keys

### TPM Integration

- [ ] `register_system_core` backed by TPM PCR measurements
- [ ] Sealed key storage via TPM
- [ ] Remote attestation support

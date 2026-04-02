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
- [x] Key rotation: transition between key versions with overlap windows
- [x] Historical key lookup: `get_key_valid_at()` for post-rotation verification
- [x] `key_ids()` to list all key IDs
- [ ] Key pinning: bind specific keys to specific artifact paths
- [ ] Keyring export: serialize full keyring state for backup/replication

**Verification**
- [x] Batch verification: `verify_batch()` with optional rayon parallelism (`parallel` feature)
- [x] Verification caching: `set_cache_enabled()` skips re-hash if mtime+size unchanged (thread-safe via `RwLock`)
- [x] Key pinning: `KeyPin` binds key IDs to path prefixes for supply-chain protection
- [ ] Configurable hash algorithm (prepare for PQC transition)

**Integrity monitoring**
- [x] Baseline snapshot: `export_baseline()` / `import_baseline()` with `IntegritySnapshot`
- [ ] Periodic re-verification scheduler (driven by `check_interval_seconds`)
- [ ] Integrity event callbacks: notify consumers on mismatch/error

### v0.4.0 — Advanced Trust

**Trust chain**
- [ ] Hierarchical trust delegation: root key -> intermediate -> publisher
- [ ] Certificate-style key metadata (publisher name, contact, scope constraints)
- [ ] Cross-signing: multiple publishers co-sign an artifact

**Revocation**
- [x] Revocation timestamps: `revoked_after` field with time-aware `check_revocation_at()`
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

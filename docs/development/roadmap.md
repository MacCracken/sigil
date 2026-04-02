# Sigil Roadmap

## Completed

### P(-1): Scaffold Hardening

- [x] Cleanliness check: fmt, clippy, audit, deny, rustdoc — all clean
- [x] `#[non_exhaustive]` on all public enums
- [x] `#[must_use]` on all pure functions
- [x] Serde on all public types
- [x] Constant-time hash comparison via `subtle::ConstantTimeEq`
- [x] Streaming file hash in `IntegrityVerifier::compute_hash`
- [x] `RevocationList` O(1) lookups via `HashSet` indexes
- [x] Serde roundtrip tests for all public types
- [x] Benchmark suite with `scripts/bench-history.sh`

### v0.2.0 — Hardening & API Cleanup

- [x] `SigilError` enum replacing `anyhow::Result` in all public API
- [x] `anyhow` dependency removed entirely
- [x] `Display` impl for `MeasurementStatus`
- [x] `TrustPolicy::builder()` with `TrustPolicyBuilder`
- [x] `PublisherKeyring::save()` — persist keyring to disk
- [x] `IntegrityVerifier::remove_baseline()`
- [x] Feature gates: `integrity`, `chain`, `policy` (all default on)
- [x] Documentation: architecture overview, CHANGELOG, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT

### v0.3.0 — Operational Capabilities

- [x] Key rotation with overlap windows, `get_key_valid_at()`, `key_ids()`
- [x] Batch verification: `verify_batch()` with optional rayon (`parallel` feature)
- [x] Verification caching: `set_cache_enabled()` (thread-safe via `RwLock`)
- [x] Key pinning: `KeyPin` binds key IDs to path prefixes
- [x] Baseline snapshots: `export_baseline()` / `import_baseline()` with `IntegritySnapshot`
- [x] Revocation timestamps: `revoked_after` with time-aware `check_revocation_at()`
- [x] Configurable hash algorithm: `HashAlgorithm` enum (SHA-256, SHA-512), `hash_data_with()`
- [x] Integrity event callbacks: `IntegrityCallback` trait with `on_mismatch`/`on_error`

### Optimizations

- [x] Sign/verify hash instead of raw data (Ed25519 over 64-byte hash, not full file)
- [x] Skip file I/O on disabled verification paths
- [x] Pre-allocated hex encoding via lookup table
- [x] Audit: zero unwrap/panic in library code, all re-exports clean, deny.toml clean

## v1.0.0 (shipped)

- [x] Cross-signing: `Cosignature`, `cosign_artifact()`, cosigner verification
- [x] CRL distribution: `Crl` struct, `RevocationList::merge()`, `Crl::apply_to()`
- [x] Policy compliance report: `ComplianceReport`, `compliance_report()`
- [x] PQC scaffold: `SignatureAlgorithm` enum, `pqc` feature flag, `signature_algorithm` on artifacts
- [x] TPM scaffold: `TpmProvider` trait, `PcrMeasurement`, `measure_system_component()`, `tpm` feature flag
- [x] `#![forbid(unsafe_code)]`
- [x] `#![warn(missing_docs)]` — full doc coverage
- [x] 8 fuzzing targets for all deserialization paths
- [x] API frozen

## Post-v1.0

### PQC Implementation (when crates mature)

- [ ] ML-DSA (FIPS 204) actual signing/verification behind `pqc` feature
- [ ] ML-KEM (FIPS 203) for key encapsulation
- [ ] Hybrid mode: Ed25519 + ML-DSA dual signatures during transition
- [ ] Re-sign utility: migrate existing trust store to PQC keys

### TPM Implementation (when agnosys exports available)

- [ ] Concrete `TpmProvider` implementation backed by agnosys TPM subsystem
- [ ] `register_system_core` with mandatory TPM attestation
- [ ] Sealed key storage via TPM
- [ ] Remote attestation end-to-end flow

### Online Verification

- [ ] OCSP-style online revocation checking
- [ ] Certificate transparency log integration
- [ ] Revocation stapling: cache OCSP responses locally

### CI/CD

- [ ] Benchmark regression thresholds in CI
- [ ] Fuzzing in CI (nightly)
- [ ] Third-party security audit

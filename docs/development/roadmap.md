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

## Backlog

### v0.5.0 — Advanced Trust (done)

- [x] Hierarchical trust delegation: root key -> intermediate -> publisher
- [x] Certificate-style key metadata (publisher name, contact, scope constraints)
- [x] Structured verification audit log (JSON event stream)
- [x] Trust store diff: compare two trust store snapshots
- Remaining items moved to v0.6.0

### v0.6.0 — Cross-signing & CRL

- [ ] Cross-signing: multiple publishers co-sign an artifact
- [ ] CRL distribution: fetch/merge remote revocation lists
- [ ] Policy compliance report: full-system trust posture summary

### v0.7.0 — Online Verification

- [ ] OCSP-style online revocation checking
- [ ] Certificate transparency log integration
- [ ] Revocation stapling: cache OCSP responses locally

### v0.8.0 — PQC Foundation

- [ ] `pqc` feature gate (no separate crate — sigil owns all AGNOS crypto)
- [ ] ML-DSA (FIPS 204) signatures alongside Ed25519
- [ ] ML-KEM (FIPS 203) for key encapsulation (if needed for key exchange)
- [ ] Hybrid mode: Ed25519 + ML-DSA dual signatures during transition
- [ ] Re-sign utility: migrate existing trust store to PQC keys

### v0.9.0 — Production Hardening

- [ ] API freeze — no breaking changes after this
- [ ] Full doc coverage on every public item (`#[warn(missing_docs)]`)
- [ ] No `unsafe` code audit
- [ ] Benchmark regression thresholds in CI
- [ ] Fuzzing targets for all deserialization paths
- [ ] TPM integration (`register_system_core` backed by TPM PCR measurements, sealed key storage, remote attestation) — depends on agnosys TPM exports

## v1.0.0 Criteria

- All public API is stable and documented
- Error types are comprehensive and non-exhaustive
- Feature gates are well-tested in isolation and combination
- Benchmark regression suite in CI
- Security audit by third party
- No `unsafe` code
- All CLAUDE.md key principles enforced
- PQC hybrid mode operational
- TPM integration tested on real hardware

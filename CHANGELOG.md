# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-04-02

### Added
- **Key rotation**: `PublisherKeyring::rotate_key()` expires the current key version and adds a new one with a configurable overlap window for graceful transitions
- **Historical key lookup**: `PublisherKeyring::get_key_valid_at()` for verifying artifacts signed before a key rotation
- `PublisherKeyring::key_ids()` to list all key IDs in the keyring
- **Integrity baseline snapshots**: `IntegrityVerifier::export_baseline()` / `import_baseline()` with `IntegritySnapshot` type for backup/restore of integrity state
- **Batch verification**: `SigilVerifier::verify_batch()` verifies multiple artifacts in one call
- `parallel` feature flag: enables rayon-based parallel batch verification
- 9 new tests (key rotation, baseline snapshots, batch verification) — 115 total

### Performance

| Benchmark | v0.2.0 | v0.3.0 |
|---|---|---|
| verify_batch (10x4KB) | N/A | 745 us |
| revocation_key_lookup (1k) | 17 ns | 17 ns |

## [0.2.0] — 2026-04-02

### Added
- `SigilError` enum with typed variants (`KeyNotFound`, `SignatureInvalid`, `RevocationViolation`, `IntegrityMismatch`, `InvalidInput`, `Io`, `Serialization`, `Crypto`)
- `sigil::Result<T>` type alias for `Result<T, SigilError>`
- `TrustPolicy::builder()` and `TrustPolicyBuilder` for ergonomic policy construction
- `PublisherKeyring::save()` — persist keyring to disk as JSON files
- `IntegrityVerifier::remove_baseline()` — remove a file from integrity monitoring
- `Display` impl for `MeasurementStatus`
- Feature gates: `integrity`, `chain`, `policy` (all enabled by default)
- `#[non_exhaustive]` on all public enums (`TrustLevel`, `TrustEnforcement`, `ArtifactType`, `MeasurementStatus`)
- `#[must_use]` on all pure functions
- `Serialize`/`Deserialize` on `VerificationResult`, `SigilStats`, `IntegrityPolicy`, `IntegrityReport`
- Serde roundtrip tests for all public types (11 new tests)
- Benchmark suite: 10 benchmarks covering hash, sign, verify, keypair generation, integrity, revocation lookup, full artifact verification
- `scripts/bench-history.sh` for tracking benchmark results over time
- `docs/architecture/overview.md` — module map, data flow, consumer list
- `docs/development/roadmap.md`

### Changed
- **Breaking**: All public API functions now return `Result<T, SigilError>` instead of `anyhow::Result<T>`. Consumers can now match on specific error variants.
- `IntegrityVerifier::compute_hash()` now uses streaming I/O (8KB buffer) instead of reading entire file into memory
- `RevocationList` lookups are now O(1) via `HashSet` indexes (previously O(n) linear scan). Benchmark: ~17ns for 1k-entry list.
- Hash comparisons in `IntegrityVerifier` and `SigilVerifier::verify_package()` now use constant-time comparison via `subtle::ConstantTimeEq`
- Derived `PartialEq`/`Eq` on `MeasurementStatus` (replaced redundant manual impl)

### Removed
- `anyhow` dependency (replaced by `SigilError`)

### Security
- Constant-time hash comparison eliminates timing side-channel in integrity verification and package hash checking
- Streaming file hash prevents memory exhaustion on large files (e.g., kernel images)

### Performance
- `RevocationList::is_key_revoked()` / `is_artifact_revoked()`: O(n) -> O(1)
- `IntegrityVerifier::compute_hash()`: constant memory regardless of file size

#### Baseline Benchmarks (v0.2.0)

| Benchmark | Result |
|---|---|
| hash_data (4KB) | 2.0 us |
| hash_data (1MB) | 496 us |
| sign (4KB) | 27.2 us |
| verify (4KB) | 34.9 us |
| generate_keypair | 15.3 us |
| compute_hash_file (4KB) | 5.7 us |
| compute_hash_file (1MB) | 611 us |
| revocation_key_lookup (1k entries) | 17 ns |
| revocation_hash_lookup (1k entries) | 17 ns |
| verify_artifact_signed (4KB) | 45.3 us |

## [0.1.0] — 2026-04-01

### Added
- Initial extraction from agnosticos/userland/agent-runtime
- Ed25519 signing and verification via `ed25519-dalek`
- SHA-256 file integrity measurement and verification
- `SigilVerifier` trust engine with configurable policy
- Boot chain verification
- Revocation list management
- Trust levels: SystemCore, Verified, Community, Unverified, Revoked
- Enforcement modes: Strict, Permissive, AuditOnly
- 88 tests passing

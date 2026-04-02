# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — Advanced Trust

### Added
- **Certificate-style key metadata**: `KeyMetadata` struct with `publisher_name`, `publisher_contact`, `allowed_artifact_types`, `allowed_paths`. `KeyRole` enum (`Root`, `Intermediate`, `Publisher`).
- **Hierarchical trust delegation**: `issued_by` and `issuer_signature` fields on `KeyVersion`. `PublisherKeyring::get_chain()` walks the issuer chain back to root. `validate_chain()` verifies each link's signature. `SigilVerifier` integrates chain validation into artifact verification — broken chains downgrade to `Community` trust.
- **Structured verification audit log**: `AuditEvent` enum, `AuditLog` struct. Events emitted for `ArtifactVerified` and `ArtifactSigned`. JSON lines serialization. File-backed persistence via `append_to_file()`/`load_from_file()`.
- **Trust store diff**: `TrustStoreDiff` with `added`/`removed`/`changed` sets. `snapshot_trust_store()` and `diff_trust_store()` on `SigilVerifier`.
- `find_by_publisher()` and `find_by_role()` on `PublisherKeyring`
- Re-exports: `KeyPin`, `ArtifactChange`, `TrustStoreDiff`, `IntegritySnapshot`, `BaselineEntry`
- 12 new tests (chain validation 3-level, broken chain, metadata queries, audit log, trust store diff) — 142 total

## [Unreleased] — Near-term completion

### Added
- **Configurable hash algorithm**: `HashAlgorithm` enum (`Sha256`, `Sha512`) with `#[non_exhaustive]` for future PQC. `hash_data_with()` and `IntegrityVerifier::compute_hash_with()`. `TrustPolicy.hash_algorithm` field + builder method.
- **Integrity event callbacks**: `IntegrityCallback` trait with `on_mismatch()`/`on_error()`. `IntegrityVerifier::set_callback()`. Blanket impl for `Arc<T>`.
- `KeyPin` and `IntegritySnapshot`/`BaselineEntry` re-exported from crate root
- `#[must_use]` on `verify_batch()`
- 4 new tests (SHA-512 sign/verify, hash algorithm default, hash_data_with, callback) — 130 total

### Changed
- **Sign/verify hash instead of raw data**: Ed25519 now operates on the 64-byte SHA-256/512 hash, not the full file. Signature verification cost is constant regardless of file size. ~54% reduction for 1MB files.
- **Skip file I/O on disabled verification paths**: `verify_agent_binary` and `verify_package` no longer read files when their policy flags are disabled.
- **Pre-allocated hex encoding**: Lookup-table encoder replaces per-byte `format!("{:02x}")`.
- `RevocationList::from_json()` now validates entries through `add()` (previously skipped validation)
- Cleaned `deny.toml` — removed 4 unused license allowances

### Performance

| Benchmark | Before | After | Delta |
|---|---|---|---|
| verify_artifact (4KB) | 46.9 us | 42.5 us | -9.4% |
| verify_artifact (1MB) | ~1350 us* | 621 us | -54% |
| verify_batch (10x4KB) | 491 us | 429 us | -12.6% |

*estimated (raw-data signing was never benchmarked at 1MB before the change)

## [0.4.0] — 2026-04-02

### Added
- **Verification caching**: `set_cache_enabled()`, `clear_cache()`, `cache_len()`. When enabled, skips re-reading and re-hashing files whose mtime and size haven't changed. Thread-safe via `RwLock`.
- **Key pinning**: `KeyPin` struct, `add_key_pin()`, `remove_key_pins()`, `key_pins()`. Binds key IDs to path prefixes — only the pinned key may sign artifacts under that prefix. Prevents unauthorized publishers from signing critical paths.
- **Revocation timestamps**: `RevocationEntry.revoked_after` field. When set, artifacts verified before the compromise time remain valid. Supports graceful handling of key compromises with known timeline.
- `check_revocation_at()` for time-aware revocation checks
- `RevocationList::is_key_revoked_at()` / `is_artifact_revoked_at()` for time-aware queries
- 10 new tests (caching, key pinning, revocation timestamps) — 126 total

### Changed
- Verification cache uses `RwLock` (thread-safe, compatible with rayon parallel verification)
- Internal revocation check in `verify_artifact` now passes current timestamp, enabling `revoked_after` semantics

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

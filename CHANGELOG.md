# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-10

### Added — Cyrius Port
- **Full port from Rust to Cyrius** — all 10 modules ported with 206 passing tests
- **Ed25519 (RFC 8032)**: keypair generation, signing, verification — byte-exact match with RFC test vectors. Built on `bigint.cyr` (4-limb u256) with custom field arithmetic over p = 2^255 - 19
- **SHA-256 (FIPS 180-4)**: streaming hash, one-shot convenience, file hashing
- **SHA-512**: required by Ed25519 for key expansion and nonce generation
- **HMAC-SHA256 (RFC 2104)**: proper ipad/opad construction, sign/verify convenience
- **Constant-time comparison**: bitwise OR accumulation, no early exit on data
- **Hex encode/decode**: for hash and key serialization
- **TrustLevel ordering**: SystemCore > Verified > Community > Unverified > Revoked with rank-based comparison
- **TrustPolicy**: builder pattern with enforcement mode, minimum trust level, hash algorithm, verification flags
- **TrustedArtifact**: path, type, hash, signature, signer, trust level, cosigners, metadata
- **VerificationResult**: artifact + checks vector + passed flag
- **SigilError**: 8 error codes (KeyNotFound, SignatureInvalid, Revocation, IntegrityMismatch, InvalidInput, IO, Serialization, Crypto)
- **PublisherKeyring**: key storage, lookup by ID/role/publisher, key rotation with overlap, chain validation, JSON persistence
- **IntegrityVerifier**: file hash measurement, verify single/all, baseline add/remove, snapshot export/import
- **RevocationList**: key and hash revocation with temporal `revoked_after` semantics, merge, O(1) lookups via hashmap index
- **CRL**: distributable certificate revocation list with version/issuer/freshness
- **AuditLog**: structured events (ArtifactVerified, ArtifactSigned, RevocationAdded, KeyRotated), JSON lines file output
- **SigilVerifier**: main trust engine — artifact verification (hash + signature + revocation + key pin + policy), signing, batch verification, compliance report, trust store snapshot/diff/persistence, boot chain verification
- **TPM module**: PcrMeasurement, AttestationResult, runtime TPM detection, system component measurement, PCR verification, seal/unseal stubs, TPM RNG with urandom fallback
- **Key zeroization**: secret key buffers zeroed after use
- Zero external dependencies (Cyrius stdlib + sakshi only)

### Removed
- Rust v1.0.0 source (was in `rust-old/`)
- Rust CI workflows, fuzz targets, cargo config, deny.toml, codecov.yml
- Rust benchmark baselines preserved in `benchmarks-rust-v-cyrius.md` for comparison

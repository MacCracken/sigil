# Sigil Roadmap

## Completed

### Cyrius Port (v0.1.0)

- [x] Full port from Rust v1.0.0 to Cyrius
- [x] Ed25519 (RFC 8032) — keypair, sign, verify, RFC test vectors pass
- [x] SHA-256 (FIPS 180-4), SHA-512, HMAC-SHA256 (RFC 2104)
- [x] Constant-time comparison (bitwise OR accumulation)
- [x] All type system: TrustLevel, TrustPolicy, TrustedArtifact, VerificationResult, SigilStats
- [x] SigilError codes and error constructors
- [x] PublisherKeyring with rotation, chain validation, persistence
- [x] IntegrityVerifier with snapshot export/import
- [x] RevocationList with temporal semantics, CRL, merge
- [x] AuditLog with JSON lines output
- [x] SigilVerifier trust engine (verify, sign, batch, compliance, diff, boot chain)
- [x] TPM module with runtime detection, PCR measurement
- [x] 206 tests, 0 failures
- [x] Rust debris cleaned (target/, Cargo files, CI, fuzz targets)

## Backlog

### P(-1): Scaffold Hardening (current)

- [x] Rust debris removal
- [x] .gitignore updated for Cyrius
- [x] CHANGELOG, README, roadmap updated
- [ ] Benchmark suite (Cyrius .bcyr files)
- [ ] Fuzz harnesses (Cyrius .fcyr files)
- [ ] Cyrius CI workflow (.github/workflows/)
- [ ] `cyrius fmt --check` pass
- [ ] `cyrius lint` pass
- [ ] VERSION / cyrius.cyml sync verified

### v0.2.0 — Hardening

- [ ] Constant-time scalar multiplication for Ed25519 signing (Montgomery ladder)
- [ ] Ed25519 RFC 8032 test vectors 2-5
- [ ] Benchmark baseline: all crypto ops, keyring, verification
- [ ] Fuzz targets: JSON deserialization paths, key generation, signature verification
- [ ] Key zeroization audit — ensure all secret key paths zeroed
- [ ] `#derive(Serialize)` on all public types

### v0.3.0 — Integration

- [ ] agnosys TPM integration: replace seal/unseal stubs with real tpm2-tools calls
- [ ] IMA measurement integration via agnosys
- [ ] Secure boot state detection
- [ ] Trust store JSON load (currently save-only)
- [ ] Audit log JSON lines load

## Future

- PQC: ML-DSA-65 signing when Cyrius implementations mature
- Hybrid Ed25519 + ML-DSA-65 dual signatures
- Certificate pinning integration via agnosys certpin
- Parallel batch verification (when Cyrius threading matures)

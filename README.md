# Sigil

**System-wide trust verification for AGNOS.**

Sigil (Latin: seal) provides unified trust verification across the AGNOS operating system — boot chain integrity, agent binary signing, package verification, and revocation management.

## Language

Cyrius (ported from Rust v1.0.0). Zero external dependencies.

## Modules

- **ed25519** — Ed25519 signing and verification (RFC 8032)
- **trust** — Publisher keyring, key rotation, chain validation
- **integrity** — File integrity verification with SHA-256 measurement baselines
- **verify** — SigilVerifier: the main trust engine
- **policy** — Revocation list and CRL management
- **audit** — Structured audit event logging
- **tpm** — TPM integration (runtime detection, PCR measurement)
- **types** — Trust levels, artifacts, policies, verification results
- **error** — Error codes and result pattern

## Crypto Stack

All cryptography implemented in Cyrius — no external dependencies:

- **Ed25519** (RFC 8032) — asymmetric signing/verification
- **SHA-256** (FIPS 180-4) — content hashing
- **SHA-512** — Ed25519 key expansion
- **HMAC-SHA256** (RFC 2104) — keyed hashing
- **Constant-time comparison** — no timing side-channels in hash/signature checks

## Architecture

```
src/
  lib.cyr         — public API entry point
  types.cyr       — TrustLevel, TrustPolicy, TrustedArtifact, etc.
  error.cyr       — SigilError codes
  sha256.cyr      — FIPS 180-4 SHA-256
  sha512.cyr      — SHA-512 (for Ed25519)
  hex.cyr         — hex encode/decode
  ct.cyr          — constant-time comparison
  hmac.cyr        — HMAC-SHA256 (RFC 2104)
  bigint_ext.cyr  — 256-bit field arithmetic for Ed25519
  ed25519.cyr     — Ed25519 implementation (RFC 8032)
  trust.cyr       — publisher keyring, signing, key management
  integrity.cyr   — file hash measurement and verification
  policy.cyr      — revocation lists and CRL
  audit.cyr       — structured audit logging
  tpm.cyr         — TPM interface
  verify.cyr      — SigilVerifier trust engine
```

## Tests

206 tests across 9 test suites, 0 failures.

## License

GPL-3.0-only

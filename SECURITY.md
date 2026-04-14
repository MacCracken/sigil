# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.1.x | Yes |
| 2.0.x | Yes |
| < 2.0.0 | No |

## Reporting a Vulnerability

Sigil is a security-critical component of AGNOS. If you discover a vulnerability:

1. **Do not** open a public issue
2. Email security@agnos.dev with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Scope

The following are in scope:

- Timing side-channels in hash comparison or signature verification
- Key material leakage (memory, logs, error messages)
- Trust level bypass or escalation
- Revocation bypass
- Signature forgery or verification bypass
- Integer overflow in hash/signature operations
- Path traversal in file operations

## Cryptographic Implementations

As of the Cyrius port (v2.0.0), sigil owns all of its crypto
primitives directly — zero external dependencies. Each implementation
follows the referenced standard:

- **Ed25519** (signatures) — RFC 8032, `src/ed25519.cyr`
- **SHA-256** (hashing) — FIPS 180-4, `src/sha256.cyr`
- **SHA-512** (Ed25519 hash) — FIPS 180-4, `src/sha512.cyr`
- **HMAC-SHA256** — RFC 2104, `src/hmac.cyr`
- **Constant-time comparison** — bitwise-OR accumulation, `src/ct.cyr`
- **Cryptographic RNG** — `/dev/urandom` with short-read validation,
  `tpm_random` in `src/tpm.cyr` and `generate_keypair` in `src/trust.cyr`

Pre-port Rust crate dependencies (`ed25519-dalek`, `sha2`, `subtle`,
`rand`) are no longer used and the Rust source is retained only for
reference in `rust-old/`.

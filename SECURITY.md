# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x | Yes |
| < 0.2.0 | No |

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

## Cryptographic Dependencies

Sigil relies on audited crates for all cryptographic operations:

- `ed25519-dalek` — Ed25519 signatures
- `sha2` — SHA-256 hashing
- `subtle` — Constant-time comparison
- `rand` — Cryptographic RNG (via `OsRng`)

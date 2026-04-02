# Sigil

**System-wide trust verification for AGNOS.**

Sigil (Latin: seal) provides unified trust verification across the AGNOS operating system — boot chain integrity, agent binary signing, package verification, and revocation management.

## Modules

- **trust** — Ed25519 signing, publisher keyring, signature verification
- **integrity** — File integrity verification with SHA-256 measurement baselines
- **verify** — SigilVerifier: the main trust engine combining signing + integrity + revocation
- **chain** — Boot chain verification for critical system components
- **policy** — Revocation list management
- **types** — Trust levels, artifacts, policies, verification results

## Architecture

```
sigil
├── trust.rs       — Ed25519 keyring, sign/verify, key rotation
├── integrity.rs   — File hash measurement and verification
├── verify.rs      — SigilVerifier (trust engine)
├── chain.rs       — Boot chain verification
├── policy.rs      — Revocation entries and lists
└── types.rs       — TrustLevel, TrustPolicy, TrustedArtifact, etc.
```

## License

GPL-3.0-only

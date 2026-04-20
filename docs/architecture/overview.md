# Sigil Architecture

## Module Map

```
lib.cyr (entry point)
  ├── types.cyr         Enums, structs, constructors, accessors
  ├── error.cyr         SigilError codes, Result pattern
  ├── sha256.cyr        FIPS 180-4 SHA-256
  ├── sha512.cyr        SHA-512 (for Ed25519)
  ├── hex.cyr           Hex encode/decode
  ├── ct.cyr            Constant-time comparison
  ├── hmac.cyr          HMAC-SHA256 (RFC 2104)
  ├── hkdf.cyr          HKDF-SHA256 (RFC 5869)
  ├── aes_ni.cyr        AES-NI scaffold (dormant in 2.9.0; dispatch in 2.9.1)
  ├── aes_gcm.cyr       AES-256-GCM AEAD (FIPS 197 + NIST SP 800-38D)
  ├── bigint_ext.cyr    256-bit field arithmetic (mod p = 2^255-19)
  ├── ed25519.cyr       Ed25519 (RFC 8032)
  ├── trust.cyr         PublisherKeyring, sign/verify, key management
  ├── integrity.cyr     IntegrityVerifier, file hash measurement
  ├── policy.cyr        RevocationList, CRL
  ├── audit.cyr         AuditLog, structured events
  ├── tpm.cyr           TPM interface (runtime detection)
  └── verify.cyr        SigilVerifier (main trust engine)
```

## Data Flow

```
Artifact on disk
  → hash_file() → content_hash (SHA-256 hex)
  → trust_store lookup → TrustedArtifact
  → signature verification (Ed25519 or HMAC)
  → revocation check (key + hash)
  → key pin check (path prefix authorization)
  → policy compliance (enforcement mode + minimum trust)
  → VerificationResult (passed/failed + checks)
  → AuditEvent logged
```

## Consumers

daimon, kavach, ark, aegis, phylax, mela, stiva, argonaut, and all AGNOS applications needing trust verification.

## Dependencies

- **Cyrius stdlib**: alloc, freelist, vec, hashmap, str, io, fmt, json, sakshi, chrono, bigint
- **External**: none

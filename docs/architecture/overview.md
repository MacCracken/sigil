# Sigil Architecture

## Module Map

```
sigil (lib.rs)
  |
  +-- error.rs        SigilError enum, Result alias, io_err helper
  |
  +-- types.rs        TrustLevel, TrustEnforcement, ArtifactType, TrustPolicy,
  |                   TrustPolicyBuilder, TrustedArtifact, VerificationResult,
  |                   TrustCheck, SigilStats
  |
  +-- trust.rs        KeyVersion, PublisherKeyring, hash_data, sign_data,
  |                   verify_signature, generate_keypair, key_id_from_verifying_key
  |
  +-- verify.rs       SigilVerifier (the main trust engine)
  |
  +-- integrity.rs*   MeasurementStatus, IntegrityMeasurement, IntegrityPolicy,
  |                   IntegrityReport, IntegrityVerifier
  |
  +-- chain.rs*       verify_boot_chain_impl (called via SigilVerifier)
  |
  +-- policy.rs*      RevocationEntry, RevocationList

  * = feature-gated (integrity, chain, policy)
```

## Data Flow

### Signing (write path)

```
File on disk
  --> std::fs::read()
  --> hash_data() (SHA-256)
  --> sign_data() (Ed25519)
  --> TrustedArtifact { content_hash, signature, signer_key_id, trust_level }
  --> trust_store.insert()
```

### Verification (read path)

```
File on disk
  --> std::fs::read()
  --> hash_data() (SHA-256)
  --> trust_store.get(content_hash)
  --> signature check (keyring lookup -> verify_signature)
  --> revocation check (RevocationList)
  --> policy check (TrustLevel >= minimum)
  --> enforcement mode (Strict / Permissive / AuditOnly)
  --> VerificationResult { passed, checks, trust_level }
```

### Boot Chain Verification

```
List of component paths
  --> for each: look up trusted baseline hash in trust_store
  --> build IntegrityPolicy with expected hashes
  --> IntegrityVerifier::verify_all() (streaming SHA-256 per file)
  --> IntegrityReport { verified, mismatches, errors }
```

## Trust Levels (highest to lowest)

| Level | Meaning | How assigned |
|-------|---------|-------------|
| SystemCore | Core OS component | `register_system_core()` only |
| Verified | Signature verified against keyring | `sign_artifact()` with known key |
| Community | Valid signature, unknown publisher | `sign_artifact()` with unknown key |
| Unverified | No signature or unknown | Default for unregistered artifacts |
| Revoked | Explicitly revoked | Revocation list match |

## Consumers

Sigil is consumed by all AGNOS components that need trust verification:

- **daimon** — agent runtime, verifies agent binaries before execution
- **kavach** — security daemon, manages trust policy
- **ark** — package manager, verifies packages before installation
- **aegis** — system integrity, runs boot chain verification
- **phylax** — guardian, monitors file integrity
- **mela** — marketplace, signs and verifies publisher bundles
- **stiva** — stack/layer manager, verifies configs
- **argonaut** — installer, verifies system images

## Feature Gates

| Feature | Modules | Default |
|---------|---------|---------|
| `integrity` | `integrity.rs` | on |
| `chain` | `chain.rs` (requires `integrity`) | on |
| `policy` | `policy.rs` | on |

With `--no-default-features`, only `trust.rs`, `types.rs`, `verify.rs`, and `error.rs` are compiled. This gives consumers signing and verification without integrity monitoring or revocation management.

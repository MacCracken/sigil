# Sigil

**System-wide trust verification for AGNOS.**

Sigil (Latin: seal) is the single crypto / trust boundary for the
AGNOS operating system — boot chain integrity, agent binary
signing, package verification, TEE remote attestation, and
revocation management.

## Language

Cyrius (ported from Rust v1.0.0; original Rust source removed in
2.7.0). Zero external dependencies.

**Cyrius pin:** `6.0.1` (synced across `cyrius.cyml` and CI).

## Crypto stack

All cryptography implemented in Cyrius — no external dependencies:

- **Ed25519** (RFC 8032) — asymmetric signing/verification
- **ECDSA P-256** (FIPS 186-4) — SEC1 curve secp256r1 verify
- **ECDSA P-384** (FIPS 186-4) — SEC1 curve secp384r1 verify
- **SHA-256** (FIPS 180-4) — content hashing
- **SHA-384** (FIPS 180-4) — paired with P-384 ECDSA and TDX att_key_type=3
- **SHA-512** (FIPS 180-4) — Ed25519 key expansion
- **HMAC-SHA256** (RFC 2104) — keyed hashing
- **HKDF-SHA256** (RFC 5869) — key derivation
- **AES-256-GCM** (FIPS 197 + NIST SP 800-38D) — AEAD with AES-NI
  dispatch (runtime-detected)
- **ML-DSA-65** (FIPS 204) — post-quantum signing, gated behind
  `-D SIGIL_PQC` until the cyrius preprocessor cap raises
- **Constant-time comparison** — bitwise-OR accumulation; no
  early-exit branches on secret data
- **Cryptographic RNG** — `/dev/urandom` with short-read validation

## Modules

### Crypto primitives

- **`sha256.cyr`**, **`sha384.cyr`**, **`sha512.cyr`** — hashing
- **`sha_ni.cyr`** — SHA-256-NI hardware dispatch (runtime probe)
- **`hmac.cyr`**, **`hkdf.cyr`** — keyed hashing and key derivation
- **`bigint_ext.cyr`** — 256-bit field arithmetic for Ed25519
- **`ed25519.cyr`** — Ed25519 signatures
- **`ecdsa_p256.cyr`**, **`ecdsa_p384.cyr`** — ECDSA verify
- **`aes_gcm.cyr`**, **`aes_ni.cyr`** — AES-256-GCM AEAD
- **`mldsa_*.cyr`** — ML-DSA-65 (PQC, opt-in)
- **`hex.cyr`** — hex encode/decode

### Trust engine

- **`types.cyr`** — TrustLevel, TrustPolicy, TrustedArtifact, etc.
- **`error.cyr`** — SigilError codes, Result pattern
- **`trust.cyr`** — PublisherKeyring, signing, key management
- **`integrity.cyr`** — file hash measurement and verification
- **`policy.cyr`** — revocation lists and CRL
- **`audit.cyr`** — structured audit logging
- **`verify.cyr`** — SigilVerifier main trust engine (single +
  parallel-batch entry points)
- **`certpin.cyr`** — TLS cert SPKI pinning

### TEE remote attestation (3.2.x + 3.4 cycles)

- **`x509.cyr`** — minimal X.509 cert parser + chain walker
  (P-256 and P-384 SPKIs; ECDSA-SHA256 chain-link signatures)
- **`pem.cyr`** — RFC 4648 base64 + PEM block decoder
- **`sgx.cyr`** — Intel SGX DCAP v3 quote parser +
  `sgx_quote_verify_with_pck` + `sgx_quote_verify_full`
- **`tdx.cyr`** — Intel TDX v4 TD-quote parser + verify
  orchestrators; dispatches on `att_key_type` (P-256 or P-384)
- **`sev_snp.cyr`** — AMD SEV-SNP attestation report parser +
  `snp_report_verify` + `snp_report_verify_full`
- **`seal.cyr`** — SGX sealing-key derivation (HKDF-bound)

### System integration

- **`tpm.cyr`** — TPM interface (runtime detection, PCR measurement)
- **`ima.cyr`** — Linux IMA log verification
- **`secureboot.cyr`** — Secure Boot chain verification

## Architecture overview

```
                    ┌─────────────────┐
                    │  consumer apps  │  daimon, kavach, ark, aegis,
                    │   (AGNOS)       │  phylax, mela, stiva, argonaut
                    └────────┬────────┘
                             │
                  ┌──────────▼──────────┐
                  │  verify.cyr         │  SigilVerifier
                  │  trust.cyr          │  PublisherKeyring
                  │  integrity.cyr      │  file hash verify
                  │  policy.cyr         │  revocation
                  │  certpin.cyr        │  SPKI pinning
                  └──────────┬──────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
│  TEE attest    │  │ system integ    │  │  primitives     │
│  sgx / tdx /   │  │  tpm / ima /    │  │  ed25519, ecdsa,│
│  sev_snp /     │  │  secureboot     │  │  sha2, hmac,    │
│  seal / x509 / │  │                 │  │  hkdf, aes-gcm, │
│  pem           │  │                 │  │  mldsa          │
└────────────────┘  └─────────────────┘  └─────────────────┘
```

See [`docs/architecture/overview.md`](docs/architecture/overview.md)
for the full module map and data flow.

## Tests

1178 assertions across 37 test files, 0 failures (3.4.1 baseline).
The TEE attestation arc and 3.4 cycle ship with synthesised
end-to-end fixtures regeneratable from `scripts/*.out`.

```sh
cyrius build programs/smoke.cyr build/sigil   # full build
for t in tests/tcyr/*.tcyr; do cyrius test "$t"; done
```

## Roadmap

Open cycles (gated on forcing functions):

- **v3.5** — parallel verify (drop `_sigil_batch_mutex` via
  caller-provided crypto scratch).
- **v3.6** — perf tuning: Solinas word-level field reduction for
  P-256/P-384 (target ≤ 10 ms/verify) + unified `_into` API
  (closes seven open bump-allocator LOWs).

See [`docs/development/roadmap.md`](docs/development/roadmap.md)
for the active backlog and possible future surfaces.

## Documentation

- [`CHANGELOG.md`](CHANGELOG.md) — every release entry
- [`CLAUDE.md`](CLAUDE.md) — development process + cyrius quirks
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — work loop and submission
  checklist
- [`SECURITY.md`](SECURITY.md) — supported versions, reporting,
  scope, crypto implementations
- [`docs/architecture/overview.md`](docs/architecture/overview.md)
  — module map, data flow, consumers
- [`docs/development/roadmap.md`](docs/development/roadmap.md)
  — forward-looking work
- [`docs/audit/`](docs/audit/) — security audit reports per cycle

## License

GPL-3.0-only

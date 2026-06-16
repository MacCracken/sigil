# Sigil Architecture

## Module Map

Single-file compilation via `include` (Cyrius flat-library shape).
Order in `src/lib.cyr` reflects dependency direction — primitives
first, trust engine last.

```
lib.cyr (entry point)
  │
  ├── types.cyr         Enums, structs, constructors, accessors
  ├── error.cyr         SigilError codes, Result pattern
  ├── crypto_scratch.cyr Per-thread crypto-scratch banks (3.6 parallel verify)
  │
  ├── sha_ni.cyr        SHA-256-NI hardware dispatch (runtime probe)
  ├── sha256.cyr        FIPS 180-4 SHA-256
  ├── hex.cyr           Hex encode/decode
  │
  ├── hmac.cyr          HMAC-SHA256 (RFC 2104)
  ├── hkdf.cyr          HKDF-SHA256 (RFC 5869)
  ├── aes_ni.cyr        AES-NI hardware dispatch (runtime probe)
  ├── aes_gcm.cyr       AES-256/128-GCM AEAD (FIPS 197 + NIST SP 800-38D)
  ├── poly1305.cyr      Poly1305 one-time MAC (RFC 8439 §2.5)
  ├── chacha20.cyr      ChaCha20 stream cipher (RFC 8439 §2.3/§2.4)
  ├── chacha20poly1305.cyr  ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)
  │
  ├── sha512.cyr        FIPS 180-4 SHA-512 (Ed25519 key expansion)
  ├── sha384.cyr        FIPS 180-4 SHA-384 (P-384 ECDSA, TDX P-384)
  ├── hmac_sha384.cyr   HMAC-SHA384 (RFC 4231 / FIPS 198-1)
  ├── hkdf_sha384.cyr   HKDF-SHA384 (RFC 5869)
  ├── tls12_prf.cyr     TLS 1.2 PRF P_SHA256/P_SHA384 (RFC 5246 §5)
  ├── bigint_ext.cyr    256-bit field arithmetic (mod p = 2^255-19; Karatsuba u256_mul_full)
  ├── bignum.cyr        General variable-width big-int + modexp (RSA engine)
  ├── ed25519.cyr       Ed25519 sign/verify (RFC 8032)
  ├── x25519.cyr        X25519 ECDH key agreement (RFC 7748)
  ├── ecdsa_p256.cyr    ECDSA verify on secp256r1 (FIPS 186-4)
  ├── ecdsa_p384.cyr    ECDSA verify on secp384r1 (FIPS 186-4)
  ├── ecdsa_sign.cyr    ECDSA P-256/P-384 RFC 6979 deterministic sign
  │
  ├── x509.cyr          Minimal X.509 parser + chain walker
  │                       — P-256 and P-384 SPKIs
  │                       — ECDSA-SHA256 chain-link signatures only
  ├── pem.cyr           RFC 4648 base64 + PEM block decoder
  ├── privkey.cyr       EC + Ed25519 private-key parsers (PEM + DER)
  ├── rsa.cyr           RSA PKCS#1 v1.5 verify + sign + keys (RFC 8017)
  ├── sgx.cyr           Intel SGX DCAP v3 quote parse + verify
  │                       — sgx_quote_verify_with_pck (per-piece)
  │                       — sgx_quote_verify_full (end-to-end)
  ├── sev_snp.cyr       AMD SEV-SNP attestation report verify
  │                       — snp_report_verify (per-piece)
  │                       — snp_report_verify_full (end-to-end)
  ├── tdx.cyr           Intel TDX v4 TD-quote verify
  │                       — dispatches on att_key_type (P-256 or P-384)
  │                       — tdx_quote_verify_with_pck (per-piece)
  │                       — tdx_quote_verify_full (end-to-end)
  ├── seal.cyr          SGX sealing-key derivation (HKDF-bound)
  │
  ├── ML-DSA-65         FIPS 204 PQC signing — default-on since 3.7.6 — 8 files
  │   ├── mldsa_params, mldsa_reduce, mldsa_ntt, mldsa_poly,
  │   ├── mldsa_rounding, mldsa_encode, mldsa_sample, mldsa
  │
  ├── trust.cyr         PublisherKeyring, sign/verify, key management
  ├── integrity.cyr     IntegrityVerifier, file hash measurement
  ├── policy.cyr        RevocationList, CRL
  ├── audit.cyr         AuditLog, structured events
  ├── tpm.cyr           TPM interface (runtime detection)
  ├── ima.cyr           Linux IMA log verification
  ├── secureboot.cyr    Secure Boot chain verification
  ├── certpin.cyr       TLS cert SPKI pinning
  └── verify.cyr        SigilVerifier (main trust engine,
                        single + parallel-batch entry points)
```

## Data Flow

### Trust-store / publisher verification

```
Artifact on disk
  → hash_file()       → content_hash (SHA-256 hex)
  → trust_store lookup → TrustedArtifact
  → signature verify  → Ed25519 (or HMAC fallback for legacy)
  → revocation check  → key + content_hash
  → key pin check     → path-prefix authorization
  → policy compliance → enforcement mode + minimum trust
  → VerificationResult (passed/failed + per-check status)
  → AuditEvent logged
```

### TEE remote attestation (SGX / TDX / SEV-SNP)

The 3.4 cycle added end-to-end orchestrators that close the
"caller must walk the X.509 chain themselves" gap from 3.2.x.

```
SGX / TDX quote bytes              SEV-SNP report bytes (1184 B)
  │                                  │
  ▼                                  ▼
sgx_quote_parse                    snp_report_parse
tdx_quote_parse                      │
  │                                  │
  ▼                                  ▼
*_quote_verify_full(quote,         snp_report_verify_full(report,
  intel_sgx_root_der,                vcek_chain_pem, ark_root_der,
  now_unix)                          now_unix)
  │                                  │
  ├─► pem_decode_certs       ◄──────┤
  │   (qe_cert_data → PCK)           (out-of-band VCEK chain → leaf)
  │
  ├─► x509_parse each + root
  ├─► drop self-issued top-of-chain (embedded root copy)
  ├─► x509_verify_chain (anchored on caller's external root)
  │
  ├─► extract leaf pubkey (64 B for SGX/TDX PCK, 96 B for SNP VCEK)
  │
  ├─► sgx_quote_verify_with_pck      snp_report_verify
  │     (3 internal sig checks:        (SHA-384 + P-384 ECDSA over
  │      PCK→QE-report, AK binding,    signed body)
  │      AK→quote-body — dispatches
  │      on att_key_type for TDX)
  │
  └─► returns 1 on full success, 0 on any failure
```

### Parallel batch verify

`verify.cyr:sv_verify_batch` fans the artifact list out across
worker threads. Each worker calls into `sv_verify_artifact_into`
with a pre-allocated artifact scratch buffer (no bump-allocator
calls from worker bodies — see CLAUDE.md quirk #7). Since **3.6.0**
the path is **mutex-free**: each worker is assigned a private *bank*
of every crypto primitive's transient working state via thread-local
storage (`crypto_scratch.cyr`), so concurrent workers never share the
static `var X[N]` scratch the old `_sigil_batch_mutex` used to
serialise. Result: ~3.4× at 64 artifacts / 4 workers. See
`docs/audit/2026-06-03-3.6.0-parallel-verify-audit.md`.

**Banking is plain `var` + per-lane wipe, never `secret var`.** A banked
array holding secret state (x25519's clamped scalar `k`, chacha20's
keystream) must zeroize **only the calling worker's own lane** on exit —
a `secret var` whole-array wipe would zero *all* lanes and clobber a
concurrent worker (a real corruption caught by `tests/tcyr/
banking_concurrent.tcyr`; CLAUDE.md quirk #9 / ADR 0004). 3.8.0 extended
the bank scheme from the verify primitives to `chacha20_block` /
`chacha20_xor` / `x25519` / `x25519_base` ahead of any concurrent AEAD or
TLS-handshake consumer. See
`docs/audit/2026-06-16-3.8.0-chacha-x25519-banking-audit.md`.

## Consumers

`daimon`, `kavach`, `ark`, `aegis`, `phylax`, `mela`, `stiva`,
`argonaut`, and any AGNOS application needing trust verification.

## Dependencies

- **Cyrius stdlib (auto-included)**: `alloc`, `freelist`, `vec`,
  `hashmap`, `str`, `string`, `io`, `fs`, `fmt`, `result`, `fnptr`,
  `bayan`, `chrono`, `tagged`, `process`, `slice`, `atomic`. (`json` /
  `bigint` were folded into `bayan` at cyrius 6.1.25 — neither ships
  standalone on the 6.2.x pin.)
- **Cyrius stdlib (opt-in — consumer MUST `include`)**: `lib/ct.cyr`,
  `lib/keccak.cyr`, `lib/thread.cyr`, `lib/thread_local.cyr`,
  `lib/random.cyr` — see README → Usage. Omitting any is a runtime
  `ud2`/SIGILL, not a build failure.
- **AGNOS first-party crates**: `sakshi` (structured tracing, `2.3.0`)
  — `programs/smoke.cyr` + full `src/lib.cyr` only; `agnosys` (kernel
  interfaces, `1.4.3`) — `tpm`/`ima`/`secureboot`/`certpin` only.
  **Neither is referenced by the `dist/sigil.cyr` crypto bundle.**
- **External**: none

## Single-pass compilation notes

Sigil is included by `src/lib.cyr` as a single compilation unit;
consumers either include `src/lib.cyr` for the full surface or
pick individual modules (e.g. `tests/tcyr/x509.tcyr` includes
only what the test needs). The ML-DSA modules were historically
gated behind `#ifdef SIGIL_PQC` to stay under cyrius's 1 MB
preprocessor output cap (CLAUDE.md quirk #8); **cyrius 6.0.87
raised the cap and 3.7.6 dropped the gate** — PQC is now
unconditional and `-D SIGIL_PQC` is a back-compat no-op.

# Sigil

**System-wide trust verification for AGNOS.**

Sigil (Latin: seal) is the single crypto / trust boundary for the
AGNOS operating system — boot chain integrity, agent binary
signing, package verification, TEE remote attestation, and
revocation management.

## Language

Cyrius (ported from Rust v1.0.0; original Rust source removed in
2.7.0). Zero external dependencies.

**Cyrius pin:** `6.0.53` (synced across `cyrius.cyml` and CI).

## Crypto stack

All cryptography implemented in Cyrius — no external dependencies:

- **Ed25519** (RFC 8032) — asymmetric signing/verification
- **ECDSA P-256 / P-384** (FIPS 186-4) — secp256r1 / secp384r1
  verify **and** RFC 6979 deterministic signing (raw + DER)
- **X25519** (RFC 7748) — Curve25519 ECDH key agreement
- **SHA-256 / SHA-384 / SHA-512** (FIPS 180-4) — hashing
- **HMAC-SHA256 / HMAC-SHA384** (RFC 2104 / FIPS 198-1) — keyed hashing
- **HKDF-SHA256 / HKDF-SHA384** (RFC 5869) — key derivation
- **TLS 1.2 PRF** (RFC 5246 §5) — P_SHA256 / P_SHA384 key schedule
- **RSA PKCS#1 v1.5** (RFC 8017) — signature verify **and** sign,
  SHA-256/384, with DER/PEM key parsing (PKCS#1, SPKI, PKCS#8); on a
  general big-integer engine (constant-time Montgomery modexp for the
  secret exponent; verify-after-sign fault guard)
- **AES-256-GCM / AES-128-GCM** (FIPS 197 + NIST SP 800-38D) — AEAD
  with runtime-detected AES-NI dispatch
- **ChaCha20-Poly1305** (RFC 8439) — AEAD (ChaCha20 cipher +
  Poly1305 one-time MAC)
- **ML-DSA-65** (FIPS 204) — post-quantum signing, gated behind
  `-D SIGIL_PQC` until the cyrius preprocessor cap raises
- **Private-key parsers** — PEM + DER for ECDSA P-256/P-384 (SEC1 /
  PKCS#8) and Ed25519 (PKCS#8); X.509 + PEM cert parsing
- **Constant-time comparison** — bitwise-OR accumulation; no
  early-exit branches on secret data
- **Cryptographic RNG** — `/dev/urandom` with short-read validation

## Modules

### Crypto primitives

- **`sha256.cyr`**, **`sha384.cyr`**, **`sha512.cyr`** — hashing
- **`sha_ni.cyr`** — SHA-256-NI hardware dispatch (runtime probe)
- **`hmac.cyr`**, **`hkdf.cyr`** — HMAC/HKDF-SHA256
- **`hmac_sha384.cyr`**, **`hkdf_sha384.cyr`** — HMAC/HKDF-SHA384
- **`tls12_prf.cyr`** — TLS 1.2 PRF (RFC 5246 §5), P_SHA256/P_SHA384
- **`bignum.cyr`** — general variable-width big integers + modexp
- **`rsa.cyr`** — RSA PKCS#1 v1.5 verify + sign + key parsing (RFC 8017)
- **`bigint_ext.cyr`** — 256-bit field arithmetic for Ed25519/X25519
- **`ed25519.cyr`** — Ed25519 signatures
- **`x25519.cyr`** — X25519 ECDH key agreement
- **`ecdsa_p256.cyr`**, **`ecdsa_p384.cyr`** — ECDSA verify
- **`ecdsa_sign.cyr`** — ECDSA P-256/P-384 RFC 6979 deterministic sign
- **`privkey.cyr`** — EC + Ed25519 private-key parsers (PEM + DER)
- **`aes_gcm.cyr`**, **`aes_ni.cyr`** — AES-256/128-GCM AEAD
- **`chacha20.cyr`**, **`poly1305.cyr`**, **`chacha20poly1305.cyr`**
  — ChaCha20-Poly1305 AEAD
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

## Usage — stdlib include order (3.6+)

Sigil is consumed as a vendored distlib: `cyrius deps` resolves it into your
`lib/sigil.cyr`, which you then `include`.

**Since 3.6, two stdlib modules must be `include`d _before_ `lib/sigil.cyr`** —
and they are *not* part of the cyrius auto-prepend union (the base stdlib —
`string`/`alloc`/`str`/`vec`/`io`/… — is, so those stay automatic). This is the
same opt-in pattern as [mabda](https://github.com/MacCracken/mabda)'s manual
deps:

```cyrius
include "lib/thread.cyr"         # thread_create / thread_join — parallel-batch verify
include "lib/thread_local.cyr"   # thread_local_init/get/set — per-thread crypto banks
include "lib/sigil.cyr"          # sigil itself — MUST come last

fn main(): i64 {
    # build a PublisherKeyring + TrustPolicy, then:
    var sv = sigil_verifier_new(keyring, policy);
    var r = sv_verify_agent(sv, "/path/to/agent");
    # single OR sv_verify_batch parallel verify — both now safe, no caller mutex
    return 0;
}
```

**Why it's now required (and why ≤ 3.5.x consumers break on upgrade):** 3.6
replaced the `_sigil_batch_mutex` with per-thread crypto-scratch *banks* backed
by thread-local storage (the threading-safety contract at the top of
`dist/sigil.cyr` has the full mechanism). `cbank()` is on the hot path of
**every** banked primitive (`sha_ni` onward) and lazily calls
`thread_local_init()`, so even a single *serial* `sv_verify_*` reaches it — the
dependency is unconditional, not parallel-batch-only. Omitting the includes
fails the build with `undefined variable 'thread_local_init'` (or
`'thread_create'`) sourced from inside `sigil.cyr`.

Requires **cyrius ≥ 6.0.52** (the release that shipped `lib/thread_local.cyr`).

## Tests

1329 assertions across 50 test files, 0 failures (3.6.3). Crypto
suites use published known-answer vectors (RFC / FIPS / NIST); the
TEE attestation arc ships synthesised end-to-end fixtures.
`tests/tcyr/batch_parallel.tcyr` doubles as the parallel-verify race
detector — run mutex-off since 3.6.

```sh
cyrius build programs/smoke.cyr build/sigil   # full build
for t in tests/tcyr/*.tcyr; do cyrius test "$t"; done
```

## Roadmap

- **v3.5.x — cyrius native-TLS arc support** (in progress). Shipped:
  modern AEAD + key agreement (Poly1305/ChaCha20/AEAD/X25519,
  HMAC/HKDF-SHA384), AES-128-GCM, EC + Ed25519 private-key parsers,
  ECDSA P-256/P-384 deterministic signing, TLS 1.2 PRF (3.6.1), RSA
  PKCS#1 v1.5 **verify** + bignum/modexp engine (3.6.2), RSA key
  parsing + PKCS#1 v1.5 **sign** (3.6.3). Remaining (3.6.x): RSA sign
  hardening — CRT + blinding — with a security audit pass (3.6.4),
  then PSS + cycle closeout.
- **v3.6** — parallel verify (**shipped 3.6.0**): dropped
  `_sigil_batch_mutex` via per-thread crypto-scratch banks over
  cyrius 6.0.52 thread-local storage (3.42× at 64 artifacts / 4
  workers).
- **v3.7** — perf tuning: Solinas word-level field reduction for
  P-256/P-384 (target ≤ 10 ms/verify) + unified `_into` API
  (closes the open bump-allocator LOWs).

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

# Security Policy

## Supported Versions

Sigil follows a rapid release cadence — minor bumps land
frequently, patch versions ship within hours of report when
needed. The supported window is **the current minor and the
immediately preceding minor**.

| Version | Supported |
|---------|-----------|
| 3.11.x | Yes (current minor) |
| 3.10.x | Yes (prior minor) |
| < 3.10.0 | No — upgrade within the 3.x line |

Older 2.x versions are no longer supported; the 3.0 cutover
(2026-05-01) removed the Rust source after parity closeout and
the supported window has been on the 3.x line since.

## Reporting a Vulnerability

Sigil is a security-critical component of AGNOS — it IS the
trust boundary for every consumer (`daimon`, `kavach`, `ark`,
`aegis`, `phylax`, `mela`, `stiva`, `argonaut`). If you
discover a vulnerability:

1. **Do not** open a public issue.
2. Email security@agnos.dev with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix
within 7 days for CRITICAL and HIGH severity issues. MEDIUM and
LOW severities are handled in the next regular cycle.

Severity definitions (from CLAUDE.md):

- **CRITICAL** — exploitable immediately; remote or privilege
  escalation; key leakage; signature forgery.
- **HIGH** — exploitable with moderate effort; timing
  side-channel on secret data.
- **MEDIUM** — exploitable under specific conditions.
- **LOW** — defense-in-depth improvement.

## Scope

In scope:

- Timing side-channels in hash comparison, signature
  verification, or AEAD primitives
- Key material leakage (memory residue, logs, error messages)
- Trust-level bypass or escalation
- Revocation bypass
- Signature forgery or verification bypass
- ECDSA / Ed25519 / ML-DSA implementation flaws (RFC 8032,
  FIPS 186-4, FIPS 204 conformance)
- AES-GCM tag forgery or nonce-reuse handling
- X.509 / PEM parser memory safety (all inputs are
  attacker-controlled per the TEE attestation threat model)
- TEE attestation verifier flaws (SGX DCAP v3, TDX v4,
  SEV-SNP report verification)
- Integer overflow in hash/signature/AEAD length handling
- Path traversal in file operations
- Command injection via any sigil entry point

## Cryptographic Implementations

As of the Cyrius port (v2.0.0), sigil owns all of its crypto
primitives directly — zero external dependencies. Each
implementation follows the referenced standard:

- **Ed25519** (signatures) — RFC 8032, `src/ed25519.cyr`
- **ECDSA P-256** (verify) — FIPS 186-4, `src/ecdsa_p256.cyr`
- **ECDSA P-384** (verify) — FIPS 186-4, `src/ecdsa_p384.cyr`
- **SHA-256** (hashing) — FIPS 180-4, `src/sha256.cyr`
  (+ SHA-NI runtime dispatch in `src/sha_ni.cyr`)
- **SHA-384** (hashing) — FIPS 180-4, `src/sha384.cyr`
- **SHA-512** (Ed25519 hash) — FIPS 180-4, `src/sha512.cyr`
- **HMAC-SHA256** — RFC 2104, `src/hmac.cyr`
- **HKDF-SHA256** — RFC 5869, `src/hkdf.cyr`
- **ECDSA P-256 / P-384 deterministic signing** — RFC 6979,
  `src/ecdsa_sign.cyr`
- **HMAC-SHA384 / HKDF-SHA384** — RFC 2104 / RFC 5869,
  `src/hmac_sha384.cyr`, `src/hkdf_sha384.cyr`
- **TLS 1.2 PRF** (P_SHA256 / P_SHA384) — RFC 5246 §5,
  `src/tls12_prf.cyr`
- **RSA PKCS#1 v1.5** (verify + sign) — RFC 8017, on a
  constant-time Montgomery modexp engine with base blinding,
  CRT, and a Bellcore verify-after-sign fault guard,
  `src/rsa.cyr`, `src/bignum.cyr`
- **AES-256-GCM / AES-128-GCM** (AEAD) — FIPS 197 + NIST
  SP 800-38D (arbitrary-length IVs per §7.1 since 3.7.2),
  `src/aes_gcm.cyr` (+ AES-NI runtime dispatch in
  `src/aes_ni.cyr`)
- **ChaCha20-Poly1305** (AEAD) — RFC 8439,
  `src/chacha20.cyr`, `src/poly1305.cyr`,
  `src/chacha20poly1305.cyr`
- **X25519** (ECDH key agreement) — RFC 7748, `src/x25519.cyr`
- **ML-DSA-65** (PQC signing) — FIPS 204, `src/mldsa*.cyr`,
  **default-on since 3.7.6** (`-D SIGIL_PQC` is now a
  back-compat no-op; needs `lib/keccak.cyr`)
- **X.509 parser + chain walker** — minimal subset (P-256 /
  P-384 SPKIs, ECDSA-SHA256 chain links), `src/x509.cyr`
- **PEM decoder** — RFC 4648 base64, `src/pem.cyr`
- **Constant-time comparison** — bitwise-OR accumulation;
  cyrius stdlib's `lib/ct.cyr`
  (`ct_eq_bytes` / `ct_eq_bytes_lens`; was sigil's
  `src/ct.cyr` pre-3.0.2)
- **Cryptographic RNG** — kernel CSPRNG via the single entropy
  boundary `_sigil_random_fill` (`src/random.cyr`) → stdlib
  `random_bytes`, which dispatches per-target (getrandom on
  Linux/AGNOS, getentropy on macOS, ProcessPrng on Windows) and
  is **fail-closed** (no weak fallback). Every keygen / nonce /
  blinding draw — including `tpm_random` in `src/tpm.cyr` —
  funnels through it (since 3.7.15; replaced the prior direct
  `/dev/urandom` path, which was non-functional on Windows).

## Audit Trail

Every release ships with a corresponding audit document under
[`docs/audit/YYYY-MM-DD-audit.md`](docs/audit/). Multiple-cycle
days disambiguate via `YYYY-MM-DD-<version>-audit.md`. Each
audit follows the 10-step Security Hardening checklist in
`CLAUDE.md` and records findings by severity.

The 3.2.x TEE attestation arc (six bites) and the 3.4.x TEE
completion cycle (two bites) collectively introduced ~3700 lines
of cryptographic and parsing code at **0 CRITICAL / 0 HIGH /
0 MEDIUM** findings. The LOW findings of the bump-allocator
per-call-lifetime shape were **resolved at 3.7.3** via the
caller-scratch `_into` API — the **audit floor cleared 8 → 0**
and has held empty through **3.9.7**. The 3.9.6 and 3.9.7
concurrent-crypto banking audits resolved every finding in-cycle
(3.9.7: F1 MEDIUM latent DER-wrapper race, F2 LOW RSA-sign
secret-residue — both fixed before ship).

## Threat model assumptions

- TEE quote / report bytes are fully attacker-controlled (they
  travel from an untrusted remote host via the attestation flow).
  Every length field, offset, and embedded structure is validated
  before any dereference.
- X.509 / PEM parsers operate against attacker-controlled DER
  and base64 input; bounds-check every TLV walk and every base64
  decode write.
- The caller establishes the trust root externally (Intel SGX
  Root CA, AMD ARK Root, AGNOS publisher keyring). Sigil never
  trusts an in-quote / in-chain "root copy" — embedded
  self-issued certs are silently dropped before chain verify.
- Single-tenant deployment for AGNOS — cache-timing attacks
  from a co-located adversary are out of scope today; queued
  via the "scatter-store for the fixed-base comb" backlog item
  if the threat model shifts.

Pre-port Rust crate dependencies (`ed25519-dalek`, `sha2`,
`subtle`, `rand`) are no longer used. The original Rust source
was removed in 2.7.0 after full parity closeout;
`benchmarks-rust-v-cyrius.md` retains the cross-implementation
performance baseline.

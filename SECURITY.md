# Security Policy

## Supported Versions

Sigil follows a rapid release cadence — minor bumps land
frequently, patch versions ship within hours of report when
needed. The supported window is **the current minor and the
immediately preceding minor**.

| Version | Supported |
|---------|-----------|
| 3.12.x | Yes (current minor) |
| 3.11.x | Yes (prior minor) |
| < 3.11.0 | No — upgrade within the 3.x line |

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
- Authenticode PE parser memory safety, and Authenticode
  signature forgery or verification bypass (`src/authenticode.cyr`)
- UEFI signature-list / signed-variable enrollment construction
  flaws (`src/efi_sigdb.cyr`)
- Argon2 / BLAKE2b implementation flaws (RFC 9106 / RFC 7693
  conformance) and password-KDF parameter handling
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
- **BLAKE2b** (hashing, keyed + unkeyed) — RFC 7693,
  `src/blake2b.cyr`
- **Argon2id / Argon2i / Argon2d** (memory-hard password
  hashing) — RFC 9106, `src/argon2.cyr`, built on the BLAKE2b
  above. Argon2 is memory-hard by design, so a single hash
  allocates and touches the full `m` cost — a login endpoint
  **must rate-limit** or the KDF becomes a memory-amplifying DoS
  vector
- **HMAC-SHA256** — RFC 2104, `src/hmac.cyr`
- **HKDF-SHA256** — RFC 5869, `src/hkdf.cyr`
- **ECDSA P-256 / P-384 deterministic signing** — RFC 6979,
  `src/ecdsa_sign.cyr`
- **HMAC-SHA384 / HKDF-SHA384** — RFC 2104 / RFC 5869,
  `src/hmac_sha384.cyr`, `src/hkdf_sha384.cyr`
- **TLS 1.2 PRF** (P_SHA256 / P_SHA384) — RFC 5246 §5,
  `src/tls12_prf.cyr`
- **RSA PKCS#1 v1.5 and RSA-PSS** (verify + sign) — RFC 8017,
  `src/rsa.cyr`, `src/bignum.cyr`. **Secret** exponents
  (`d`, `dp`, `dq`) run on the constant-time Montgomery ladder
  (`bn_mont_modexp`) with base blinding, CRT, and a Bellcore
  verify-after-sign fault guard. Since 3.12.2 the **public**
  exponent runs a separate public-schedule modexp
  (`bn_mont_modexp_pub` — high-bit scan + conditional multiply
  instead of the unconditional constant-time multiply); it
  **must not** be used with a secret exponent. Its three call
  sites all take public exponents: verify's `_rsa_recover_em`,
  the sign path's blinding `r^e`, and the verify-after-sign
  `s^e`
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
  P-384 / Ed25519 / RSA SPKIs; chain links dispatch to
  ECDSA-SHA256/384, Ed25519, or `rsa_pkcs1v15_verify_sha256/384`
  per the issuer key), `src/x509.cyr`
- **PEM decoder** — RFC 4648 base64, `src/pem.cyr`
- **Authenticode PE signing and verification** —
  `src/authenticode.cyr`: the Authenticode SHA-256 image digest,
  a bottom-up definite-length DER encoder, PKCS#7 / CMS
  `SignedData` over `SpcIndirectDataContent`, and (since 3.12.2)
  `authenticode_pe_verify` / `_verify_ex` / `_verify_chain` /
  `_verify_chain_ex`, which accept both sigil's own output and
  third-party binaries (CMS signedAttrs with the `0xA0` → `0x31`
  re-tag, `sha256WithRSAEncryption`). Signing is RSA PKCS#1 v1.5
  or, via `authenticode_pkcs7_sign_p256` /
  `authenticode_pe_sign_p256`, ECDSA P-256 with RFC 6979
  deterministic nonces
- **UEFI signature lists + signed variable enrollment** —
  `src/efi_sigdb.cyr`: `efi_signature_list_from_cert` (`.esl`),
  `efi_time`, and `efi_auth_from_esl`
  (`EFI_VARIABLE_AUTHENTICATION_2` / `.auth`, a detached PKCS#7
  under `EFI_CERT_TYPE_PKCS7`)
- **Constant-time comparison** — bitwise-OR accumulation;
  cyrius stdlib's `lib/ct.cyr`
  (`ct_eq_bytes` / `ct_eq_bytes_lens`; was sigil's
  `src/ct.cyr` pre-3.0.2)
- **64×64 → 128 limb multiply** — `src/mul64.cyr` (new in
  3.12.2), x86-64 `MUL r/m64` in an `asm{}` block under
  `#ifdef CYRIUS_ARCH_X86` with a portable aarch64 fallback. No
  CPUID probe — `MUL r/m64` is baseline x86-64, not an ISA
  extension. It backs every big-integer path (RSA, ECDSA P-256 /
  P-384, Ed25519) and is also a **side-channel improvement**:
  the portable 32-bit-halves code it replaces carried two
  value-dependent carry-fixup branches per product, so the
  secret-operand ladders no longer branch on operand values here
- **Cryptographic RNG** — kernel CSPRNG via the single entropy
  boundary `_sigil_random_fill` (`src/random.cyr`) → stdlib
  `random_bytes`, which dispatches per-target (getrandom on
  Linux/AGNOS, getentropy on macOS, ProcessPrng on Windows) and
  is **fail-closed** (no weak fallback). Every keygen / nonce /
  blinding draw — including `tpm_random` in `src/tpm.cyr` —
  funnels through it (since 3.7.15; replaced the prior direct
  `/dev/urandom` path, which was non-functional on Windows).

## Audit Trail

Each **security-bearing** cycle files an audit document under
[`docs/audit/`](docs/audit/), named `YYYY-MM-DD-<version>-<topic>-audit.md`
(multiple-cycle days disambiguate on the version). Each audit
follows the 10-step Security Hardening checklist in `CLAUDE.md`
and records findings by severity.

**Stated plainly rather than aspirationally:** this is not yet
one document per release. `docs/audit/` jumps from the 3.9.7
audit (2026-06-29) to the 3.12.2 audit (2026-07-30) — the six
releases in between (3.10.0, 3.10.1, 3.11.0, 3.11.1, 3.12.0,
3.12.1) have no audit document of their own, and their security
notes live in `CHANGELOG.md` instead. The gap is tracked in
[`docs/doc-health.md`](docs/doc-health.md).

The 3.2.x TEE attestation arc (six bites) and the 3.4.x TEE
completion cycle (two bites) collectively introduced ~3700 lines
of cryptographic and parsing code at **0 CRITICAL / 0 HIGH /
0 MEDIUM** findings. The LOW findings of the bump-allocator
per-call-lifetime shape were **resolved at 3.7.3** via the
caller-scratch `_into` API — the **audit floor cleared 8 → 0**
and has held empty through **3.12.2**. Every audit since has
resolved its findings in-cycle, so nothing is carried forward:
3.9.6 (the concurrent-TLS-handshake crash), 3.9.7 (F1 MEDIUM
latent DER-wrapper race, F2 LOW RSA-sign secret-residue), and
3.12.2 (below).

**3.10.1** fixed a memory-safety defect in the same module the
3.12.2 findings touch: `authenticode_pe_hash` read the 2-byte PE
optional-header magic before proving those bytes were inside the
image, a 1–2 byte OOB read on a truncated PE. Fixed by hoisting
the `opt + 2 > pe_len` bound above the read.

**3.12.2 — F1 HIGH: a signing-correctness defect in shipped
code** ([full audit](docs/audit/2026-07-30-3.12.2-asm-multiply-authenticode-verify-audit.md)).
**Read the direction first: this fails CLOSED.** It is not a
forgery or key-recovery class — nothing wrong is ever *accepted*
— it is an availability defect on the boot chain, which is why
it is rated HIGH rather than MEDIUM: the artifact is long-lived
and the failure is silent at signing time.
Through 3.12.1 `authenticode_pe_sign` hashed `pe[0, pe_len)` but
wrote the attribute-certificate table at the 8-byte-aligned
`cert_start`, zero-padding `[pe_len, cert_start)`. The
Authenticode spec hashes up to the cert table — *including* that
pad — so for any `pe_len` not a multiple of 8, sigil's signature
covered a different byte range than firmware / sbverify /
Windows recompute: a structurally valid signature on an image
firmware would reject. It stayed invisible because PE file
alignment is 512 and the test fixture was 256 bytes, both
8-aligned. Fixed by laying the image plus pad down first and
hashing `out[0, cert_start)`; **aligned inputs still produce
byte-identical signatures to 3.12.1**, only unaligned inputs
change. Regression-locked by a 253-byte round-trip test that was
mutation-proven — it fails on the 3.12.1 signer behaviour and
passes on the fix.

The same cycle recorded **F2 LOW** and **four hardenings**, all
reachable from untrusted input, plus two INFO findings (the new
asm multiply *improves* the constant-time posture by removing
two value-dependent branches per limb product; and the new
non-constant-time `bn_mont_modexp_pub` was proven unreachable
from any secret exponent across all six modexp call sites).
**F2 LOW:** `authenticode_pe_hash`'s 144-byte SHA-256
context leaked on every call (`sha256_init()` is `fl_alloc(144)`
and was never `fl_free`d) and is now a banked `cbank()` lane via
`sha256_init_into` — allocator-free and race-free. The
optional-header magic became an allow-list (`0x10B` / `0x20B`);
previously anything other than `0x10B` was treated as PE32+.
`NumberOfRvaAndSizes >= 5` is now required (an image with fewer
data directories previously had its section-header bytes read as
a security directory), as is `e_lfanew >= 0x40`. The certificate
table must now be 8-byte aligned, inside the file, not
overlapping the hashed headers, and the file trailer; and the
`WIN_CERTIFICATE` must have rev `0x0200`, type `0x0002`, and a
single entry that fills the table (no un-inspected trailing
entries).

## Threat model assumptions

- TEE quote / report bytes are fully attacker-controlled (they
  travel from an untrusted remote host via the attestation flow).
  Every length field, offset, and embedded structure is validated
  before any dereference.
- X.509 / PEM parsers operate against attacker-controlled DER
  and base64 input; bounds-check every TLV walk and every base64
  decode write.
- PE / EFI images submitted for Authenticode hashing or
  verification are attacker-controlled. Every header offset
  (`e_lfanew`, the optional-header magic, `NumberOfRvaAndSizes`,
  the security data directory) is validated before use, and the
  certificate table must be aligned, in-bounds, disjoint from
  the hashed headers, and the file trailer.
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

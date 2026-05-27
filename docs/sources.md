# Sigil Sources

External specification citations for every cryptographic
primitive sigil implements. Sigil is a domain crate (crypto +
trust), so per the agnosticos first-party-standards a
consolidated source index is required: a reviewer unfamiliar
with the domain should be able to trace any algorithm back to
its origin.

This file is the single index. Per-module headers also cite
their specs inline; this file is the cross-module overview.

## Symmetric primitives

### SHA-256 / SHA-384 / SHA-512 — `src/sha256.cyr`, `src/sha384.cyr`, `src/sha512.cyr`

- **FIPS 180-4** — Secure Hash Standard (NIST, 2015-08).
  Defines SHA-1, SHA-256, SHA-384, SHA-512, SHA-512/224,
  SHA-512/256.
  - https://csrc.nist.gov/publications/detail/fips/180/4/final
- **NIST CAVP test vectors** — used for the `tests/tcyr/sha256.tcyr`,
  `sha384.tcyr`, `sha512.tcyr` known-answer vectors.
  - https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing

### SHA-NI hardware dispatch — `src/sha_ni.cyr`

- **Intel SHA Extensions Whitepaper** (2013-07).
  - Defines `SHA256RNDS2`, `SHA256MSG1`, `SHA256MSG2` semantics.
  - https://www.intel.com/content/dam/develop/external/us/en/documents/intel-sha-extensions-white-paper-402097.pdf
- **CPUID Leaf 7 EBX bit 29** — `SHA` feature flag (runtime
  probe in `_sha_ni_cpuid_probe`).

### HMAC-SHA256 — `src/hmac.cyr`

- **RFC 2104** — HMAC: Keyed-Hashing for Message Authentication
  (1997-02).
  - https://www.rfc-editor.org/rfc/rfc2104.txt
- **FIPS 198-1** — The Keyed-Hash Message Authentication Code
  (NIST, 2008-07; reaffirms RFC 2104 with formal validation
  requirements).
  - https://csrc.nist.gov/publications/detail/fips/198/1/final

### HKDF-SHA256 — `src/hkdf.cyr`

- **RFC 5869** — HMAC-based Extract-and-Expand Key Derivation
  Function (HKDF) (2010-05).
  - https://www.rfc-editor.org/rfc/rfc5869.txt
- **NIST SP 800-56C Rev. 2** — Recommendation for Key-Derivation
  Methods in Key-Establishment Schemes (2020-08). Validates
  HKDF for FIPS-mode key derivation.
  - https://csrc.nist.gov/publications/detail/sp/800-56c/rev-2/final

### AES-256-GCM — `src/aes_gcm.cyr`

- **FIPS 197** — Advanced Encryption Standard (AES) (NIST,
  2001-11; updated 2023-05).
  - https://csrc.nist.gov/publications/detail/fips/197/final
- **NIST SP 800-38D** — Recommendation for Block Cipher Modes
  of Operation: Galois/Counter Mode (GCM) and GMAC (2007-11).
  - https://csrc.nist.gov/publications/detail/sp/800-38d/final
- **NIST CAVP GCMVS** — test vector format for AES-GCM
  validation.
  - https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes

### AES-NI hardware dispatch — `src/aes_ni.cyr`

- **Intel Advanced Encryption Standard New Instructions
  (AES-NI) Whitepaper** (2010-05).
  - https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
- **CPUID Leaf 1 ECX bit 25** — `AESNI` feature flag.

### Poly1305 one-time MAC — `src/poly1305.cyr`

- **RFC 8439** — ChaCha20 and Poly1305 for IETF Protocols
  (2018-06). §2.5 defines the MAC; §2.5.2 is the worked example;
  Appendix A.3 carries the test vectors.
  - https://www.rfc-editor.org/rfc/rfc8439
- **D. J. Bernstein — "The Poly1305-AES message-authentication
  code"** (FSE 2005): the original construction and the
  one-time-key security argument.
  - https://cr.yp.to/mac/poly1305-20050329.pdf
- **poly1305-donna** (public-domain reference): the 26-bit-limb
  decomposition this implementation follows.
  - https://github.com/floodyberry/poly1305-donna

## Asymmetric primitives

### Ed25519 — `src/ed25519.cyr` (with `src/bigint_ext.cyr` for field arithmetic)

- **RFC 8032** — Edwards-Curve Digital Signature Algorithm
  (EdDSA) (2017-01).
  - https://www.rfc-editor.org/rfc/rfc8032.txt
- **Bernstein, Lange et al. — "High-speed high-security
  signatures"** (CHES 2011). Original Ed25519 paper.
  - https://ed25519.cr.yp.to/ed25519-20110926.pdf
- Constant-time scalar multiplication via fixed-base comb.

### ECDSA P-256 — `src/ecdsa_p256.cyr`

- **FIPS 186-4** — Digital Signature Standard (DSS) (NIST,
  2013-07). Defines ECDSA and the P-256 / P-384 curves.
  - https://csrc.nist.gov/publications/detail/fips/186/4/final
- **NIST SP 800-186** — Recommendations for Discrete-Logarithm
  Based Cryptography (2023-02). Updated curve parameters and
  validation requirements.
  - https://csrc.nist.gov/publications/detail/sp/800-186/final
- **SEC 1 v2** — Elliptic Curve Cryptography (Certicom Research,
  2009-05). Defines secp256r1 == NIST P-256 and the
  uncompressed point format used in X.509 SPKI.
  - https://www.secg.org/sec1-v2.pdf

### ECDSA P-384 — `src/ecdsa_p384.cyr`

- **FIPS 186-4** (as above).
- **SEC 1 v2** — secp384r1 == NIST P-384.
- **NIST SP 800-186** Appendix D — Solinas decomposition for
  P-384 modular reduction (planned for v3.6 cycle).

### ML-DSA-65 — `src/mldsa*.cyr` (opt-in via `-D SIGIL_PQC`)

- **FIPS 204** — Module-Lattice-Based Digital Signature
  Standard (NIST, 2024-08).
  - https://csrc.nist.gov/publications/detail/fips/204/final
- **CRYSTALS-Dilithium specification** (the algorithm submitted
  to the NIST PQC competition; ML-DSA is FIPS 204's
  standardised form).
  - https://pq-crystals.org/dilithium/

## TEE attestation

### X.509 cert parser + chain walker — `src/x509.cyr`

- **RFC 5280** — Internet X.509 PKI Certificate and CRL Profile
  (2008-05).
  - https://www.rfc-editor.org/rfc/rfc5280.txt
- **ITU-T X.690** — ASN.1 BER / DER encoding rules (2021-02).
  - https://www.itu.int/rec/T-REC-X.690
- **RFC 5758** — Additional Algorithms and Identifiers for DSA
  and ECDSA (2010-01). Defines ecdsa-with-SHA256 OID.
  - https://www.rfc-editor.org/rfc/rfc5758.txt
- Scope cuts deliberately taken (see ADR pending): ECDSA-SHA256
  only chain-link signatures; P-256 and P-384 SPKIs; no policy
  mapping; no name constraints; no CRL fetching; no RSA.

### PEM decoder — `src/pem.cyr`

- **RFC 4648 §4** — base64 encoding (the standard alphabet,
  not URL-safe).
  - https://www.rfc-editor.org/rfc/rfc4648.txt
- **RFC 7468** — Textual Encodings of PKIX, PKCS, and CMS
  Structures. Defines the `-----BEGIN CERTIFICATE-----` /
  `-----END CERTIFICATE-----` block format sigil decodes.
  - https://www.rfc-editor.org/rfc/rfc7468.txt

### Intel SGX DCAP v3 quote — `src/sgx.cyr`

- **Intel SGX TEE Quote Reference Specification (DCAP v3)** —
  the canonical wire format for the quote header, enclave
  report body, and signature section.
- **Intel Software Guard Extensions Data Center Attestation
  Primitives (DCAP) Quote Verification Library Specification.**
- **Intel SGX ECDSA Quote Generation Specification** — the
  PCK chain shape, QE report binding hash, AK signature
  structure.

### Intel TDX v4 TD-quote — `src/tdx.cyr`

- **Intel Trust Domain Extensions (TDX) Module Specification
  v1.0 and v1.5** — TDX 1.0 corresponds to att_key_type=2
  (P-256), TDX 1.5+ corresponds to att_key_type=3 (P-384).
- **Intel TDX Quoting Library Specification** — the TD_QUOTE_BODY
  layout (584 bytes, MRTD / MRSEAM / RTMR0..3 / report_data).

### AMD SEV-SNP attestation report — `src/sev_snp.cyr`

- **AMD SEV Secure Nested Paging Firmware ABI Specification
  (Publication 56860)** — defines the 1184-byte attestation
  report structure, signature encoding (LE-padded r/s in 72-byte
  slots), and VCEK chain shape.
  - https://www.amd.com/system/files/TechDocs/56860.pdf

### SGX sealing — `src/seal.cyr`

- **Intel SGX SDK — Data Sealing**: HKDF-bound key derivation
  from EGETKEY-sourced sealing root + policy + measurement +
  ISVSVN + key_id. The EGETKEY instruction is enclave-only;
  sigil's seal surface receives the sealing root from the
  caller's enclave-side bridge (Gramine, Occlum, TDX TDG_MR_REPORT).

## Constant-time comparison

- **lib/ct.cyr** (Cyrius stdlib) — `ct_eq_bytes` /
  `ct_eq_bytes_lens` use bitwise-OR accumulation with no
  early exit. Migrated from sigil's own `src/ct.cyr` at the
  3.0.2 cycle.
- **Reference**: Daniel J. Bernstein, "Cache-timing attacks on
  AES" (2005).
  - https://cr.yp.to/antiforgery/cachetiming-20050414.pdf

## Cryptographic RNG

- **`/dev/urandom`** with short-read validation, used in
  `tpm_random` (`src/tpm.cyr`) and `generate_keypair`
  (`src/trust.cyr`).
- **NIST SP 800-90A Rev. 1** — Recommendation for Random Number
  Generation Using Deterministic Random Bit Generators
  (2015-06). Reference standard; sigil delegates the actual
  bit-source to the Linux kernel's CRNG which validates against
  this spec.
  - https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final

## Threat-model / industry context

- **NSA Commercial National Security Algorithm Suite 2.0 (CNSA
  2.0)** — informs the PQC migration timeline that motivates
  ML-DSA-65's inclusion in sigil.
  - https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
- **CVE database (general)** — every audit pass cross-checks
  sigil's primitives against CVE patterns for that algorithm
  family. See `docs/audit/YYYY-MM-DD-*.md` for per-cycle CVE
  review notes.

## Process references

- **agnosticos first-party-standards** — sigil's domain-crate
  requirements (audit cadence, source citation, perf
  benchmarks).
  - https://github.com/MacCracken/agnosticos/blob/main/docs/development/planning/first-party-standards.md
- **agnosticos first-party-documentation** — doc-tree
  conventions sigil follows.
  - https://github.com/MacCracken/agnosticos/blob/main/docs/development/planning/first-party-documentation.md

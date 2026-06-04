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

### HMAC-SHA384 — `src/hmac_sha384.cyr`

- **RFC 2104** / **FIPS 198-1** — same HMAC construction as
  SHA-256, over SHA-384's **128-byte** block / **48-byte** digest.
- **RFC 4231** — Identifiers and Test Vectors for HMAC-SHA-224,
  HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 (2005-12). §4 Test
  Cases 1–7 are sigil's regression vectors (`tests/tcyr/
  hkdf_sha384.tcyr`; TC5 truncation omitted — sigil emits the full
  48-byte tag).
  - https://www.rfc-editor.org/rfc/rfc4231.txt

### HKDF-SHA256 — `src/hkdf.cyr`

- **RFC 5869** — HMAC-based Extract-and-Expand Key Derivation
  Function (HKDF) (2010-05).
  - https://www.rfc-editor.org/rfc/rfc5869.txt
- **NIST SP 800-56C Rev. 2** — Recommendation for Key-Derivation
  Methods in Key-Establishment Schemes (2020-08). Validates
  HKDF for FIPS-mode key derivation.
  - https://csrc.nist.gov/publications/detail/sp/800-56c/rev-2/final

### HKDF-SHA384 — `src/hkdf_sha384.cyr`

- **RFC 5869** — same HKDF extract/expand construction over
  HMAC-SHA384 (HashLen = 48, max OKM = 255×48 = 12240 bytes).
- **RFC 8446 §7.1** — TLS 1.3 key schedule; the
  `TLS_AES_256_GCM_SHA384` (0x1302) ciphersuite drives its key
  schedule off HKDF-SHA384. This is the consumer (cyrius native
  TLS arc) that motivated the 3.5.6 addition.
  - https://www.rfc-editor.org/rfc/rfc8446.txt#section-7.1
- **RFC 8448 §4** — published byte-for-byte TLS 1.3 handshake using
  `TLS_AES_256_GCM_SHA384`; cyrius verifies its key schedule
  against it. Sigil's own HKDF-SHA384 vectors were cross-verified
  against Python `hmac`/`hashlib` and `openssl kdf`.
  - https://www.rfc-editor.org/rfc/rfc8448.txt#section-4

### TLS 1.2 PRF — `src/tls12_prf.cyr`

- **RFC 5246 §5** — The Transport Layer Security (TLS) Protocol
  Version 1.2 (2008-08). Defines `PRF(secret, label, seed) =
  P_<hash>(secret, label || seed)` and `P_hash`; TLS 1.2 uses the
  cipher-suite's negotiated hash (default SHA-256; SHA-384 for the
  `*_SHA384` suites).
  - https://www.rfc-editor.org/rfc/rfc5246.txt#section-5
- **RFC 5288 / RFC 5289** — the AES-GCM / SHA-384 cipher suites that
  select `P_SHA384` for the TLS 1.2 key schedule.
- **Test vectors** — the canonical 2009 IETF TLS WG "Test vectors for
  TLS 1.2 PRF" pair (P_SHA256 + P_SHA384), also used by mbedTLS /
  wolfSSL. Reproduced with a stdlib-only Python `hmac`/`hashlib`
  reference before embedding; the SHA-256 output matched the
  published vector byte-for-byte (the validation anchor for the
  SHA-384 emission).

### RSA PKCS#1 v1.5 verify + sign + key parsing — `src/rsa.cyr`, `src/bignum.cyr`

- **RFC 8017** — PKCS #1: RSA Cryptography Specifications Version 2.2
  (2016-11). §8.2.2 RSASSA-PKCS1-v1_5 verification, §8.2.1 signing,
  §9.2 EMSA-PKCS1-v1_5 encoding (incl. the DigestInfo prefixes),
  §5.2.1/§5.2.2 RSAVP1/RSASP1, §A.1.1/§A.1.2 the `RSAPublicKey` /
  `RSAPrivateKey` ASN.1 (parsed by `rsa_pubkey_from_der` /
  `rsa_privkey_from_der`, also accepting X.509 SPKI / PKCS#8).
  - https://www.rfc-editor.org/rfc/rfc8017.txt
- **Constant-time signing** — the secret-exponent modexp uses a
  Montgomery (CIOS) square-and-multiply-always ladder
  (`bn_mont_modexp`); cf. Koç, Acar, Kaliski, "Analyzing and Comparing
  Montgomery Multiplication Algorithms" (1996). A **verify-after-sign**
  step (recompute `s^e mod n`) is the Boneh–DeMillo–Lipton ("Bellcore")
  fault-attack guard. **Base blinding** (`s=(m·r^e)^d·r^-1 mod n`,
  random `r`; defends DPA / timing-correlation) and **CRT** (Garner
  recombination, ~4×) shipped in 3.6.4; the modular inverse for `r^-1`
  uses binary inversion (`bn_modinv`).
- **Verify hygiene** — sigil reconstructs the full expected `EM` and
  compares all octets (rather than parsing/skipping), the recommended
  defense against the PKCS#1 v1.5 forgery class (Bleichenbacher 2006 /
  "BERserk": low-exponent forgeries exploiting lax verifiers).
- **Test vectors** — a real RSA-2048 key + SHA-256/SHA-384 PKCS#1 v1.5
  signatures, generated with a pure-Python RSA (seeded keygen + manual
  EMSA-PKCS1-v1_5 encode), each self-checked `pow(s,e,n) == EM`; the
  `bn_modexp` engine is cross-checked against Python `pow(b,e,m)` up to
  RSA-2048 width. (No external crypto lib used.)

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

### ChaCha20 stream cipher — `src/chacha20.cyr`

- **RFC 8439** — ChaCha20 and Poly1305 for IETF Protocols
  (2018-06). §2.1 quarter round, §2.3 block function, §2.3.2 /
  §2.4.2 test vectors.
  - https://www.rfc-editor.org/rfc/rfc8439
- **D. J. Bernstein — "ChaCha, a variant of Salsa20"** (2008): the
  original cipher.
  - https://cr.yp.to/chacha/chacha-20080128.pdf

### ChaCha20-Poly1305 AEAD — `src/chacha20poly1305.cyr`

- **RFC 8439** §2.8 — the IETF AEAD construction (one-time-key
  derivation, mac-data layout); §2.8.2 test vector.
  - https://www.rfc-editor.org/rfc/rfc8439
- TLS 1.3 ciphersuite `TLS_CHACHA20_POLY1305_SHA256` (RFC 8446
  §B.4).

## Asymmetric primitives

### X25519 key agreement — `src/x25519.cyr` (with `src/bigint_ext.cyr` for field arithmetic)

- **RFC 7748** — Elliptic Curves for Security (2016-01). §5 the
  Montgomery ladder + scalar clamp; §5.2 / §6.1 test vectors.
  - https://www.rfc-editor.org/rfc/rfc7748
- **D. J. Bernstein — "Curve25519: new Diffie-Hellman speed
  records"** (PKC 2006). The original X25519 design.
  - https://cr.yp.to/ecdh/curve25519-20060209.pdf
- Constant-time Montgomery ladder with masked `cswap`.

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
- Scope cuts deliberately taken: ECDSA-SHA256-only chain-link
  signatures; P-256 and P-384 SPKIs; no policy mapping; no name
  constraints; no CRL fetching. RSA chain-link verify is not wired
  into `x509.cyr` yet (backlog) — though sigil does have standalone
  RSA PKCS#1 v1.5 verify in `rsa.cyr` (3.6.2).

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

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

(none — tip is 3.6.6.)

## [3.6.6] — 2026-06-04

Verify-path **Montgomery** exponentiation (the public modexp), RSA
benchmarks, and `pem_decode_privkey` now emits the parsed **RSAK
struct** directly. No new primitives — a perf + ergonomics bite on the
RSA surface. Cut after a 24-agent adversarial review whose one confirmed
finding (an unenforced odd-modulus precondition) was fixed in-cycle.

### Added

- **RSA benchmarks** (`tests/bcyr/rsa.bcyr`, new — kept separate from
  `sigil.bcyr` to stay under the 1 MB preprocessor cap that mldsa
  already pushes). `benches/history.csv` rows `v3.6.6-rsa-montgomery`:
  verify 3.385 ms; sign (CRT) 74.82 ms; plus the schoolbook/Montgomery
  and full-width/CRT comparison rows.
- **Tests** — `rsa.tcyr` +1 (even-modulus reject), `privkey.tcyr` +4
  (PEM RSA → RSAK struct, modulus matches). Suite **51 files / 1369
  assertions**, 0 failures.

### Changed

- **Montgomery on the public-exponent modexp** (`src/rsa.cyr`) — the
  three public-exponent sites switched `bn_modexp` → `bn_mont_modexp`:
  `_rsa_recover_em` (RSAVP1 verify), and the `r^e` blinding + `s^e`
  verify-after-sign in `_rsa_raw_sign`. **Verify modexp 11.680 ms →
  3.401 ms (3.43×)**; operands are public, so this is a pure speed win
  (no change to the constant-time posture). `bn_modexp` stays as a
  tested general primitive. Signatures unchanged (still match the
  external byte-for-byte KATs).
- **`pem_decode_privkey` emits the RSAK struct** (`src/privkey.cyr`) —
  for RSA, when `key_max >= RSAK_SIZE` (2384) it base64-decodes + calls
  `rsa_privkey_from_der` into `key_out` and returns `RSAK_SIZE`; the
  `0-SIG_PRIVKEY_RSA` sentinel is now only the buffer-too-small signal.
  One auto-detecting entry point now loads any supported key type
  (EC/Ed25519 → scalar, RSA → struct). EC/Ed25519 contract unchanged.

### Security

- 3.6.6 audit: `docs/audit/2026-06-04-3.6.6-montgomery-pem-rsak-audit.md`.
  0 outstanding (CRITICAL/HIGH/MEDIUM/LOW). The adversarial review's one
  confirmed LOW — `_rsa_recover_em` fed `bn_mont_modexp` (odd-modulus
  precondition) an attacker-controlled modulus with no oddness check —
  was **fixed in this release**: an even/zero modulus is now rejected at
  the verify boundary before the Montgomery ladder (defense-in-depth; the
  EM compare already rejected it, so not exploitable). Audit floor
  unchanged at 8 LOW.

## [3.6.5] — 2026-06-04

RSASSA-**PSS** (the modern TLS 1.3 RSA signature scheme) and **x509 RSA
chain-link verification**, both on the existing bignum/RSA engine. Plus
a debt-clearing pass: the overdue **3.5.6 audit doc** is written, and
several deferrals that prior cycles had buried in source comments are
**surfaced into the roadmap** (none were tracked anywhere a planning doc
would catch them). Toolchain pin 6.0.53 → 6.0.58.

### Added

- **RSA-PSS** (`src/rsa.cyr`, RFC 8017 §8.1/§9.1) —
  `rsa_pss_verify_sha256` / `_sha384` and `rsa_pss_sign_sha256` /
  `_sha384`. MGF1 with the matching hash; sign uses a fresh
  `/dev/urandom` salt of length hLen (the TLS 1.3 `rsa_pss_rsae_*`
  convention); verify is salt-length-agnostic (EMSA-PSS-Verify recovers
  the salt, like OpenSSL `SALTLEN_AUTO`). Two cores were extracted so
  PSS reuses the audited v1.5 logic: `_rsa_recover_em` (RSAVP1) and
  `_rsa_raw_sign` (RSASP1 with base blinding + CRT + verify-after-sign).
- **x509 RSA chain-link verify** (`src/x509.cyr`) — `x509_parse` now
  recognises rsaEncryption SubjectPublicKeyInfo (new key-type
  `X509_CURVE_RSA`; the (n, e) live in a 544-byte side block referenced
  from the cert) and the `sha256WithRSAEncryption` /
  `sha384WithRSAEncryption` signature algorithms (`X509_SIG_RSA_SHA256`
  / `_SHA384`). `_x509_verify_link` dispatches RSA issuers to
  `rsa_pkcs1v15_verify_sha256/384`; inner/outer signature algorithms
  must match (RFC 5280 §4.1.1.2). Unblocks real AMD ARK/ASK chains
  (RSA-4096 + SHA-384). ECDSA-P256 chain-link path unchanged.
- **Tests** — `rsa.tcyr` +10 (external pure-Python PSS KAT verify for
  SHA-256/384, sign→verify roundtrips, and tamper / wrong-message /
  wrong-length / cross-hash / cross-scheme rejects). `x509_rsa.tcyr`
  +20 (new; OpenSSL-generated RSA-2048 CA signing SHA-256 and SHA-384
  leaves, green path + tamper / wrong-issuer-key / DN-mismatch rejects).
  Suite **51 files / 1364 assertions**, 0 failures.

### Fixed

- **Overdue 3.5.6 audit doc written** —
  `docs/audit/2026-06-04-3.5.6-hmac-hkdf-sha384-audit.md`. 3.5.6
  (HMAC-/HKDF-SHA384) had shipped with KAT tests but no per-bite
  security audit (the only 3.5.x/3.6.x bite missing one — a CLAUDE.md §
  Security violation that had been parked inside the roadmap's
  "closeout" line). Retrospective audit: 0 findings.
- **Buried deferrals surfaced** — three scope cuts that prior cycles
  hid in source comments are now tracked in the roadmap backlog:
  AES-GCM arbitrary-length IVs (`aes_gcm.cyr`), AES-128 seal keys
  (`seal.cyr`), and the stale "`_into` API lands in 3.6" promise in
  `sgx.cyr`/`tdx.cyr` (the work is v3.7). No behaviour change; honesty
  fix.

### Security

- 3.6.5 audit: `docs/audit/2026-06-04-3.6.5-pss-x509-rsa-audit.md`. 0
  CRITICAL/HIGH/MEDIUM; 1 LOW (the RSA SPKI side block is a per-parse
  bump `alloc`, same shape as the existing 3.2.2 LOW-1 — folds into the
  v3.7 `_into` cleanup, bringing the audit floor to 8 LOW). PSS verify
  is fully public (no CT requirement); PSS sign inherits the
  constant-time ladder + blinding + Bellcore guard from `_rsa_raw_sign`.

### Changed

- Cyrius toolchain pin **6.0.53 → 6.0.58** (`cyrius.cyml`).

## [3.6.4] — 2026-06-03

RSA sign-path hardening — **base blinding** + **CRT** — and a
consolidated **security audit pass** over the whole RSA surface. The
3.6.3 signer was already constant-time in the exponent and
fault-checked; this resolves the 3.6.3 LOW-1 (blinding) and adds the
~4× CRT speed-up. Signatures are unchanged (deterministic v1.5), so
they still match the external reference byte-for-byte.

### Added

- **Base blinding** (`src/rsa.cyr`) — `s = (m·r^e)^d·r^-1 mod n` with a
  fresh `/dev/urandom` factor `r` per signature, decorrelating the
  secret-exponent modexp's timing/power from the key. Fails closed if
  entropy is unavailable.
- **CRT signing** (`src/rsa.cyr`) — Garner recombination (sign mod p
  and mod q with the constant-time Montgomery ladder, then combine);
  ~4× over the full-width modexp. The existing verify-after-sign
  (Bellcore) guard covers the CRT fault surface; a full-width fallback
  remains for keys without CRT parameters.
- **`bn_modinv`** (`src/bignum.cyr`) — modular inverse via binary
  inversion (odd modulus), plus `bn_add_assign` / `bn_shr1` /
  `bn_is_one`. Used for the blinding factor's inverse and CRT recombine.
  Non-constant-time (only ever applied to the ephemeral random `r`).
- **Tests** — `tests/tcyr/bignum.tcyr` (+5: `bn_modinv` self-check
  `r·r^-1 ≡ 1 mod n` at 256/2048-bit + the non-coprime `-1` path).
  `rsa.tcyr` signing now exercises the blinded + CRT path (still
  matching the Python reference). Suite 50 files / 1334 assertions.

### Security

- Consolidated audit `docs/audit/2026-06-03-3.6.4-rsa-hardening-audit.md`
  over the full RSA surface (verify + keys + sign): secret-exponent
  modexps are CT Montgomery ladders, now blinded; verify-after-sign
  guards the CRT fault surface; `bn_modinv` non-CT only on the
  ephemeral `r`. **3.6.3 LOW-1 (base blinding) resolved.** A real bug
  was caught and fixed: `bn_modinv` looped forever on non-coprime input
  (`u→0`) — now guarded to return -1. 0 CRITICAL / HIGH / MEDIUM / LOW.

### Changed

- **Dist regenerated** — `dist/sigil.cyr` picks up the hardened signer
  + `bn_modinv`; `cyrius doc --check` 0 undocumented.

## [3.6.3] — 2026-06-03

RSA key parsing + PKCS#1 v1.5 **signing**. Second RSA bite of the
cyrius native-TLS arc. The sign-path **hardening (CRT + base blinding)
and a dedicated security audit pass are 3.6.4** — what ships here is a
correct, constant-time-in-the-exponent, fault-checked signer.

### Added

- **`rsa_pubkey_from_der`** (`src/rsa.cyr`) — parse an RSA public key
  from a bare PKCS#1 `RSAPublicKey` or an X.509 SubjectPublicKeyInfo
  (rsaEncryption). RSA verify now works straight off a cert/TLS key.
- **`rsa_privkey_from_der`** (`src/rsa.cyr`) — parse PKCS#1
  `RSAPrivateKey` (RFC 8017 §A.1.2) or PKCS#8 into an `RSAK` struct
  (n, e, d, p, q, dp, dq, qinv). Both parsers reuse the audited
  `der_walk` from `src/x509.cyr`.
- **`bn_mont_modexp`** (`src/bignum.cyr`) — constant-time Montgomery
  (CIOS) modular exponentiation for the secret exponent: square-and-
  multiply-always over a fixed bit width with a constant-time select,
  so timing/control-flow don't depend on the exponent bits. Odd
  modulus required (RSA n/p/q). KAT-validated equal to the schoolbook
  `bn_modexp` at 256-bit and 2048-bit.
- **`rsa_pkcs1v15_sign_sha256` / `_sha384`** (`src/rsa.cyr`) —
  RSASSA-PKCS1-v1.5 (RFC 8017 §8.2.1): `s = m^d mod n` via the CT
  ladder, with **verify-after-sign** (recompute `s^e mod n`, refuse to
  emit unless it equals `m` — the Bellcore fault guard). The
  EMSA-PKCS1-v1.5 encoder is now shared with verify.
- **Tests** — `tests/tcyr/rsa.tcyr` (+21: pubkey/privkey DER parse incl.
  `p·q == n`, deterministic sign matching an independent Python RSA
  reference byte-for-byte for SHA-256/384, sign→verify roundtrips) and
  `tests/tcyr/bignum.tcyr` (+3: Montgomery == schoolbook). Suite now 50
  files / 1329 assertions.

### Security

- Per-bite audit `docs/audit/2026-06-03-3.6.3-rsa-keys-sign-audit.md`:
  constant-time secret-exponent modexp; verify-after-sign; bounds-safe
  DER parsing (reused audited walker; magnitude over-length rejected);
  signatures match an external reference. **LOW-1: base blinding
  deferred to 3.6.4** (the signer is CT-in-exponent and fault-checked;
  blinding adds DPA/timing-correlation defense). 0 CRITICAL / HIGH /
  MEDIUM.

### Changed

- **Dist regenerated** — `dist/sigil.cyr` picks up the new RSA + bignum
  surface; `cyrius doc --check` 0 undocumented.
- `src/privkey.cyr` comments refreshed: the RSA DER parser referenced
  as "arrives in 3.5.10" is now `rsa_privkey_from_der` (3.6.3);
  `pem_decode_privkey` still returns the `SIG_PRIVKEY_RSA` sentinel
  (full RSAK-struct integration is a later follow-up).

## [3.6.2] — 2026-06-03

RSA PKCS#1 v1.5 signature **verification** (RFC 8017) — the
load-bearing interop path of the cyrius native-TLS arc's RSA item —
plus the general big-integer / modexp engine it required. Verify only;
RSA key DER parsing, PSS, and signing are subsequent 3.6.x bites.

### Added

- **`src/bignum.cyr`** — general variable-width big integers
  (little-endian i64 limbs, byte-buffer backed): `bn_from_be`/`bn_to_be`,
  `bn_cmp`/`bn_sub_assign`/`bn_shl1`/`bn_bitlen`, schoolbook `bn_mul`
  (reusing stdlib `_mul64`), binary long-division `bn_mod`, and
  left-to-right square-and-multiply `bn_modexp`. sigil's first
  arbitrary-width modular arithmetic (`lib/bigint.cyr` is fixed u256;
  `bigint_ext` is Curve25519-only). **Public-exponent / verify use
  only** — not constant-time, must not be reused for secret exponents
  (sign) without blinding + a CT ladder. Single-threaded (not on the
  batch path), so unbanked.
- **`src/rsa.cyr`** — `rsa_pkcs1v15_verify_sha256` /
  `rsa_pkcs1v15_verify_sha384` (RFC 8017 §8.2.2 / §9.2). Recovers
  `m = s^e mod n` via `bn_modexp`, then **reconstructs the full
  expected** `EM = 00 01 PS 00 DigestInfo H` and compares all `k`
  octets — the robust shape that rejects the PKCS#1 v1.5 forgery class
  (Bleichenbacher'06 / BERserk: garbage-after-hash, short `PS`,
  algorithm substitution). Range-checks `s < n`, exact signature
  length, and the 8-octet minimum `PS`.
- **Tests** — `tests/tcyr/bignum.tcyr` (+6: modexp KATs incl. a full
  RSA-2048-size `s^65537 mod n`, all cross-checked vs Python `pow`;
  serialize round-trip; `base^0`/`0^e` edges) and `tests/tcyr/rsa.tcyr`
  (+6: a real RSA-2048 key with valid SHA-256 / SHA-384 signatures
  accepted, and tamper / wrong-message / wrong-length / hash-mismatch
  all rejected). Suite now 50 files / 1305 assertions.

### Security

- Per-bite audit `docs/audit/2026-06-03-3.6.2-rsa-verify-audit.md`:
  verify operates only on public data (no CT/zeroization obligation);
  full-EM reconstruction defeats the RSA-verify forgery family;
  buffer bounds for RSA ≤ 4096. 0 CRITICAL / HIGH / MEDIUM / LOW.

### Changed

- **Dist regenerated** — `dist/sigil.cyr` now includes
  `src/bignum.cyr` + `src/rsa.cyr`; `cyrius doc --check` 0 undocumented.

## [3.6.1] — 2026-06-03

TLS 1.2 PRF (RFC 5246 §5) for the cyrius native-TLS arc, plus a
toolchain pin bump to cyrius 6.0.53.

### Added

- **`src/tls12_prf.cyr`** — `tls12_prf_sha256` / `tls12_prf_sha384`
  (RFC 5246 §5): `PRF(secret, label, seed) = P_hash(secret, label ||
  seed)` with `A(i) = HMAC(secret, A(i-1))`. Default `P_SHA256` plus
  the `P_SHA384` variant for the SHA-384 suites. Built on the existing
  `hmac_sha256` / `hmac_sha384`; no new hashing primitive. Arbitrary
  output length; `label || seed` capped at 256 bytes (over-cap returns
  0, no truncation). This resolves the "ship-or-decline" TLS 1.2 PRF
  item (cyrius native-TLS arc line item 5) on the **ship** side —
  cyrius can drop its inline PRF and call sigil's.
- **Tests** (`tests/tcyr/tls12_prf.tcyr`, +9 assertions) — the
  canonical IETF TLS 1.2 PRF vectors (P_SHA256 100-byte, P_SHA384
  148-byte), reproduced with a stdlib-only Python `hmac`/`hashlib`
  reference before embedding (SHA-256 matched the published vector
  byte-for-byte); plus truncation prefixes, determinism, and the
  over-cap guard. Suite now 48 files / 1293 assertions.

### Changed

- **Toolchain pin** cyrius 6.0.52 → **6.0.53**. `lib/` snapshot
  re-synced. Deps unchanged (agnosys 1.3.2, sakshi 2.2.6 — both
  already latest).
- **Dist regenerated** — `dist/sigil.cyr` now includes
  `src/tls12_prf.cyr`; `cyrius doc --check` 0 undocumented.

### Security

- Per-bite audit `docs/audit/2026-06-03-3.6.1-tls12-prf-audit.md`:
  buffer bounds (the 256-byte `label||seed` guard precedes both
  `memcpy`s — no OOB), `secret var` zeroization of the derived
  key stream, no secret-dependent control flow. 0 CRITICAL / HIGH /
  MEDIUM / LOW.

## [3.6.0] — 2026-06-03

Parallel batch verify — `sv_verify_batch` drops `_sigil_batch_mutex`
and runs the crypto truly concurrently across worker threads.
**3.42× speedup** at 64 artifacts / 4 workers (422.867 ms → 123.563 ms
vs the `v3.2.0-allocfree` baseline). Also a maintenance bump:
toolchain to cyrius 6.0.52, agnosys 1.3.2, sakshi 2.2.6.

The batch path was parallel since 3.0 but serialised every artifact
behind a mutex, because the crypto primitives' transient working
arrays are static function-scope globals (CLAUDE.md quirk #1), not
stack-locals, and so raced across workers. cyrius 6.0.52 shipped
thread-local storage (`lib/thread_local.cyr`), which unblocks giving
each worker its own private *bank* of every such array — dropping the
mutex with no signature churn.

### Added

- **`src/crypto_scratch.cyr`** — per-thread crypto-scratch bank
  selection over cyrius 6.0.52 TLS. `crypto_bank_set(bank)` assigns a
  worker its lane; `cbank()` returns it (0 on the main/serial path,
  self-installing the main TLS block as a backstop);
  `crypto_tls_main_init()` pre-warms the main thread. `SIGIL_CRYPTO_BANKS
  = 8` lanes (bank 0 = main, 1..workers = batch). Each racing
  `var X[N]` is widened to `[N*8]` and sliced by `cbank()*N`, so
  concurrent workers touch disjoint memory — no offset map, collisions
  impossible by construction.

### Changed

- **Mutex dropped from `sv_verify_batch` / `_batch_worker`** (`src/verify.cyr`).
  Workers are assigned banks 1..workers and the main thread pre-warms
  crypto inits + its TLS block before fan-out (clamped so the bank
  index can never exceed the scratch width).
- **Per-thread banking** of every transient working array on the
  verify call path: `sha256`/`sha512` message schedules, the SHA-NI
  block scratch (`src/sha_ni.cyr`), the Ed25519 field/group/verify
  temporaries (`src/ed25519.cyr`), the `fp_*` / `u512_mod_p` scratch
  (`src/bigint_ext.cyr`, incl. `fp_inv`'s addition chain), and the
  `hash_file_into` file-read buffer + digest (`src/trust.cyr`).
- **`ge_identity` is now alloc-free** — it built `0`/`1` via
  `u256_from` (each `alloc(32)`), which would race on the non-thread-
  safe bump allocator once the mutex is gone. Rewritten as
  `memset` + two stores (also faster).
- **Toolchain pin** cyrius 6.0.14 → **6.0.52**; deps **agnosys 1.2.7 →
  1.3.2**, **sakshi 2.2.5 → 2.2.6**. `lib/` snapshot re-synced.
- **Dist regenerated** — `dist/sigil.cyr` rebuilt (now includes
  `src/crypto_scratch.cyr`).

### Performance

- `sv_verify_batch_64`: **123.563 ms** (was 422.867 ms) — **3.42×** at
  4 workers. `batch_4` 3.50×, `batch_16` 3.39×. `batch_1` (serial)
  6.897 ms — no regression from the per-call `cbank()` read.
  `benches/history.csv` row `v3.6-parallel-crypto`.

### Security

- Race surface enumerated exhaustively and closed; verified by
  `tests/tcyr/batch_parallel.tcyr` mutex-off (35/35 clean runs — the
  first run failed and surfaced the un-banked `fp_inv` /
  `hash_file_into` buffers, both then banked). Constant-time and
  zeroization posture unchanged (banking shifts only data-independent
  base addresses; no secret-material buffer is banked). Audit:
  `docs/audit/2026-06-03-3.6.0-parallel-verify-audit.md`. 0 CRITICAL /
  HIGH / MEDIUM.

## [3.5.9] — 2026-05-28

ECDSA P-256/P-384 signing with RFC 6979 deterministic nonces — issue
line item 3 of the cyrius native-TLS arc. Pairs with the existing
verify path and consumes the private scalars `src/privkey.cyr` (3.5.8)
parses, so cyrius can now sign TLS 1.3 CertificateVerify with an EC
server/client cert. Pure additive surface.

### Added

- **`src/ecdsa_sign.cyr`** — new module:
  - `ecdsa_p256_sign(d, msg, msg_len, sig_out)` /
    `ecdsa_p384_sign(...)` — raw `r‖s` (64 / 96 bytes, big-endian).
    Hashes the message internally (SHA-256 / SHA-384), matching the
    verify entry points.
  - `ecdsa_p256_sign_der` / `ecdsa_p384_sign_der` — DER
    `SEQUENCE { INTEGER r, INTEGER s }` (the TLS 1.3
    CertificateVerify / RFC 8446 §4.2.3 form). Returns the DER byte
    length.
  - RFC 6979 §3.2 deterministic nonce via HMAC_DRBG keyed on the
    curve hash (`hmac_sha256` / `hmac_sha384`) — signing is a pure
    function of (key, message), eliminating the catastrophic
    per-signature RNG dependence. Reuses each curve's mod-n scalar
    arithmetic (`fn_p256_inv`/`fn_p256_mul`, etc.) and `pt_scalarmul`.
  - A carry-correct scalar add-mod-n (the lib `u256_addmod` drops the
    2^256 carry, which is wrong for the P-256/P-384 scalar field
    where `n ≈ 2^256`).
- **Tests** (`tests/tcyr/ecdsa_sign.tcyr`, +20 assertions) — exact
  `(r‖s)` for the RFC 6979 Appendix A.2.5 (P-256/SHA-256) and A.2.6
  (P-384/SHA-384) "sample"/"test" vectors (independently reproduced
  with a stdlib-only Python RFC 6979 implementation before
  embedding), determinism, sign→verify roundtrips (raw + DER), and
  DER structure.
- **Benches** — `ecdsa_p256_sign` (74 ms) + `ecdsa_p384_sign`
  (179 ms) in `tests/bcyr/sigil.bcyr` + `history.csv` row
  `v3.5.9-ecdsa-sign`. (Dominated by the textbook long-division
  reduction; the v3.7 Solinas work improves both.)

### Changed

- **Dist regenerated** — `dist/sigil.cyr` rebuilt;
  `cyrius doc --check` reports **0 undocumented**. Full suite (47
  files, 1284 assertions) green. Toolchain pin unchanged (cyrius
  6.0.14). Audit:
  `docs/audit/2026-05-28-3.5.9-ecdsa-sign-audit.md`.

## [3.5.8] — 2026-05-28

EC + Ed25519 private-key parsers (PEM + DER) — the first half of
issue line item 4
(`docs/development/issues/2026-05-28-cyrius-tls-arc-full-audit.md`),
needed before any TLS server key can come online. Pure additive
surface; the RSA private-key parser is deferred to 3.5.10 (it needs
the bignum/key type that lands with the RSA engine — `pem_decode_privkey`
recognizes the RSA label and returns a dedicated unsupported sentinel
until then).

### Added

- **`src/privkey.cyr`** — new module:
  - `ed25519_privkey_from_der(der, der_len, seed_out)` — PKCS#8 /
    RFC 8410 → 32-byte seed.
  - `ecdsa_p256_privkey_from_der` / `ecdsa_p384_privkey_from_der` —
    SEC1 (RFC 5915) **or** PKCS#8 (RFC 5208) → the private scalar `d`
    as fixed-length big-endian (32 / 48 bytes), matching the byte
    order `ecdsa_p256_verify` / `ecdsa_p384_verify` and the 3.5.9
    sign path consume. The version INTEGER discriminates the
    containers; embedded curve OIDs are full-byte validated.
  - `pem_decode_privkey(pem, pem_len, key_out, key_max, out_algo)` —
    auto-detects the PEM label (`EC PRIVATE KEY` / `PRIVATE KEY` /
    `RSA PRIVATE KEY`) and, for PKCS#8, the algorithm from the algid
    OID. Returns the key byte count (32/48) + a `SIG_PRIVKEY_*` tag,
    or `0 - SIG_PRIVKEY_RSA` for the recognized-but-unsupported RSA
    case. Reuses the base64 decoder + marker search from
    `src/pem.cyr` (no duplication).
- **Tests** (`tests/tcyr/privkey.tcyr`, +33 assertions) — Ed25519
  PKCS#8 end-to-end (seed → derive public key → sign/verify), P-256
  /P-384 SEC1 + PKCS#8 scalar parse, curve/OID/truncation rejection,
  and the PEM layer for all five EC/Ed25519 forms + the RSA sentinel.
  PEM blocks are inlined in the test (the repo `.gitignore` excludes
  `*.pem`, so fixtures can't be committed); each base64 body is the
  same key as the matching DER vector, so the two layers cross-check
  the same keys.

### Changed

- **Dist regenerated** — `dist/sigil.cyr` rebuilt via
  `scripts/regen-dist.sh` with the new module;
  `cyrius doc --check dist/sigil.cyr` reports **0 undocumented**.
  Full suite (46 files, 1264 assertions) green. Toolchain pin
  unchanged (cyrius 6.0.14).

## [3.5.7] — 2026-05-28

AES-128-GCM — first of the five scheduled additions for the cyrius
native-TLS arc (issue
`docs/development/issues/2026-05-28-cyrius-tls-arc-full-audit.md`,
line item 1). `TLS_AES_128_GCM_SHA256` (0x1301) is the RFC 8446 §9.1
**mandatory** TLS 1.3 ciphersuite; this also unblocks the four TLS
1.2 `*_WITH_AES_128_GCM_SHA256` suites. Pure additive public surface
— AES-256-GCM behaviour and signatures are unchanged. Toolchain pin
bumped to cyrius 6.0.14.

### Added

- **AES-128-GCM** (`src/aes_gcm.cyr`, FIPS 197 + NIST SP 800-38D) —
  `aes_128_key_expand(key, round_keys)` (16-byte key → 176-byte /
  11-key schedule, Nk=4 / Nr=10), `aes_128_gcm_encrypt` /
  `aes_128_gcm_decrypt` mirroring the AES-256 surface byte-for-byte.
  AES-128 differs from AES-256 only in the key schedule and round
  count; the block transform, GHASH, CTR mode, and GCM framing are
  shared and now parametrized on the round count.
- **AES-128 AES-NI path** (`src/aes_ni.cyr`) —
  `aes128_encrypt_block_ni` (10-round AESENC/AESENCLAST pipeline
  over the 11-key schedule). The boot self-test now validates
  **both** the AES-256 (FIPS 197 §C.3) and AES-128 (§C.1) NI vectors
  before going live; either diverging routes both key sizes to the
  software path.
- **Tests** (`tests/tcyr/aes128_gcm.tcyr`, +15 assertions) — the
  canonical GCM AES-128 known-answer vectors (McGrew & Viega / NIST
  Test Cases 1–4: empty, single-block, 4-block, and AAD +
  partial-final-block), plus a decrypt roundtrip, a one-bit
  tag-flip rejection with the AEAD no-plaintext-leak check, and an
  empty-message roundtrip.

### Changed

- **Block-encrypt + GCM driver parametrized on round count** — the
  software block transform (`_aes_encrypt_block_sw(…, nr)`), CTR
  helper, and GCM encrypt/decrypt drivers now take an `nr` parameter
  (14 = AES-256, 10 = AES-128); the public `aes_gcm_encrypt` /
  `aes_gcm_decrypt` are thin wrappers fixing `nr = 14`. No behaviour
  change to the AES-256 path (15-assertion `aes_gcm.tcyr` + 5-assertion
  `aes_ni.tcyr` suites unchanged and green).
- **Toolchain pin** — cyrius `6.0.12` → `6.0.14`
  (`cyrius.cyml [package].cyrius`). Full suite (45 files, 1231
  assertions) green; clean build clean.
- **Dist regenerated** — `dist/sigil.cyr` rebuilt via
  `scripts/regen-dist.sh`; `cyrius doc --check dist/sigil.cyr`
  reports **0 undocumented**.

## [3.5.6] — 2026-05-28

HMAC-SHA384 + HKDF-SHA384 — a forcing-function addition for the
cyrius native TLS 1.3 arc. Cyrius held its v6.0.13 (Mini-arc A.4,
TLS 1.3 key schedule) pending these primitives: the
`TLS_AES_256_GCM_SHA384` (0x1302) ciphersuite derives its RFC 8446
§7.1 key schedule off HKDF-SHA384, which sigil did not yet expose
(only the SHA-256 variants shipped). Pure additive public surface —
no breakage, no removal. Toolchain pin bumped to cyrius 6.0.12.

### Added

- **HMAC-SHA384** (`src/hmac_sha384.cyr`, FIPS 198-1 / RFC 4231 §3)
  — `hmac_sha384(key, key_len, msg, msg_len, out48)`. Standard
  ipad/opad construction over SHA-384's **128-byte block** and
  **48-byte digest** (NOT 64/32 — every size constant cascades from
  the larger block; keys > 128 bytes are SHA-384-hashed first).
  K′/ipad/opad scratch are `secret var`, zeroized on return.
- **HKDF-SHA384** (`src/hkdf_sha384.cyr`, RFC 5869 over HMAC-SHA384)
  — `hkdf_extract_sha384` / `hkdf_expand_sha384` / `hkdf_sha384`
  (combined one-shot). HashLen = 48, max OKM = 255×48 = **12240
  bytes**. Empty salt → 48 zero bytes (§2.2); PRK + every HMAC
  intermediate zeroized; loop count derived from public `out_len`
  (no branch on secret data). Mirrors `src/hkdf.cyr`'s structure
  and the global-scratch discipline.
- **Tests** (`tests/tcyr/hkdf_sha384.tcyr`, +19 assertions) — RFC
  4231 §4 HMAC-SHA384 Test Cases 1–4, 6, 7 (TC6/TC7 exercise the
  >128-byte key-hash path; TC5 truncation omitted as sigil emits
  the full tag), plus three HKDF-SHA384 vectors cross-verified
  against Python `hmac`/`hashlib` **and** `openssl kdf -kdfopt
  digest:SHA384 … HKDF`, plus the 255×48 cap and zero-length edges.

### Changed

- **Toolchain pin** — cyrius `6.0.3` → `6.0.12`
  (`cyrius.cyml [package].cyrius`). Full suite (44 files, 1216
  assertions) green; clean build clean.
- **Dist regenerated** — `dist/sigil.cyr` rebuilt via
  `scripts/regen-dist.sh` with the two new modules;
  `cyrius doc --check dist/sigil.cyr` reports **0 undocumented**.

## [3.5.5] — 2026-05-27

Documentation pass on the consumer-facing bundle API — a
prerequisite for upstreaming sigil into the main Cyrius language.
No source-logic changes; doc comments only.

### Changed

- **Doc-comment coverage** — `cyrius doc --check dist/sigil.cyr`
  went from **76 undocumented → 0** (88 public functions, all
  documented). Added concise doc comments immediately above every
  previously-undocumented public function the bundle doc-checker
  surfaces, across seven modules:
  - `src/types.cyr` (49) — enum-name helpers, `TrustPolicy` /
    `TrustCheck` / `TrustedArtifact` / `VerificationResult` /
    `SigilStats` constructors and field accessors.
  - `src/sha256.cyr` (14) — FIPS 180-4 round helpers (`rotr32`,
    `shr32`, `Ch`/`Maj`/`Σ`/`σ`), `sha256_global_init`, the
    streaming `init`/`transform`/`update`/`finalize`, and the
    one-shot `sha256`.
  - `src/error.cyr` (6) — `sigil_is_ok`/`is_err`, `sigil_err`
    constructor + accessors + free.
  - `src/hex.cyr` (3) — `hex_encode`, `sha256_hex`, `sha512_hex`.
  - `src/hkdf.cyr` (2) — `hkdf_extract`, `hkdf_expand` (rich
    RFC 5869 blocks already present; the blank line separating them
    from `fn` was bridged so the checker associates them).
  - `src/hmac.cyr` (1) — `hmac_sha256`.
  - `src/sha_ni.cyr` (1) — `sha_ni_available`.
- **Dist regenerated** — `dist/sigil.cyr` rebuilt via
  `scripts/regen-dist.sh` so the bundle carries the new doc
  comments and the `3.5.5` version header.

### Verification

Full suite **1197 assertions / 0 failures** (43 `.tcyr` files,
unchanged — no test surface touched); smoke build clean;
`cyrius doc --check dist/sigil.cyr` reports 0 undocumented (exit 0).

## [3.5.4] — 2026-05-27

Closeout of the **3.5 cycle** — the last patch before 3.6.0. No
source changes: a P(-1) Scaffold Hardening / Closeout pass per
CLAUDE.md.

### Changed

- **Audit consolidation** — the four per-bite audit docs
  (`2026-05-27-3.5.{0,1,2,3}-audit.md`) are merged into a single
  arc audit `docs/audit/2026-05-27-3.5-arc-audit.md`; references in
  `state.md` / `roadmap.md` repointed.
- **Benchmarks** — `tests/bcyr/sigil.bcyr` gained ChaCha20 /
  Poly1305 / AEAD / X25519 cases; `benches/history.csv` row
  `v3.5.4-modern-crypto` (chacha20_xor_1kb 43 µs, poly1305_mac_1kb
  3 µs, chacha20poly1305_encrypt_1kb 52 µs, x25519_base 2.965 ms).
  Notable: the AEAD is ~13× faster than AES-256-GCM at 1 KB on the
  dev host (AES-GCM's bit-by-bit GHASH dominates).
- **Docs** — `doc-health.md` refreshed for the arc; `sources.md`,
  `architecture/overview.md` module map, and ADR 0001/0003
  cycle-renumber amendments synced.

### Closeout verification

Full suite **1197 assertions / 0 failures**; clean-from-scratch
build OK; `cyrlint` gate green; security re-scan clean; the 3.5 arc
is purely additive so consumers stay API-compatible. Full checklist
in the arc audit.

## [3.5.3] — 2026-05-27

Closes the **3.5 cycle — modern AEAD + key agreement primitives**.
X25519 completes the pure-Cyrius TLS 1.3 `ChaCha20-Poly1305 +
X25519` suite — cipher (3.5.1), AEAD (3.5.2), MAC (3.5.0), and now
key agreement are all sigil-native.

### Added

- **X25519 key agreement (RFC 7748)** — `src/x25519.cyr`: `x25519`
  (scalar·u) + `x25519_base` (scalar·9 public-key derivation).
  Montgomery ladder reusing the Curve25519 field arithmetic in
  `src/bigint_ext.cyr` (`fp_*`, mod 2^255−19); constant-time
  `cswap`; RFC 7748 scalar clamp. All ladder state lives in one
  `secret var` scratch block, zeroized on return. Tests
  (`tests/tcyr/x25519.tcyr`, +6): §5.2 vectors 1-2 and §6.1
  Diffie-Hellman (public-key derivation + both-sides shared
  secret).

## [3.5.2] — 2026-05-27

The 3.5 cycle's third bite — the ChaCha20-Poly1305 AEAD, composing
the 3.5.1 cipher with the 3.5.0 MAC into TLS 1.3's
`TLS_CHACHA20_POLY1305_SHA256` construction.

### Added

- **ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)** —
  `src/chacha20poly1305.cyr`: `chacha20poly1305_encrypt` +
  `chacha20poly1305_decrypt`. Poly1305 one-time key derived from
  the counter-0 ChaCha20 block; ciphertext from counter 1; tag over
  `aad || pad16 || ct || pad16 || le64(aad_len) || le64(ct_len)`.
  Decrypt verifies the tag in constant time (`ct_eq_bytes`) before
  releasing plaintext, returning `ERR_INTEGRITY_MISMATCH` on
  mismatch — same AEAD contract and return shape as
  `aes_gcm_decrypt`. Tests (`tests/tcyr/chacha20poly1305.tcyr`,
  +5): §2.8.2 vector (ciphertext + tag), round-trip, tamper-reject.

## [3.5.1] — 2026-05-27

The 3.5 cycle's second bite — the ChaCha20 stream cipher, the
prerequisite for the ChaCha20-Poly1305 AEAD. Validated against the
RFC 8439 block-function and encryption test vectors.

### Added

- **ChaCha20 stream cipher (RFC 8439 §2.3 / §2.4)** —
  `src/chacha20.cyr`: `chacha20_block` (one 64-byte keystream
  block) + `chacha20_xor` (encrypt/decrypt with per-block counter
  increment). 20-round ARX permutation in 32-bit-word arithmetic.
  RFC 8439 §2.4 usage cap documented in the module (≤ 256 GiB per
  key/nonce — the 32-bit counter wraps beyond that). Tests
  (`tests/tcyr/chacha20.tcyr`, +3): §2.3.2 keystream vector, §2.4.2
  "sunscreen" ciphertext, encrypt/decrypt round-trip.

## [3.5.0] — 2026-05-27

Opens the **3.5 cycle — modern AEAD + key agreement primitives**.
The cyrius v6.2.x native-TLS arc needs a pure-Cyrius TLS 1.3
`ChaCha20-Poly1305 + X25519` suite (a bare-metal AGNOS kernel has
no `libssl.so.3` to dlopen). Poly1305 is the MAC half and has no
dependency on ChaCha20 or TLS, so it ships first, standalone; the
ChaCha20 stream cipher, the AEAD composition, and X25519 stay
gated on the native-TLS slot (see `docs/development/roadmap.md`).

### Added

- **Poly1305 one-time MAC (RFC 8439 §2.5)** — `src/poly1305.cyr`:
  - `poly1305_mac(key, msg, msg_len, out)` — 16-byte tag over a
    message under a 32-byte one-time key.
  - `poly1305_verify(key, msg, msg_len, tag)` — recompute-and-
    compare in constant time via the stdlib `ct_eq_bytes`.
  - Implemented in the 26-bit-limb (`poly1305-donna`) form: every
    intermediate product stays below 2^59, so the whole reduction
    mod 2^130−5 runs in signed i64 with no 128-bit arithmetic
    path. The final freeze is **constant-time** (mask-select, no
    branch on the key-derived accumulator) per sigil's
    constant-time-on-secret-data rule.
  - **One-time-key contract** documented in the module header:
    unlike HMAC, a Poly1305 key must never authenticate two
    distinct messages (RFC 8439 §2.6). For the AEAD the one-time
    key is derived fresh from the ChaCha20 keystream per nonce.
  - Tests (`tests/tcyr/poly1305.tcyr`, +5 assertions): RFC 8439
    §2.5.2 canonical worked example (exercises full + partial
    blocks and the carry chain), RFC 8439 A.3 #1 all-zero vector,
    the r=0 → tag=s property, and verify accept/reject.

### Changed

- **Cyrius toolchain pin bumped `6.0.1` → `6.0.3`** across
  `cyrius.cyml` and CI (`.github/workflows/ci.yml`). Clears the
  cycc-6.0.3 vs pin-6.0.1 toolchain-drift warning. No source
  impact; full suite green.
- **Roadmap restructure** — the v3.5 slot is now the AEAD +
  key-agreement cycle (above); the prior parallel-verify cycle
  slid to v3.6 and the perf-tuning / Solinas cycle to v3.7. The
  earlier backlog note that claimed "Poly1305 already ships" was
  corrected — it did not; only a descriptive comment existed in
  `src/aes_gcm.cyr`.

## [3.4.3] — 2026-05-23

`secret var` adoption pass on the AES-GCM AEAD path. Twelve
stack-local secret buffers in `src/aes_gcm.cyr` (GHASH H subkey,
GHASH running state, AES-CTR keystream, encrypt/decrypt tag, and
the inner GHASH multiplication scratch) move from `var X[N];` +
explicit end-of-function `memset(&X, 0, N)` to `secret var X[N];`
(Cyrius 5.3.5+). The compiler now emits zeroization for every
return path including early errors — the prior shape only zeroed
on the happy path. No functional change; spec-tests unchanged at
1178/0.

This is the in-place "land when an adjacent edit touches the
module" backlog item from the 3.4.1 audit follow-up list. Closure
target was originally "land in-place"; bundled here as a focused
defense-in-depth patch ahead of the 3.5 / 3.6 cycles (still gated
on forcing functions per roadmap).

### Changed

- **`src/aes_gcm.cyr` — 12 stack-local conversions to `secret var`:**
  - `_ghash_mul`: `v[16]` (working copy of H subkey).
  - `_ghash_update`: `block[16]` (plaintext/ciphertext scratch),
    `scratch[16]`, `scratch2[16]` (GHASH multiplication output).
  - `_aes_gcm_ctr_xor`: `ks[16]` (AES-CTR keystream block —
    leakage recovers plaintext).
  - `aes_gcm_encrypt`: `h[16]` (GHASH subkey), `y[16]` (GHASH
    state), `s[16]` (AES_K(J0) for tag).
  - `aes_gcm_decrypt`: `h[16]`, `y[16]`, `s[16]`,
    `expected_tag[16]`.

  Heap-allocated `round_keys` (240 B `fl_alloc`) keeps its
  explicit `memset` + `fl_free` — `secret var` is stack-scope
  only. IV / counter / length / constant-zero blocks
  (`j0`, `counter`, `len_block`, `zero_block`) are not key
  material and keep their explicit end-`memset` calls as
  defense-in-depth — applying the `secret var` keyword to
  non-secret values would dilute its semantic.

### Security

- Closes the "secret var ambient adoption" backlog item from the
  3.4.1 roadmap. The prior end-of-function `memset` pattern
  zeroed buffers only on the happy-path return; with `secret
  var`, the compiler emits zeroization on every return including
  early-exit error paths (e.g. the `aad_len < 0` /
  `pt_len < 0` validation rejects in encrypt/decrypt — which
  previously left whatever stack content was already present).
- Audit pass at `docs/audit/2026-05-23-3.4.3-audit.md`. Zero
  CRITICAL / HIGH / MEDIUM / LOW findings; seven LOW findings
  from prior cycles (bump-allocator lifetime) carry forward to
  3.6 unchanged.

### Performance

- `aes_gcm_encrypt_1kb` 716 µs → 723 µs (+1.0%).
- `aes_gcm_decrypt_1kb_valid` 715 µs → 729 µs (+2.0%).
- `aes_gcm_decrypt_1kb_forged` 720 µs → 730 µs (+1.4%).

  Deltas are run-to-run noise plus a small real cost from the
  compiler-emitted zeroization on return. Within tolerance for
  the security gain. Numbers logged to `benches/history.csv` as
  `v3.4.3-secret-var-aesgcm`.

## [3.4.2] — 2026-05-22

Packaging-fix release. `dist/sigil.cyr` (sigil's bundled
single-file distribution) had drifted ten module additions
behind the source tree — frozen at 3.2.0-era content since the
upstream `cyrius distlib` subcommand was retired. This release
regenerates the bundle from the current `cyrius.cyml [lib].modules`
list and ships `scripts/regen-dist.sh` to replace the retired
cyrius subcommand going forward. Bundles the 2026-05-22 doc-tree
restructure as ride-along so the documentation ledger gets a
released-version timestamp.

### Fixed

- **`dist/sigil.cyr` — regenerated against current source tree.**
  The bundled distribution was missing every module added since
  3.2.0:
  - `ecdsa_p256.cyr` (3.2.1) — ECDSA P-256 verify
  - `x509.cyr` (3.2.2) — minimal X.509 cert parser + chain walker
  - `sgx.cyr` (3.2.3) — Intel SGX DCAP v3 quote verify
  - `sha384.cyr`, `ecdsa_p384.cyr`, `sev_snp.cyr` (3.2.4)
  - `tdx.cyr` (3.2.5) — Intel TDX v4 TD-quote verify
  - `seal.cyr` (3.2.6) — SGX sealing-key derivation
  - `pem.cyr` (3.4.0) — RFC 4648 base64 + PEM block decoder
  - And by composition all three of the 3.4 cycle's
    `*_verify_full` end-to-end orchestrators (which depend on
    `pem.cyr` + `x509.cyr` + `ecdsa_*.cyr`).

  Bundle grew from 9,457 → 14,086 lines. Consumers building
  against `dist/sigil.cyr` rather than including `src/lib.cyr`
  against a sibling checkout now see the full 3.4.x public API
  surface. First-party AGNOS consumers (daimon, kavach, ark,
  …) build against `src/lib.cyr` directly and were unaffected.

### Added

- **`scripts/regen-dist.sh`** — replaces the retired `cyrius
  distlib` subcommand. Concatenates `cyrius.cyml [lib].modules`
  in source-include order into `dist/sigil.cyr` with the prior
  bundle's header + section-separator format preserved. Re-run
  whenever `[lib].modules` changes or a listed module needs
  its update to land in the dist bundle.

### Changed

- **`cyrius.cyml [lib].modules`** — added `src/pem.cyr` (was
  missing from the list, which was the proximate cause of the
  3.4.x portion of the dist drift). Added a test-layout
  comment block documenting sigil's per-module `.tcyr` pattern
  vs. the agnosticos-standard single `src/test.cyr` shape.

### Documentation

The 2026-05-22 doc-tree sweep moves under this release rather
than waiting for the next 3.x minor. Per Keep a Changelog,
patch releases can carry documentation changes; bundling here
gives `docs/doc-health.md` a released-version timestamp.

- **Tree restructured** to match agnosticos
  [first-party-documentation](https://github.com/MacCracken/agnosticos/blob/main/docs/development/planning/first-party-documentation.md)
  conventions:
  - **New**: `docs/development/state.md` — live state snapshot
    (version, test counts, consumers, audit floor); refreshed
    every release. Replaces the volatile content previously
    inlined in `CLAUDE.md`.
  - **New**: `docs/adr/` — architecture decision records.
    Seeded with `README.md`, `template.md`, and three ADRs
    documenting the `_sigil_batch_mutex` retention (0001),
    the ML-DSA cmdline gate (0002), and the bump-alloc-drift
    deferral to 3.6 (0003).
  - **New**: `docs/architecture/README.md` — ADR-sibling
    index for non-obvious code invariants. Numbered notes
    deferred to first grep-from-the-wild promotion.
  - **New**: `docs/sources.md` — consolidated RFC / FIPS /
    NIST / Intel SGX / AMD SEV-SNP citation index for every
    crypto primitive. Required for domain crates per
    first-party-standards.
  - **New**: `docs/doc-health.md` — fresh / stale / archive
    ledger across the doc tree. Refreshed in place when docs
    are touched.
- `CLAUDE.md` restructured to match agnosticos
  `example_claude.md` template (durable rules only; volatile
  state moved to `state.md`; fixed planning-doc link from
  `applications/` → `planning/`).
- `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and
  `docs/architecture/overview.md` rewritten against the
  current 3.4.x surface (added ECDSA P-256/P-384, AES-GCM,
  HKDF, SHA-384, ML-DSA, X.509, PEM, SGX/TDX/SEV-SNP, seal).
- `docs/development/roadmap.md` — trimmed renumber breadcrumbs
  from the 3.4 ship; bumped LOW-finding count to 7 across the
  3.2.x and 3.4.x cycles.

### Security

- Audit pass at `docs/audit/2026-05-22-3.4.2-audit.md`. Zero
  CRITICAL / HIGH / MEDIUM / LOW findings on the source tree
  (unchanged from 3.4.1). Two INFO findings document the
  packaging-flow gap that allowed the dist drift to accumulate
  (root cause: retired `cyrius distlib` subcommand) and the
  candidate programmatic gate (module-list drift check at
  closeout) that would have caught it earlier.

## [3.4.1] — 2026-05-22

SEV-SNP attestation completion. Closes the explicit gap deferred
from 3.4.0: the AMD VCEK leaf in a SEV-SNP cert chain holds a
P-384 pubkey that sigil's prior x509 parser (P-256-only) could
not extract. 3.4.1 extends x509 SPKI parsing to dispatch on the
curve OID (prime256v1 OR secp384r1), tracks per-cert curve and
pubkey width, and ships `snp_report_verify_full` to match the
`*_verify_full` shape that SGX and TDX got in 3.4.0.

### Added

- **x509 P-384 SPKI extraction.** `src/x509.cyr` accepts
  either `id-ecPublicKey + prime256v1` (existing, 64-byte
  pubkey) or `id-ecPublicKey + secp384r1` (NEW, 96-byte
  pubkey). On-curve validation dispatches to the matching
  curve primitive (`pt_is_on_curve` for P-256,
  `pt_p384_is_on_curve` for P-384). New `secp384r1` OID
  constant (1.3.132.0.34 → DER `06 05 2B 81 04 00 22`). New
  accessors `x509_cert_curve(c)` and `x509_cert_pubkey_len(c)`.
  New constants `X509_CURVE_P256` (= 1) and `X509_CURVE_P384`
  (= 2).
- **`snp_report_verify_full(report, vcek_chain_pem,
  vcek_chain_pem_len, ark_root_der, ark_root_der_len,
  now_unix)`.** End-to-end SEV-SNP verify. Composes
  `pem_decode_certs` → `x509_parse` (per cert + ARK root) →
  drop self-issued top → `x509_verify_chain` anchored on
  caller's root → curve gate (leaf must be P-384, pubkey_len
  must be 96) → `snp_report_verify` against the 96-byte VCEK
  pubkey. 11-assertion test surface
  (`tests/tcyr/snp_verify_full.tcyr`) covers happy path,
  wrong-root rejection, malformed inputs, tamper rejection,
  and the wrong-curve-leaf guard.
- **P-384 cert parsing tests.** New
  `tests/tcyr/x509_p384.tcyr` (12 assertions) covers SPKI
  extraction against a real P-384 cert, chain walk under a
  P-256 root, and the mixed-curve guard that rejects P-384
  issuers.

### Changed

- **`X509Cert` struct layout.** The pubkey slot at offset +96
  expanded from 64 to 96 bytes. Subsequent fields shifted +32:
  `sig_algo` +160 → +192, `sig_off` +168 → +200, `sig_len`
  +176 → +208, `is_ca` +184 → +216, `path_len` +192 → +224.
  New fields: `curve` at +232, `pubkey_len` at +240. The
  reserved tail shrinks from 56 to 8 bytes. All accessors and
  setters updated; no public-API behavior change for P-256
  consumers.
- **`_x509_verify_link` curve gate.** Issuer cert must have
  `curve == X509_CURVE_P256` — chain-link signatures remain
  ECDSA-SHA256, and `ecdsa_p256_verify` only understands
  64-byte pubkeys. A P-384 issuer is rejected explicitly
  (would otherwise silently consume the lower 64 bytes of the
  96-byte pubkey slot and produce a wrong verify result). The
  LEAF may still be P-384; this restriction applies only to
  certs that sign a subsequent link.
- **`tests/tcyr/sev_snp.tcyr` includes.** Added `src/x509.cyr`
  and `src/pem.cyr` to the test's include list — required by
  the new `snp_report_verify_full` surface in `sev_snp.cyr`.

### Scope cuts (documented, not deferred)

- **Chain-link signature verify remains ECDSA-SHA256 only.**
  P-384 chain links (P-384 issuer signing a child) are
  rejected. Real AMD VCEK chains use RSA at the ARK/ASK links
  and ECDSA-P-384-SHA256 at the VCEK level — neither is
  walkable by sigil's x509 today. Real-deployment consumers
  must pre-walk ARK → ASK externally and hand sigil only the
  ASK → VCEK fragment (or skip the chain walk entirely and
  use `snp_report_verify` against a caller-validated VCEK
  pubkey).

### Security

- Audit pass at `docs/audit/2026-05-22-3.4.1-audit.md`. Zero
  CRITICAL / HIGH / MEDIUM findings. One NEW LOW
  (`_snp_v_init` joins the existing six bump-alloc LOWs;
  closure at 3.6 with the unified `_into` API). Three INFO
  findings document the mixed-curve restriction, in-quote ARK
  treatment, and the X509Cert struct footprint approaching
  saturation (~248 of 256 bytes used).

## [3.4.0] — 2026-05-22

TEE attestation completion. Closes the per-piece API gap from
the 3.2.x arc: a downstream consumer (kavach attestation backend,
ark publisher) can now call a single `*_verify_full` entry point
on an SGX or TDX quote, pass in the Intel SGX Root CA, and get an
end-to-end yes/no answer that walks the embedded PEM PCK chain,
verifies it against the trust anchor, extracts the leaf pubkey,
and chains into the three internal attestation signature checks.

### Added

- **`src/pem.cyr` — minimal PEM cert decoder.** New module
  (~245 LoC) exposing `pem_decode_certs(pem, pem_len, out_chain,
  max_certs)` and an `_into` variant
  `pem_decode_certs_into(pem, pem_len, out_chain, max_certs,
  der_pool, der_pool_size)` for caller-provided scratch. Decodes
  one or more `-----BEGIN CERTIFICATE----- ... -----END
  CERTIFICATE-----` PEM blocks (RFC 4648 §4 base64, whitespace
  skipped, padding-as-end-marker only). Output is a contiguous
  array of `(der_ptr, der_len)` 16-byte entries pointing into
  the DER pool. All bounds checked at every step — attacker-
  controlled input. 39-assertion test surface
  (`tests/tcyr/pem.tcyr`) covers happy paths, padding variants,
  multi-cert chains, whitespace tolerance, malformed input
  rejection, and round-trip through `x509_verify_chain` against
  the existing x509 test root+leaf fixtures.
- **`sgx_quote_verify_full(quote, root_ca_der, root_ca_der_len,
  now_unix)`.** End-to-end SGX DCAP v3 quote verify. Pipeline:
  validates `cert_data_type == 5` (PCK PEM); decodes the PEM
  chain via `pem_decode_certs`; parses each cert + the caller's
  root anchor via `x509_parse`; drops the self-issued top-of-
  chain if present (the embedded Intel SGX Root copy — trust is
  anchored on the CALLER's `root_ca_der`); walks the chain via
  `x509_verify_chain`; extracts the PCK pubkey from the leaf;
  chains into `sgx_quote_verify_with_pck` for the three internal
  sig checks (PCK→QE-report, AK binding, AK→quote-body). 11-
  assertion test surface (`tests/tcyr/sgx_verify_full.tcyr`)
  covers happy path, cert_data_type mismatch, time-window
  rejection, wrong-root rejection, malformed-root rejection,
  and quote-body tamper.
- **`tdx_quote_verify_full(quote, root_ca_der, root_ca_der_len,
  now_unix)`.** Structurally identical to SGX (TDX shares the
  Intel PCK cert chain). Dispatches internally on `att_key_type`
  for the P-256 vs P-384 AK verification path. 16-assertion
  test surface (`tests/tcyr/tdx_verify_full.tcyr`) covers both
  att_key_type variants happy path + the cross-cutting failure
  modes.
- **TDX `att_key_type = 3` (ECDSA P-384 / SHA-384) support.**
  Parser dispatches per-variant on field widths
  (`tdx_quote_ak_size` and `tdx_quote_ecdsa_sig_size`
  accessors): AK and ECDSA sig grow from 64 B to 96 B each for
  type=3; the QE report's own signature stays 64 B (Intel PCK
  is P-256 across all variants). Verify orchestrator dispatches
  on `att_key_type`:
  - AK binding hash: `sha256` for type=2 (full 32 B digest),
    `sha384` for type=3 (lower 32 B of the 48 B digest, per
    Intel TDX 1.5 spec — the report_data slot is 64 B with
    upper 32 B required-zero).
  - AK→quote-body signature: `ecdsa_p256_verify` for type=2,
    `ecdsa_p384_verify` for type=3.
  P-256 fixture path remains byte-identical to 3.2.5; the new
  P-384 fixture exercises the new path end-to-end.

### Changed

- **`src/tdx.cyr` — verify scratch enlargement.**
  `_tdxv_binding_input` from 65600 → 65632 bytes (holds the
  larger P-384 AK plus max-len qe_auth_data);
  `_tdxv_binding_hash` from 32 → 48 bytes (full SHA-384 digest
  buffer; only the lower 32 B are compared against
  `qe_report.report_data[0:32]`).
- **`src/lib.cyr` — include `src/pem.cyr`** between `x509.cyr`
  and `sgx.cyr` (the consumer modules).

### Deferred

- **`snp_report_verify_full`** carries forward to a future
  cycle. AMD's real VCEK leaf cert holds a 96-byte P-384
  pubkey, which sigil's x509 parser (P-256-only SPKI today)
  cannot extract. Closure depends on extending `x509.cyr` to
  parse `secp384r1` `id-ecPublicKey` SPKIs and tracking
  per-cert pubkey-width; that's its own scope item. Sigil's
  per-piece API (`snp_report_parse` +
  `snp_report_verify(report, vcek_pk)`) remains the supported
  integration shape — callers handle their own X.509 chain
  walk via whatever PKI surface fits AMD's chain (real chains
  use RSA at the ARK/ASK links, also out of sigil's current
  x509 scope).

### Security

- Audit pass at `docs/audit/2026-05-22-3.4.0-audit.md`. Zero
  CRITICAL / HIGH / MEDIUM findings across ~485 lines of new
  code in `pem.cyr` + the wrappers + the TDX P-384 dispatch.
- Two LOW findings: bump-allocator lifetime in `*_verify_full`
  (LOW-1) and `_pem_init` (LOW-2) — the same shape as the
  3.2.x arc's four LOWs; all four close together at 3.6 with
  the unified `_into` API.
- Four INFO findings document scope cuts (SEV-SNP deferred,
  in-quote root cert treatment, P-384 binding hash truncation,
  chain-order assumption).

### Roadmap renumber

The original 3.4 cycle (parallel verify scratch refactor) and
3.5 cycle (TEE completion) were swap-sequenced because:
- 3.4-parallel had a "sequencing decision: open when forcing
  function arrives" caveat and no consumer has surfaced.
- 3.5-TEE had a similar caveat but the kavach integration
  pressure has been present in spirit (closes the per-piece
  API gap from the 3.2.x arc). Opened in this session.

Post-renumber: 3.4 ships TEE completion (this entry); the
parallel-verify work moves to roadmap "Road to v3.5" with its
existing sequencing caveat. 3.6 perf tuning unchanged.

## [3.3.0] — 2026-05-22

Cleanup / refactor cycle. The original 3.3 goal — drop
`_sigil_batch_mutex` by moving crypto-module working state to
per-call scratch — was investigated, refactored, and **deferred
to 3.4** when a load-bearing cyrius semantic surfaced. The
refactor itself shipped (net **−190 LOC across 7 modules**) and
captures the discovery so 3.4 can be designed correctly.

### Changed

- **`src/sha256.cyr`, `src/sha512.cyr`, `src/ed25519.cyr`,
  `src/aes_gcm.cyr`, `src/bigint_ext.cyr`, `src/sha_ni.cyr` —
  per-call working state.** Explicit named module globals
  (`_sha_a..h`, `_sha_t1/t2`, `_sha_i`, `_sha256_W`, `_sha512_W`,
  `_s5_*`, `_ga_*`, `_gd_*`, `_gsm_*`, `_gts_*`, `_gsb_*`,
  `_bt_*`, `_gcomp_*`, `_gdc_*`, `_scma_*`, `_kp_*`, `_sign_*`,
  `_ver_*`, `_mod_*`, `_mf_*`, `_fp_pow_*`, `_fpi_*`, `_aes_state`,
  `_aes_tmp`) replaced with in-function `var X[N]` array
  declarations. Read-only init tables (`_ed_d`, `_ed_2d`,
  `_ed_B`, `_ed_B_table`, `_ed_L`, `_ed_sqrtm1`, `_ed_p`,
  `_mod_38`, `_sha256_K`, `_sha512_K`, `_aes_sbox`, `_aes_rcon`,
  `_sha_ni_K`) retained as proper globals — init-once,
  read-only, shared-safe.
- **`src/ed25519.cyr` — alloc-free hot path.** `ed25519_verify`
  no longer calls `ge_alloc()` × 4 + `alloc(32)` per call;
  point and scalar buffers live in the function frame.
  `ed25519_keypair` / `ed25519_sign` adopted `secret var` for
  secret material with compiler-guaranteed zeroization on
  scope exit (replaces pre-3.3 manual `memset(_kp_*, 0, ...)`).
- **`src/sha512.cyr` — alloc-free init variant.** New
  `sha512_init_into(ctx)` mirrors the 3.2.0 `sha256_init_into`
  pattern; lets `ed25519_verify` run a streaming SHA-512 hash
  without touching the freelist allocator. `sha512_init()`
  retained as a heap-allocating convenience wrapper.
- **`src/bigint_ext.cyr` — `_mul64_full` inlined.** Returning
  two values via `_m64_lo` / `_m64_hi` globals had no clean
  local equivalent; inlining into the sole caller
  `u256_mul_full` eliminates the issue and removes a function
  call from the inner multiplication loop.
- **`src/sha_ni.cyr` — bswap mask split from working buffer.**
  The pre-3.3 `_sha_ni_buf` (80 bytes) packed working state +
  ABEF/CDGH saves + bswap mask. Mask split to its own
  read-only `_sha_ni_bswap_src` global (16 bytes); working
  area becomes a function-frame array memcpy'd from the
  template per call. Sets up the 3.4 caller-scratch path for
  the same module.
- **`src/verify.cyr` — main-thread crypto pre-warm.**
  `sv_verify_batch` now warms `ed25519_init()`,
  `sha256_global_init()`, `sha512_global_init()`, and
  `sha_ni_available()` on the main thread before fan-out.
  Defence-in-depth alongside the (retained) batch mutex —
  workers never hit a cold lazy-init guard.
- **Init-guard simplification.** `_ga_inited`, `_gd_inited`,
  `_gdc_inited`, `_kp_*` first-call-alloc guards,
  `_fp_pow_inited`, `_fpi_inited`, `_aes_state_inited`,
  `_scma_prod` first-call guard, `_ver_*` first-call guards
  all removed — no longer needed once the heap allocations
  they gated moved into function frames. `_ed_decomp_exp`
  and `_scr_r256` lifted into `ed25519_init()` so the
  main-thread pre-warm covers their initialisation.

### Documented

- **CLAUDE.md quirk #1 — rewritten.** Confirmed via
  `cyrius/src/frontend/parse_fn.cyr:2886` ("DON'T restore VCNT
  — arrays inside functions are globals that persist") and
  `tests/tcyr/var_array_semantics.tcyr` that **`var X[N]`
  inside a function is a static function-scope global, not a
  stack array**. Scalar `var x = expr` locals ARE per-call
  stack-frame slots. The cc3-era promote-to-global workaround
  for scalar clobbering is no longer needed under cc6 (removed
  in this cycle); the array-static behaviour persists and
  blocks the parallel mutex-drop until 3.4's caller-scratch
  refactor.
- **`tests/tcyr/var_array_semantics.tcyr`** — minimal probe
  that proves the array-static semantics from cyrius
  user-space. Kept in-tree as both regression sentinel
  (any future cyrius change to local-array storage trips
  it) and as the load-bearing documentation for why 3.4's
  architecture is the way it is.
- **`tests/tcyr/sha256_locals_probe.tcyr`** — single-thread
  FIPS-vector correctness probe of a locals-only
  `sha256_transform_local`. Confirms the digest output
  matches the production path even when the working state is
  written before being read each call (same-thread reuse is
  safe; the cross-thread story is the array-static issue).

### Deferred

- **`_sigil_batch_mutex` stays.** Dropping it requires
  threading a caller-provided scratch buffer through every
  `sha256_transform`, `sha512_transform`, `ge_*`, `fp_*`,
  `u256_mul_full`, `u512_mod_p`, `sc_reduce`, `sc_muladd`,
  `ed25519_verify`, `hash_file_into` signature. Per-worker
  scratch pool (~3 KB / worker) pre-allocated by the main
  thread before fan-out. Mechanical but invasive — re-scoped
  as 3.4 with a clear architecture (see
  `docs/development/roadmap.md` § "Road to v3.4").

### Threading semantics (unchanged from 3.2.x)

`batch_parallel.tcyr` continues to pass 228/228 with the
mutex on. Mutex-off behaviour was characterised
experimentally: ~12% of artifacts in the count=32 mixed
batch fail signature verify, with R_check varying
non-deterministically across runs from identical inputs —
exactly the symptom an in-function array-static would
produce. The new probe in `tests/tcyr/var_array_semantics.tcyr`
ties this directly to the cyrius semantic.

## [3.2.6] — 2026-05-26

Sixth and final bite of the 3.2.x TEE attestation arc
([`docs/development/3.2-tee-arc.md`](docs/development/3.2-tee-arc.md)):
**SGX sealing key derivation**. The smallest bite of the arc
(~115 lines) — pure composition over the existing HKDF-SHA256
surface (audited at 2.9.x). **Closes out the 3.2.x TEE
attestation arc.**

### Added

- **`src/seal.cyr` — SGX sealing KDF (~115 lines).**
  - `sgx_derive_seal_key(sealing_root, policy, measurement,
    isvsvn, key_id, key_id_len, out_key)` — core derivation.
    Builds an info string `policy(1B) || isvsvn_BE(2B) ||
    measurement(32B) || key_id(var)` and runs HKDF-SHA256 over
    it with the domain-separation salt `"sigil-sgx-seal-v1"`.
    Output: a 32-byte derived key suitable for AES-256-GCM.
  - `sgx_seal_key(...)` and `sgx_unseal_key(...)` — pure aliases
    that delegate to `sgx_derive_seal_key`. A deterministic KDF
    needs no inverse; "seal" and "unseal" are semantic labels
    for the caller's surrounding AEAD encrypt / decrypt step
    (composed against `aes_gcm.cyr`).
  - Input validation: policy ∈ {0, 1}, isvsvn ∈ [0, 2^16),
    key_id_len ∈ [0, 256]. Out-of-range values rejected.
  - **Sigil cannot call SGX's `EGETKEY` directly** — the
    sealing root is caller-provided (obtained via the runtime's
    enclave-side bridge: Gramine / Occlum / TDX TDG_MR_REPORT).
    This is a deliberate scope cut documented in the source
    header and the audit (INFO-1).
- **`tests/tcyr/seal.tcyr`** — 17 assertions across 4 groups:
  cross-reference against direct HKDF (key bytes match), seal /
  unseal symmetry, divergence on each of the 6 input fields
  (policy / isvsvn / measurement / key_id bytes / key_id length
  / sealing_root), and input-validation rejection cases including
  boundary tests for zero-length and max-length key_id.

### Security

- Audit: `docs/audit/2026-05-26-audit.md`. **0 findings at any
  severity** on the new surface. Two INFO items document
  deliberate scope cuts (sealing-root provenance is the
  caller's responsibility; AEAD wrapping is caller-driven via
  `aes_gcm.cyr`).
- CVE patterns checked: HKDF salt confusion (defended by fixed
  domain-separation salt), cross-policy collision (defended by
  policy-byte-first info layout), truncation collision (HKDF-
  SHA256 not vulnerable on unambiguously-encoded info).

### TEE attestation arc — closed

The 3.2.x arc spans six tags (3.2.1 → 3.2.6) shipped 2026-05-21
through 2026-05-26. Summary in `docs/audit/2026-05-26-audit.md`:
**~3200 new lines of cryptographic and parsing code across the
arc; zero CRITICAL / HIGH / MEDIUM audit findings**.

Arc surface delivered:
- `src/ecdsa_p256.cyr` — ECDSA P-256 verify
- `src/ecdsa_p384.cyr` — ECDSA P-384 verify
- `src/sha384.cyr` — SHA-384
- `src/x509.cyr` — minimal X.509 v3 cert-chain walker (ECDSA-
  with-SHA256, prime256v1 only)
- `src/sgx.cyr` — Intel SGX DCAP v3 quote parser + verify
  orchestrator
- `src/sev_snp.cyr` — AMD SEV-SNP attestation report parser +
  verify orchestrator
- `src/tdx.cyr` — Intel TDX v4 TD-quote parser + verify
  orchestrator
- `src/seal.cyr` — SGX sealing key derivation

Plus `pt_is_on_curve` (P-256) / `pt_p384_is_on_curve` (P-384)
helpers that close the prior audit's Q-on-curve gap for
externally-sourced public keys.

### Open follow-ups tracked across the arc

1. PEM decoder + integrated chain-walk wrappers for SGX /
   SEV-SNP / TDX (currently caller-driven via the `x509_*`
   surface). Single shared follow-up patch when an integration
   surfaces a forcing function.
2. ECDSA P-384 / SHA-384 variant of the TDX parser
   (att_key_type = 3). Small delta now that the P-384 primitive
   is in tree.
3. Solinas word-level field reduction for both P-256 and P-384.
   Bench tuning — the long-division reduction is correct but
   slow (~136 ms / verify for P-256, ~3× that for P-384).
4. Unified `_into`-shape API for parsers / verifiers that
   currently allocate scratch on first call. Closes the four
   LOW findings across the arc.

None of these block any current downstream consumer.

### Module wiring

- `src/lib.cyr` includes `src/seal.cyr` after `src/tdx.cyr`.
- `cyrius.cyml [lib].modules` lists the new module.

## [3.2.5] — 2026-05-25

Fifth bite of the 3.2.x TEE attestation arc
([`docs/development/3.2-tee-arc.md`](docs/development/3.2-tee-arc.md)):
**Intel TDX v4 TD-quote parser + verify orchestrator**. Composes
against the SGX-shape signature section (TDX quotes are signed by
the SGX QE on the same host) and adds the TDX-specific 584-byte
TD report body parsing. The smallest bite of the arc since
3.2.3 — most of the structural work was already in tree.

### Added

- **`src/tdx.cyr` — TDX v4 quote parser + verify orchestrator
  (~290 lines).**
  - `tdx_quote_parse(buf, buf_len, out)` — bounds-checked
    linear walk of the v4 layout: 48-B header (version=4,
    tee_type=0x81, att_key_type=2), 584-B TD_QUOTE_BODY
    (MRTD/MRSEAM/MRSEAMSIGNER/RTMR0..3/TD_ATTRIBUTES/XFAM/
    REPORT_DATA per Intel TDX 1.0 spec), then the SGX-shape
    signature section. Three independent header invariants
    enforced — version, tee_type, att_key_type — so SGX quotes
    won't be mis-parsed as TDX (audit Step 9).
  - `tdx_quote_verify_with_pck(quote, pck_pk)` — same three-
    step shape as `sgx_quote_verify_with_pck`:
      1. PCK signs the QE report (384-B SGX enclave-report
         shape).
      2. AK is bound to the QE via SHA-256(AK || qe_auth_data)
         in `qe_report.report_data[0:32]`; upper 32 bytes
         required zero.
      3. AK signs the quote body — but the body is **632 bytes**
         (header + TD report) instead of SGX's 432.
  - Field accessors for everything a kavach TDX backend
    populates: `tdx_quote_mrtd_ptr`, `mrseam_ptr`, `rtmr0..3_ptr`,
    `report_data_ptr`, `td_attributes_ptr`, `xfam_ptr`,
    `ak_ptr`, `qe_report_ptr`, `cert_data_ptr/_len/_type`.
- **`tests/tcyr/tdx.tcyr`** — 32 assertions across 5 groups:
  parser happy path + 14 field-accessor checks, 5 malformed
  rejection cases (truncated/empty + 4 header invariant
  violations + sig_data_len overflow), verify orchestrator
  green path, 4 tamper cases (wrong PCK / qe_report_sig / AK /
  body ecdsa_sig / MRTD). Test vector generated offline
  (openssl + Python helper, same pattern as 3.2.3 SGX). Tests
  use the helper-split pattern recommended by the 3.2.4 audit
  INFO-3.

### Scope decision

- `att_key_type = 2` (ECDSA P-256 / SHA-256) supported.
  `att_key_type = 3` (P-384 / SHA-384) deferred — the 3.2.4
  P-384 primitive is available so the delta is small when an
  integration surfaces. Audit doc INFO-1.
- PCK chain walk stays caller-driven — TDX shares the SGX
  Intel Root → PCK chain, so the same external-x509-walk
  pattern from 3.2.3 applies. PEM decoding rolls into the
  existing 3.2.3 follow-up.

### Security

- Audit: `docs/audit/2026-05-25-audit.md`. **0 findings at any
  severity** on the new ~290-line surface. Two new INFO items
  document the P-384 deferral and the chain-walk scope split
  (both consistent with prior bites' patterns).
- The quote-format-confusion defense (SGX vs TDX) is the
  load-bearing audit item — three independent header invariants
  enforced; an SGX quote cannot be mis-parsed as TDX or vice
  versa.

### Module wiring

- `src/lib.cyr` includes `src/tdx.cyr` after `src/sev_snp.cyr`.
- `cyrius.cyml [lib].modules` lists the new module.

## [3.2.4] — 2026-05-24

Fourth bite of the 3.2.x TEE attestation arc
([`docs/development/3.2-tee-arc.md`](docs/development/3.2-tee-arc.md)):
**AMD SEV-SNP attestation report verifier**. The largest bite of
the arc — SEV-SNP signs with ECDSA P-384 / SHA-384, neither of
which sigil had yet, so 3.2.4 lands the foundation for both
SEV-SNP (this bite) and TDX (3.2.5 — TDX's QE-signing path may
also use P-384).

The arc doc's tentative "slot P-384 between 3.2.5 and 3.2.6" note
is superseded: P-384 lands here as a proper foundation primitive.

### Added

- **`src/sha384.cyr` — FIPS 180-4 SHA-384 wrapper (~60 lines).**
  Reuses `sha512_transform` (already audited at 2.x); only the
  IV (FIPS 180-4 §5.3.4) and the output truncation to 48 bytes
  differ. Tested against FIPS 180-4 App. B.1 vectors (empty,
  "abc", 112-char) plus a streaming-update parity check.
- **`src/ecdsa_p384.cyr` — ECDSA verify on NIST P-384
  (~700 lines).** Structural mirror of `src/ecdsa_p256.cyr`
  at 384 bits — same shape (constants → BE codec → reduction
  → field arithmetic → scalar field → Jacobian point ops →
  Montgomery-ladder scalar mul → verify), 6-limb u384
  buffers replacing 4-limb u256. Includes a public
  `pt_p384_is_on_curve` helper that `ecdsa_p384_verify` calls
  unconditionally — same Bos-et-al-2014 invalid-curve defense
  as P-256. Long-division reduction; Solinas word-level
  optimisation rolls into the existing 3.2.1 bench-tuning
  follow-up.
- **`src/sev_snp.cyr` — AMD SEV-SNP attestation report parser +
  verify orchestrator (~280 lines).** Per AMD's SEV-SNP
  Firmware ABI Spec §7.3: fixed-1184-byte report with a 672-
  byte signed body + the signature section. `snp_report_parse`
  validates version=2 + signature_algo=1 (ECDSA P-384/SHA-384)
  + exact size. `snp_report_verify(report, vcek_pk)` reverses
  AMD's little-endian r/s padded-72-byte format into the
  big-endian r||s shape `ecdsa_p384_verify` expects, verifies
  the high 24 bytes of each are zero (defense in depth), then
  composes against `ecdsa_p384_verify` to validate the body
  signature. Field accessors for measurement (SHA-384 of guest
  launch state), mr_enclave equivalents, report_data, chip_id,
  etc. — everything kavach's `SnpAttestationReport` populates.
- **`tests/tcyr/sha384.tcyr`** — 4 FIPS 180-4 vectors green.
- **`tests/tcyr/ecdsa_p384.tcyr`** — 36 assertions across 8
  groups: field arithmetic, curve-equation self-check on G,
  2G against published SEC 2 reference, RFC 6979 §A.2.6
  vectors (`sample` and `test`), 8 negative cases (modified
  msg, flipped r/s bits, r/s=0, r/s=n, off-curve pk).
- **`tests/tcyr/sev_snp.tcyr`** — 29 assertions across 5 groups:
  parser happy path + 11 field-accessor checks, 6 malformed
  rejection cases, verify orchestrator green path, 6 tamper
  cases (VCEK / measurement / report_data / sig.r / sig.s /
  non-zero pad). Synthesized vector generated offline via the
  same openssl+Python helper pattern as 3.2.3.

### Scope decision

The ARK → ASK → VCEK X.509 chain walk stays caller-driven for
3.2.4, mirroring 3.2.3's "parser-only + per-piece verify"
choice. The caller fetches the VCEK chain from AMD KDS (typically
PEM-encoded) and walks it via the existing `x509_*` surface
before handing the validated VCEK pubkey to `snp_report_verify`.
PEM decoding + an integrated `snp_report_verify_full(report,
ark_root)` wrapper land in a future patch when a real-deployment
shape surfaces. See audit doc INFO-1.

### Security

- Audit: `docs/audit/2026-05-24-audit.md`. **0 CRITICAL / HIGH /
  MEDIUM** findings across ~1200 new lines (sha384 + ecdsa_p384
  + sev_snp). One new LOW (perm-lifetime allocation in
  `_snp_v_init` — consistent with 3.2.2's LOW-1 pattern, not
  exploitable). Four new INFO items documenting deferred scope,
  a Cyrius long-`main()` quirk hit during test development
  (worked around by splitting test helpers — see audit INFO-3),
  and field-reduction speed.
- CVE-2022-21449 (zero r/s), invalid-curve attack (Bos et al.),
  CVE-2020-0601 (curve param spoofing), and algorithm-confusion
  attacks all defended. See audit Step 9.

### Cyrius compiler note

Sigil tests with very long `main()` bodies (~150 lines of locals)
can trigger a Cyrius single-pass-compiler segfault at the first
nested-call site. Workaround: split test logic into helper
functions, keep `main()` short. Documented in audit INFO-3;
filed as a Cyrius-side issue for follow-up. Future sigil tests
should adopt the helper-split pattern from the start.

### Module wiring

- `src/lib.cyr` includes (in order): `sha384.cyr` after
  `sha512.cyr`, `ecdsa_p384.cyr` after `ecdsa_p256.cyr`,
  `sev_snp.cyr` after `sgx.cyr`.
- `cyrius.cyml [lib].modules` lists all three new modules.

## [3.2.3] — 2026-05-23

Third bite of the 3.2.x TEE attestation arc
([`docs/development/3.2-tee-arc.md`](docs/development/3.2-tee-arc.md)):
**Intel SGX DCAP v3 quote parser + verify orchestrator**. Composes
against the X.509 walker (3.2.2), the ECDSA P-256 verify (3.2.1),
and the existing SHA-256 surface to give kavach a parsed
`SgxQuote` struct + the three internal signature checks Intel's
attestation scheme defines.

### Scope decision

End-to-end signature verification against a real Intel-signed
quote is **deferred**. Intel's hardware-rooted signing chain
isn't reproducible locally, and a known-good redistributable
sample wasn't available in the repos at tag time. Sigil 3.2.3
ships:

- The full **parser** with field accessors — tested against a
  synthesized DCAP v3 quote.
- The verify **orchestrator** as a thin composition of
  `ecdsa_p256_verify` + `sha256` — tested against the
  synthesized quote with stand-in PCK and AK keypairs generated
  via openssl. Every internal signature check works against the
  synthesized chain; the *logic* is in tree and exercised.

The X.509 chain walk that ties the in-quote PCK cert to Intel's
SGX Root CA is the caller's responsibility for 3.2.3 — sigil
exposes `cert_data_ptr` / `cert_data_len` / `cert_data_type`
accessors. PEM decoding of the in-quote PCK chain lands in a
future patch when a real integration (kavach) surfaces the
forcing function. See audit doc INFO-1.

### Added

- **`src/sgx.cyr` — DCAP v3 quote parser + verify orchestrator
  (~370 lines).**
  - `sgx_quote_parse(buf, buf_len, out)` — single-pass linear
    walk of the Intel DCAP v3 binary format: 48-B header, 384-B
    enclave report, u32 signature_data_len, fixed-position
    signature section (ecdsa_sig 64 B / AK 64 B / qe_report
    384 B / qe_report_sig 64 B), u16-prefixed qe_auth_data,
    u16-type + u32-size qe_cert_data. Every length field
    bounds-checked against `buf_len` before any dereference.
    Rejects non-v3 versions, non-ECDSA-P256 attestation key
    types, trailing bytes inside the signature section, and any
    inner length that overflows the buffer.
  - `sgx_quote_verify_with_pck(quote, pck_pk)` — the three
    internal signature checks Intel's scheme defines:
      1. PCK signs the QE report (`ecdsa_p256_verify` against
         the raw 384-B qe_report under `pck_pk`).
      2. AK is bound to the QE: `qe_report.report_data[0:32]`
         == `SHA-256(AK_qx || AK_qy || qe_auth_data)`;
         `report_data[32:64]` strictly zero (defense in depth —
         see audit INFO-2).
      3. AK signs the quote body
         (`ecdsa_p256_verify` against `header || enclave_report`
         under the AK extracted from the quote).
  - Field accessors covering everything kavach's
    `SgxAttestationReport` populates: `mr_enclave_ptr`,
    `mr_signer_ptr`, `isv_prod_id`, `isv_svn`, `report_data_ptr`,
    `ak_ptr`, `qe_report_ptr`, `cert_data_ptr/_len/_type`.
- **`tests/tcyr/sgx.tcyr`** — 32 assertions across 5 groups:
  parser happy path + field accessors, 5 malformed-input
  rejection cases (truncated, empty, wrong version, wrong
  att_key_type, overflowing sig_data_len, overflowing
  auth_data_len), verify orchestrator green path, and 5 tamper
  cases (each of the three internal sig checks fails in turn
  plus mr_enclave and AK mutation). Vector generated offline
  via the openssl CLI from a Python helper kept out of tree
  (synthesized — the AK and PCK keypairs are test-only).

### Security

- Audit: `docs/audit/2026-05-23-audit.md`. **0 findings at any
  severity** on the new ~370-line surface. Two new INFO items
  document deliberate scope boundaries: the deferred PEM
  decode + full chain walk (INFO-1), and the strict zero-pad
  requirement on `report_data[32:64]` (INFO-2).
- The three sig-check chain in `sgx_quote_verify_with_pck`
  defends against the standard quote forgery scenarios — see
  audit Step 9. An attacker forging a quote needs to break
  either ECDSA P-256 or SHA-256.

### Module wiring

- `src/lib.cyr` includes `src/sgx.cyr` after `src/x509.cyr`.
- `cyrius.cyml [lib].modules` lists the new module so
  `cyrius distlib` bundles it into `dist/sigil.cyr`.

## [3.2.2] — 2026-05-22

Second bite of the 3.2.x TEE attestation arc
([`docs/development/3.2-tee-arc.md`](docs/development/3.2-tee-arc.md)):
**minimal X.509 cert-chain walker**. The DER parsing substrate
SGX (3.2.3), SEV-SNP (3.2.4), and TDX (3.2.5) need. This is the
highest-risk parser yet added to sigil — it consumes attacker-
controlled DER from remote quoting enclaves and firmware — so
the audit (`docs/audit/2026-05-22-audit.md`) is the load-bearing
artifact of this tag.

### Added

- **`src/x509.cyr` — minimal X.509 parser + chain walker
  (~720 lines).** Just enough X.509 to walk SGX / SEV-SNP
  attestation chains:
  - `x509_parse(der, der_len, out_cert)` — single-pass walk of
    `Certificate ::= SEQUENCE { TBSCertificate,
    signatureAlgorithm, signature }`. Validates v3, ecdsa-with-
    SHA256 (both the inner TBS.signature and outer
    signatureAlgorithm), id-ecPublicKey + prime256v1
    parameters, on-curve subject public key (calls
    `pt_is_on_curve` — closes audit 2026-05-21 LOW-1),
    basicConstraints, and the SHA-256-of-TBS / r||s signature
    layout. Returns `1` on success, `0` on any malformed or
    unsupported input.
  - `x509_verify_chain(leaf, intermediates, intermediates_len,
    root, now_unix)` — walks root → intermediates → leaf. For
    each non-root link: re-hashes the child's TBS bytes and
    verifies the signature against the issuer's pubkey via
    `ecdsa_p256_verify`; checks issuer/subject DN byte-equality;
    checks the child's validity window against `now_unix`
    (passing `now_unix == 0` disables the time check for hosts
    with untrusted wall-clocks). Intermediates must have the
    CA basicConstraints bit set.
  - `der_walk(buf, buf_len, pos, tag, &content_pos, &next_pos)`
    — bounds-checked TLV cursor that every higher-level parse
    step goes through. Long-form lengths capped at 4 bytes,
    indefinite-length form (`0x80`) rejected, content offset
    + length bounds-checked against the buffer before any
    dereference.
  - ASN.1 time decoders (`_x509_parse_utctime`,
    `_x509_parse_gentime`) — UTCTime year-window per RFC 5280
    (`00..49` → 20xx, `50..99` → 19xx, but pre-1970 rejected
    since epoch math starts there), strict 13/15-byte format,
    trailing `Z` required, day-in-month validated against the
    year's leap status.
- **`pt_is_on_curve(x, y)` in `src/ecdsa_p256.cyr`** — affine
  curve-equation check `y² ≡ x³ - 3x + b (mod p)` plus
  in-field-range and not-(0,0) gates. Now invoked
  unconditionally by `ecdsa_p256_verify` (3.2.1's verify path
  was internally consistent for trusted keys; 3.2.2 closes the
  external-pubkey gap before the X.509 surface ships).
- **`tests/tcyr/x509.tcyr`** — 35 assertions across 8 groups:
  DER primitive walker (tag/length/bounds), ASN.1 time decode
  (UTCTime + GeneralizedTime + 4 rejection cases), parse of
  openssl-generated root + leaf certs, full chain verify green
  path, 6 negative cases (now < notBefore, now > notAfter,
  flipped TBS byte, DN mismatch, empty input, truncated input,
  wrong outer tag).

### Security

- Audit: `docs/audit/2026-05-22-audit.md`. **0 CRITICAL / HIGH /
  MEDIUM** on the new ~720-line surface. **LOW-1 from
  2026-05-21 is closed** by the on-curve check landing in
  `pt_is_on_curve` and being called from both
  `ecdsa_p256_verify` and `_xp_parse_spki`. One new LOW
  (perm-lifetime allocation in `x509_parse` — bump-allocator
  shape, not exploitable, deferred to a `_into` variant when
  the kavach backend surfaces a forcing function). Two new
  INFO items: deliberate minimum-length-encoding laxity, and
  byte-equality DN matching (correct for SGX/SEV/TDX chains,
  flagged for any future interop with human-administered CAs).
- CVE pattern check: CVE-2008-5077 (ASN.1 length confusion),
  CVE-2014-1568 (BER padding forgery), CVE-2009-2409
  (algorithm confusion via MD2), CVE-2022-3602/3786 (name-
  constraint overflow), Frankencerts-style algorithm
  substitution, and invalid-curve attack (Bos et al. 2014) all
  covered. See audit Step 9.

### Module wiring

- `src/lib.cyr` includes `src/x509.cyr` after `src/ecdsa_p256.cyr`.
- `cyrius.cyml [lib].modules` lists the new module so
  `cyrius distlib` bundles it into `dist/sigil.cyr`.

## [3.2.1] — 2026-05-21

First bite of the 3.2.x TEE attestation arc
([`docs/development/3.2-tee-arc.md`](docs/development/3.2-tee-arc.md)):
**ECDSA verify on NIST P-256**. The foundation primitive for the
SGX (3.2.3), SEV-SNP (3.2.4), and TDX (3.2.5) quote verifiers
that follow.

### Added

- **`src/ecdsa_p256.cyr` — ECDSA P-256 verify
  (`ecdsa_p256_verify(pk, msg, msg_len, sig)`).** ~680 lines
  implementing the full SEC 1 v2.0 §4.1.4 / FIPS 186-5 §6.4.2
  verify pipeline:
  - P-256 field arithmetic mod
    `p = 2^256 − 2^224 + 2^192 + 2^96 − 1` (`fp_p256_add`,
    `fp_p256_sub`, `fp_p256_neg`, `fp_p256_mul`, `fp_p256_sq`,
    `fp_p256_inv`).
  - Scalar arithmetic mod the group order `n` (`fn_p256_mul`,
    `fn_p256_inv`).
  - Jacobian point operations on `y² = x³ − 3x + b`
    (`pt_double`, `pt_add`, `pt_from_affine`, `pt_to_affine`)
    using the EFD `dbl-2001-b` and `add-2007-bl` formulas
    (4M+4S double, 12M+4S add).
  - Constant-time scalar multiplication via Montgomery ladder
    (`pt_scalarmul`) with `pt_cswap` for branchless point
    swap. Ladder lives even though verify takes only public
    inputs — defense in depth for any future sign / DH caller
    composing against the same primitive.
  - Field reduction via textbook long-division (256 iterations
    of shl1 + conditional subtract). Slow but easy to audit;
    Solinas word-level reduction queued as a bench-tuning
    follow-up (see `docs/audit/2026-05-21-audit.md` INFO-2).
- **`ecdsa_p256_verify_der(pk, msg, msg_len, sig_der, sig_der_len)`
  — DER-wrapped signature decoder.** Strict-enough X.509 /
  RFC 5480 shape: outer `SEQUENCE`, two `INTEGER`s, short-form
  length only, optional 33-byte leading-`0x00` sign byte
  tolerated. Every offset/length is bounds-checked against
  `sig_der_len` before dereference.
- **Big-endian byte ⇄ u256 codec (`u256_load_be` / `u256_store_be`).**
  SEC 1 §2.3.5 encodes integers MSB-first; ed25519's
  little-endian helpers were not reusable.
- **`tests/tcyr/ecdsa_p256.tcyr`** — 49 assertions across 9
  groups: BE codec roundtrip, `p256_reduce` corner cases,
  field arithmetic, the curve-equation self-check
  (`gy² ≡ gx³ − 3gx + b`), point arithmetic vs. published 2G
  vector, ECDSA verify against both RFC 6979 §A.2.5 vectors
  (`sample` / `test` messages), six negative-case rejections
  (modified msg, flipped r/s bits, r=0, s=0, r=n, s=n), and
  the DER wrapper.
- **`tests/bcyr/ecdsa_p256.bcyr`** — verify bench (single row
  `ecdsa_p256_verify`).

### Perf

- `ecdsa_p256_verify` measured at **136.283 ms** on the dev host
  (RFC 6979 sample-msg, 15 iters, cyrius 6.0.1). Recorded in
  `benches/history.csv` as `v3.2.1,ecdsa_p256_verify`. Slower
  than `ed25519_verify` (~6.4 ms) — the gap is the bit-by-bit
  field reduction. Solinas word-level reduction is the obvious
  follow-up; tracked in `docs/development/roadmap.md` "Backlog
  — unscheduled" until a downstream surfaces a forcing
  function.

### Security

- Security audit: `docs/audit/2026-05-21-audit.md`. Zero
  CRITICAL / HIGH / MEDIUM findings on the new surface. Two
  LOW findings tracked:
  - **LOW-1** — Q-on-curve check deferred to the TEE bites
    that consume external-channel public keys (3.2.3–3.2.5).
  - **LOW-2** — DER decoder tolerates non-strict 33-byte int
    encodings; defense-in-depth, no exploitable consequence
    in sigil's API surface.
- Constant-time discipline maintained for the scalar-mul
  primitive even though verify inputs are public — preserves
  the "no timing side-channels on any future secret-data
  caller" invariant.

### Module wiring

- `src/lib.cyr` includes `src/ecdsa_p256.cyr` after
  `src/ed25519.cyr`.
- `cyrius.cyml [lib].modules` lists the new module so
  `cyrius distlib` bundles it into `dist/sigil.cyr`.

## [3.2.0] — 2026-05-21

The 3.2.0 batch tracker lives in
[`docs/development/3.2-scope.md`](docs/development/3.2-scope.md).
All four batch items landed: NI self-test gate, alloc-free
verify hot path, `cyrlint` cleanup + CI gate, and the downstream
re-test sweep. `secret var` ambient adoption stays as a
ship-when-touched item, not blocking the tag.

### Added

- **Alloc-free verify hot path
  (`sv_verify_artifact_into(sv, path, type, scratch)` +
  `VerifyScratch`).** The 3.0 batch-verify path serialised the
  full `sv_verify_artifact` call inside `_sigil_batch_mutex`
  because the body hit `alloc` / `fl_alloc` / `vec_new` /
  `vec_push`-grow ~10× per artifact — none thread-safe under
  cyrius (CLAUDE.md quirk #7). Measured under cyrius 5.7.48:
  0.96x–1.04x vs serial (no win).

  3.2.0 introduces a 768-byte `VerifyScratch` block that holds
  every per-artifact intermediate inline: hash hex buffer (72 B),
  decoded Ed25519 public-key bytes (40 B), `TrustedArtifact`
  (48 B), `VerificationResult` (32 B), 8-slot `TrustCheck` pool
  (192 B), pre-allocated cap-16 vec header + data (152 B), and
  a SHA-256 streaming context (144 B). Workers receive a
  per-artifact slot; the entire orchestrator (`hash_file_into`,
  `hex_decode_into`, `_vresult_add_check_scratch`,
  `sha256_init_into`) writes into the scratch without touching
  any global allocator. `sv_verify_batch` pre-allocates one
  contiguous `count * 768`-byte pool on the main thread before
  spawn; per-batch allocator activity drops from ~`10 * count`
  fl_allocs to **one** alloc.

  Public API preserved: `sv_verify_artifact(sv, path, type)`
  still allocates an internal scratch and returns the vr
  pointer with the same accessor surface (`vresult_passed`,
  `vresult_checks`, `vresult_artifact`, `vec_len(checks)`,
  `check_name/passed/detail`). New helpers added alongside the
  existing fns: `hex_decode_into`, `hash_file_into`,
  `sha256_init_into`, `verify_scratch_new`.

  **The mutex stays — and here is the honest part.** While the
  alloc-free worker body removes the allocator-race surface,
  the crypto modules themselves use **module-level globals**
  for working state (`_sha_ctx`, `_sha_a..h`, `_sha_t1/t2`,
  `_sha_i`, `_sha256_W` in `sha256.cyr`; equivalent globals in
  `ed25519.cyr`, `aes_gcm.cyr`). This is the cyrius local-
  clobbering workaround documented in CLAUDE.md quirk #1.
  Concurrent workers running `sha256_transform` race on those
  globals and produce corrupted digests, which fail signature
  verify and surface as wrong-trust-level results. Verified
  experimentally during 3.2.0 dev: dropping the mutex made
  30/228 `batch_parallel.tcyr` assertions fail (parallel
  results diverged from serial). Mutex-on → 228/228 pass.

  Bench on the dev host (cyrius 6.0.1, 4-worker pool):
  `sv_verify_batch_64` 423 ms = ~6.6 ms/artifact, essentially
  identical to the per-artifact `sv_verify_batch_1` 6.7 ms.
  Same throughput as 3.0's mutex-wrap. Recorded in
  `benches/history.csv` under label `v3.2.0-allocfree`.

  **What 3.2.0 actually delivers:** ~10× lower allocator
  churn per batch, ~768-byte amortised per-artifact memory
  footprint vs the 3.0 path's scattered fl_allocs, and a
  cleaner foundation. Parallel-throughput target slips to
  **3.3** pending the crypto-modules-as-per-call-scratch
  rewrite (see `docs/development/roadmap.md` § "Towards
  v3.3"). The honest reframing of the original 3.1 "Option 1"
  scope: half the work landed in 3.2.0; the other half
  (per-worker crypto state) requires moving working state out
  of module globals in `sha256.cyr` / `ed25519.cyr` /
  `aes_gcm.cyr` plus a cyrius local-clobbering audit at every
  call site that currently relies on globals.

  **Deprecation note (4.0 target):** the heap-allocating
  `verification_result_new` / `trusted_artifact_new` /
  `trust_check_new` constructors stay in tree for backward
  compatibility but are no longer the canonical
  construction path. 4.0 removes them in favour of inline
  scratch-slot writes.

- **`cyrlint` cleanup + CI gate.** Cyrlint baseline against
  `src/*.cyr` under cyrius 6.0.1 surfaced 11 warnings (down
  from 35 under 2.9.5's 5.7.x cyrlint). Closed 9 of them in
  the 3.2.0 ship: 7 box-drawing-character lines in
  `src/sha_ni.cyr` replaced with ASCII separators (the unicode
  chars were 3 bytes each — visually 69 chars but physically
  159 bytes, tripping the >120-char rule); 2
  multiple-consecutive-blank-line warnings in `src/trust.cyr`
  and `src/verify.cyr` trimmed. The 2 surviving warnings
  (`src/aes_gcm.cyr` `_aes_sbox_hex` 512-char FIPS 197 S-box;
  `src/mldsa_ntt.cyr` `_mldsa_zetas_hex` 2048-char NTT zetas)
  are indivisible data-table literals — exempted via a narrow
  rule in the CI workflow's `lint:` job that allows line-
  length warnings from those two files only; any other
  warning class still fails the gate.

  Added the `lint:` job to `.github/workflows/ci.yml`,
  matching the agnosys / yukti `cyrlint` gate pattern.

- **NI self-test gate (`aes_ni_self_test` /
  `sha_ni_self_test`).** `aes_ni_available()` and
  `sha_ni_available()` now require BOTH a positive CPUID probe
  AND a known-vector self-test pass before the cache pins to 1.
  On mismatch the cache pins to 0 and sigil silently falls
  through to the software path. Catches the class of bug
  documented in [`docs/development/issues/2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md`](docs/development/issues/2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md)
  — hardcoded `[rbp-N]` parameter loads in the NI asm blocks
  coupling to a cyrius prologue layout that drifts across
  toolchain versions. Production traffic never goes live on a
  broken NI dispatcher; the worst case is a silent perf regression
  to the software path. Vectors used:
  - AES-NI: FIPS 197 §C.3 — key `00..1F`, plaintext
    `00112233445566778899AABBCCDDEEFF` →
    `8EA2B7CA516745BFEAFC49904B496089`.
  - SHA-NI: FIPS 180-4 §B.1 — `"abc"` →
    `BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD`.

  Constant-time OR-accumulating compare (no early exit) on both
  vectors. Self-test runs ONCE per process at first
  `aes_ni_available()` / `sha_ni_available()` call; subsequent
  calls return the cached result with zero overhead.

  Coverage: `tests/tcyr/aes_ni.tcyr` 5/5 (was 4/4) and
  `tests/tcyr/sha_ni.tcyr` 13/13 (was 12/12) — each gains a
  `<module> self-test gate` group that asserts the direct self-
  test fn returns 0 on AES-NI / SHA-NI hosts.

  Benchmark on the dev host (Intel x86_64, cyrius 6.0.1):
  `aes256_encrypt_block` 20 ns avg, `sha256_1kb_ni` 2 µs avg,
  `sha256_64kb_ni` 164 µs avg, `aes_gcm_encrypt_1kb` 731 µs avg —
  all within noise vs the 3.1.2 numbers. Self-test cost is one-
  time at startup; per-call hot path is unchanged. Recorded in
  `benches/history.csv` under label `v3.2.0-ni-selftest`.

  **What this does NOT catch:** the SIGILL failure mode (asm
  reads an unmapped pointer from a mis-spilled `[rbp-N]` slot).
  Catching SIGILL needs cyrius signal-handling, which doesn't
  exist. The structural fix — migrating the NI asm blocks off
  hardcoded `[rbp-N]` byte literals entirely — is blocked on
  cyrius shipping an asm-block global-symbol pseudo, requested
  upstream in
  [`cyrius/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md).
  See the issue file for the migration plan once that pseudo
  lands.

## [3.1.2] — 2026-05-21

### Changed

- **Cyrius toolchain bumped 5.11.4 → 6.0.1.** Picks up cycc 6.x
  (UEFI fn-call UD2 emit fix, two stdlib-resolution path bugs
  resolved). `cyrius.cyml` `cyrius` pin and CI's
  `CYRIUS_VERSION` env both moved together so build and CI
  agree on a single toolchain.
- **`sakshi` pin 2.2.3 → 2.2.5.** Picks up sakshi's own
  cyrius-6.0.1 toolchain bump and CI/release repairs. No
  sakshi surface change consumed by sigil.
- **`agnosys` pin 1.0.4 → 1.2.7.** Picks up agnosys's
  multi-profile distlib (core / security / storage / trust /
  system) plus the cycc 6.0.1 language-annotation pass. Sigil
  continues to consume the full `dist/agnosys.cyr` bundle —
  the multi-profile split is forward-compatible.

### Added

- `slice` added to `[deps] stdlib` in `cyrius.cyml`, and
  `include "lib/slice.cyr"` added to `src/lib.cyr`. Required
  because agnosys 1.2.7's bundled dist now uses first-class
  `slice<T>` / `[T]` subscripts (cycc 5.8.10+), which expand
  to `_slice_idx_get_W` helpers defined only in
  `lib/slice.cyr`. Without it the smoke build fails with
  `slice subscript requires include "lib/slice.cyr" : undef`
  at `lib/agnosys.cyr:5434`.

### Notes

- `cyrius.lock` is maintained by hand for the two non-stdlib
  bundles (`lib/sakshi.cyr`, `lib/agnosys.cyr`). Cyrius 6.0.1
  inherits the v5.11.8 file-copy-not-symlink dep strategy but
  `cmd_deps_lock` in `cbt/deps.cyr` still gates on `readlink`,
  so `cyrius deps` writes an empty lockfile on every run.
  Same workaround used by yukti; agnosys side-steps it by
  `.gitignore`-ing `lib/` entirely (sigil already does too —
  the lockfile is the only on-disk record of resolved dep
  hashes here). Treat as a known cyrius bug, not a sigil
  regression.
- `dist/sigil.cyr` regenerated via `cyrius distlib` at v3.1.2
  (8893 lines, unchanged).

## [3.1.1] — 2026-05-11

### Changed

- **Stdlib annotation pass**: every public fn in `src/*.cyr`
  carries a `: i64` return-type annotation. Mechanical pass
  matching cyrius's v5.11.x annotation arc; parse-only, zero
  runtime / codegen change.
- `cyrius` pin bumped 5.9.20 → 5.11.4 — required for `: i64`
  return-type syntax (v5.10.x REAL TYPE SYSTEM).
- `dist/sigil.cyr` regenerated via `cyrius distlib` at v3.1.1
  (8893 lines). Ready for next cyrius-side fold-in slot.

## [3.1.0] — 2026-05-06

**Version-label correction for the 3.0.2 surface change.** 3.0.2
removed `src/ct.cyr` and with it the public symbols `ct_eq` and
`ct_eq_32` from `dist/sigil.cyr`, and was tagged as a patch. That
was the wrong label — removing public symbols is a minor bump,
not a patch. 3.1.0 retags the same content with the correct
SemVer level. No code change relative to 3.0.2.

### Changed

- VERSION 3.0.2 → 3.1.0.
- `cyrius.cyml` `version` 3.0.2 → 3.1.0.

## [3.0.2] — 2026-05-06

**ct_eq retired in favor of cyrius stdlib `ct_eq_bytes_lens`**.
Paired with cyrius v5.9.20's lift of the canonical XOR-accumulate
into `lib/ct.cyr`. Patch release — no sigil API change; internal
refactor only.

### Changed

- `cyrius` pin bumped 5.8.64 → 5.9.20 (required for the new
  `ct_eq_bytes_lens` symbol).
- All five internal `ct_eq` call sites migrated to
  `ct_eq_bytes_lens` (one identifier rename, identical semantics):
  `src/integrity.cyr` (×2 — file hash compares), `src/aes_gcm.cyr`
  (poly1305 tag verify), `src/ed25519.cyr` (signature R-component
  compare), `src/verify.cyr` (artifact hash compare).
- `src/aes_gcm.cyr` doc comment refreshed to name the upstream
  helper.

### Removed

- **`src/ct.cyr`**: the file that defined sigil's hand-rolled
  `ct_eq(a, a_len, b, b_len)` and `ct_eq_32(a, b)`. Both are gone.
  `ct_eq_32` had zero internal call sites; consumers wanting a
  32-byte fixed compare can write `ct_eq_bytes(a, b, 32)` against
  the upstream stdlib (cyrius v5.9.18+).
- `cyrius.cyml [lib].modules`: dropped `"src/ct.cyr"`.
- `src/lib.cyr`: dropped `include "src/ct.cyr"`. Replaced with a
  comment crumb pointing at the migration.

### Verified

- All sigil tcyr tests touching the migrated paths still pass:
  `aes_gcm.tcyr` (15/15), `ed25519.tcyr` (20/20),
  `verify.tcyr` (48/48).
- `cyrius distlib` rebuilds `dist/sigil.cyr` cleanly (8893 lines,
  316 KB; pre-3.0.2 dist excluded the now-deleted `src/ct.cyr`'s
  ~30 LOC). No `ct_eq` symbol present in the bundle.

### Upstream context

agnosys 1.1.2 filed the gap at cyrius v5.9.14 ship
(`agnosys/docs/development/issues/2026-05-06-cyrius-ct-eq-bytes-stdlib.md`).
cyrius v5.9.18 added the single-length `ct_eq_bytes(a, b, n)`
core; cyrius v5.9.20 added the dual-length companion + this
sigil patch retires the duplication. Three downstream sites
collapse to one stdlib helper.

## [3.0.1] — 2026-05-05

### Changed

- `cyrius` pin bumped 5.7.48 → 5.8.64 ahead of the cyrius v5.8.65
  stdlib foldin. Sigil is on the foldin manifest; this patch is
  the prerequisite for cyrius's `[deps].sigil.tag` to point at
  3.0.1 in the foldin slot.
- `[deps.sakshi].tag` bumped 2.0.0 → 2.2.3 (latest).
  `[deps.agnosys]` stays at 1.0.4 (transitive via mabda which
  holds at 2.5.0; not on the v5.8.65 foldin manifest).
- No source changes — pure pin + version bump.

### Verified

- `cyrius test`: **76 + 24 = 100** asserts pass against cyrius
  5.8.64 with sakshi 2.2.3 resolved.
- `cyrius fmt --check`: clean across all source.
- `dist/sigil.cyr` rebuilt at 8916 lines.

## [3.0.0] — 2026-05-01

**The 3.0 line lands.** Closes the 2.x cycle's accumulated
breaking-change cleanups and ships parallel batch verify
infrastructure as the foundation for the 3.1 throughput rewrite.
The 2.9.2..2.9.5 work that landed on `main` during the 3.0 branch's
development (SHA-NI hot path, AES-NI activation, agnosys 1.0.4
aarch64 portability, the `[lib].modules` manifest fix) is folded
into this release via the 2026-05-01 merge.

Migration notes for downstream consumers (daimon, kavach, ark,
aegis, phylax, mela, stiva, argonaut, takumi):

- **`TRUST_COMMUNITY` enum variant removed.** Numeric slot 2 is
  intentionally unassigned so any persisted state keyed on values
  3/4 round-trips identically pre/post-3.0. Consumers who were
  using `TRUST_COMMUNITY` (audit found one inactive reference, an
  argonaut vendored bundle frozen at sigil v2.0.1) should pick
  `TRUST_VERIFIED` or define their own enum value outside sigil's
  type.
- **`alog_append_to_file` → `alog_save`** and
  **`alog_load_from_file` → `alog_load`.** Pure rename to align
  with the `rl_save` / `crl_save` / `sv_save_trust_store`
  vocabulary. No behaviour change. Module-header migration notes
  retained in `src/audit.cyr` for one cycle.
- **`-D SIGIL_BATCH_PARALLEL` cmdline flag removed.** The parallel
  path is now the default behaviour at
  `count >= _SIGIL_BATCH_PARALLEL_THRESHOLD` (= 4). Consumers who
  were passing the flag should remove it; the build will still
  succeed but the flag is a no-op.
- **Cyrius minimum pin: 5.7.48.** The 5.5.x and 5.6.x lines are
  no longer supported. Consumers tracking sigil HEAD should bump
  their own toolchain pins to match.

Security: a fresh internal audit
(`docs/audit/2026-05-01-audit.md`) re-verified all 12 findings
from the 2026-04-13 v2.0.1 audit as fixed and surveyed every
crypto module added during the 2.x → 3.0 cycle. Zero
CRITICAL/HIGH findings; one MEDIUM (thread-safety on module-global
crypto scratch — currently mitigated by the parallel-batch mutex,
slated for the 3.1 alloc-free rewrite); two LOW; three INFO.

### Added

- **Parallel `sv_verify_batch`**, default-on at
  `count >= _SIGIL_BATCH_PARALLEL_THRESHOLD` (= 4). Ships the
  worker-pool spawn/join/shard machinery, a 4-worker default pool,
  the threshold-gated serial fast path for small counts, and a
  shared `_sigil_batch_mutex` that serialises `sv_verify_artifact`
  calls across workers. Correctness is identical to the serial
  path (228/228 tests in `tests/tcyr/batch_parallel.tcyr`, sizes
  0/1/4/32, mixed signed/unknown/revoked, determinism across
  repeat runs). **No throughput win in 3.0** — measured
  0.96×–1.04× vs serial because the mutex wraps the full
  `sv_verify_artifact` call, including the dominant `ed25519_verify`
  (~6.4 ms/artifact under SHA-NI). Actual speedup defers to 3.1's
  alloc-free verify-hot-path rewrite (tracked in
  `docs/development/roadmap.md` § Road to v3.1).
- **`tests/tcyr/batch_parallel.tcyr`** (228 assertions) —
  correctness guard for `sv_verify_batch` asserting the batch
  result matches a serial reference run per-artifact (passed,
  trust_level, content hash) across mixed-archetype inputs; plus
  determinism across repeat calls.
- **`tests/bcyr/batch_parallel.bcyr`** — scaling-curve benchmark
  for `sv_verify_batch` at counts 1/4/16/64. Separate from
  `tests/bcyr/sigil.bcyr` because the full sigil+mldsa+verify
  include set hits the 1 MB preprocessor cap (CLAUDE.md quirk #8).

### Changed

- **`src/lib.cyr`** unconditionally `include`s `lib/thread.cyr`.
  The 5.5.x-era `#ifdef SIGIL_BATCH_PARALLEL` gate around the
  threading include is gone; the cyrius 16384 fixup-table cap
  was raised in 5.5.37 (per
  `docs/development/issues/archive/2026-04-22-cyrius-fixup-cap-raises.md`,
  now resolved) and 5.7.48 builds clean with the threading
  primitives always pulled in. The `-D SIGIL_BATCH_PARALLEL`
  cmdline opt-in is removed in this release — the parallel path
  is the default behaviour.
- **`src/verify.cyr`** parallel-fan-out body and `_batch_worker`
  fn / `_sigil_batch_mutex` globals are no longer wrapped in
  `#ifdef SIGIL_BATCH_PARALLEL`.
- **Cyrius pin** → `5.7.48` (was `5.5.30` on `main` pre-merge,
  through 5.5.32 / 5.5.35 during 3.0 bring-up). Pin is the
  minimum-compatible floor; active toolchain dispatches to whatever
  `cyriusly current` reports.
- **Sub-3.0 breaking changes:** `TRUST_COMMUNITY` enum variant
  removed (numeric slot 2 intentionally unassigned for
  persisted-state compatibility); `alog_append_to_file` →
  `alog_save`, `alog_load_from_file` → `alog_load` (vocabulary
  alignment with `rl_save` / `crl_save` / `sv_save_trust_store`).

### Known limitations

- **Parallel batch verify is correctness-only in 3.0.** Workers
  serialise on the full-call mutex because `sv_verify_artifact`'s
  downstream chain hits cyrius's non-thread-safe `alloc` /
  `vec_push` / `map_get` (CLAUDE.md quirk #7). The infrastructure
  is in place; throughput wins land in 3.1 once
  `sv_verify_artifact` is rewritten to accept caller-provided
  scratch.

### Merged from `main` (2026-05-01)

- 2.9.2 → 2.9.5 picked up via `git merge main`. SHA-NI probe +
  compress (2.9.2/2.9.3), build-output rename (2.9.4), cyrius
  5.7.48 + agnosys 1.0.4 toolchain bump (2.9.5). Cyrius pin on
  the 3.0 branch advances `5.5.35` → `5.7.48`. Conflicts: cyrius
  pin in `cyrius.cyml`, CI `CYRIUS_VERSION`, and CHANGELOG
  Unreleased section — all resolved in favour of main's modern
  toolchain. The 3.0 scope tracker's "cyrius pin" note is now
  superseded; current dispatch is 5.7.48.
- **Material code merges, no conflict:** SHA-NI module
  (`src/sha_ni.cyr`) added to 3.0 from main; `[lib].modules`
  manifest header fix; per-arch agnosys 1.0.4 syscall wrappers;
  18 src/test files reformatted for 5.7.x continuation-indent
  rule; `src/sha256.cyr` now `include`s `src/sha_ni.cyr`
  directly per the dispatch contract.

## [2.9.5] — 2026-04-30

**Toolchain + dep refresh: cyrius 5.6.42 → 5.7.48, agnosys
1.0.3 → 1.0.4, plus a structural fix to `cyrius.cyml` that
unblocks 5.7.x's auto-deps prepend.** The agnosys bump pulls
in the aarch64 portability sweep landed in agnosys 1.0.4
(per-arch `src/syscall_*_linux.cyr` peer files; raw-syscall
migration to `sys_*` wrappers). Sigil itself remains a
crypto + trust library; no API change.

### Fixed

- **`[lib].modules` section header** added to `cyrius.cyml`.
  Pre-fix the `modules = [...]` table sat directly under
  `[build]` (whose preceding line was `defines = [...]`), so
  TOML scoped it as `[build].modules`. Cyrius 5.7.x treats
  `[build].modules` as an auto-prepend list — every src/ file
  was inlined into the temp before the entry source, then
  `src/lib.cyr`'s explicit `include` directives pulled them
  in a second time. Result on 5.7.48: 374 `duplicate fn`
  warnings on every `cyrius build` (374 = total fn count
  across the library, since every fn was redefined). The
  byte-identical fix is a one-line `[lib]` section header
  before `modules = [...]`. This is the same lesson agnosys
  learned at 1.0.1 ("76% binary size reduction"); sigil's
  manifest layout pre-dates it. With the fix, the duplicate
  count drops to **0**.
- **`src/sha256.cyr` now `include "src/sha_ni.cyr"`.**
  `sha256_transform()` dispatches via `sha_ni_available()`
  / `sha256_transform_ni()` (the SHA-NI hardware path landed
  in 2.9.3); previously the dispatch infrastructure came in
  via `src/lib.cyr`'s explicit list OR via the pre-fix
  auto-prepend. With auto-prepend disabled and individual
  test files pulling in only `src/sha256.cyr` (not the full
  `src/lib.cyr`), the dispatch-target functions resolved as
  `error: undefined function 'sha_ni_available' (will crash
  at runtime)` and the hash_data tests aborted partway.
  Pulling sha_ni in directly from sha256.cyr matches the
  module's documented dispatch contract and restores the
  individual test harnesses.

### Changed

- **`cyrius.cyml [package].cyrius`** pinned `5.6.42` →
  `5.7.48`. Catches up across the 5.7.x cycle's syscall
  portability narrative (per-arch table dispatch, `sys_*`
  wrappers, `_SC_ARITY` arity checks) and the late
  refactor-pass / advanced-TS work.
- **`cyrius.cyml [deps.agnosys]`** tag `1.0.3` → `1.0.4`.
  agnosys 1.0.4 ships per-arch peer files self-gated with
  `#ifdef CYRIUS_ARCH_X86 / AARCH64` so the sigil-bundled
  `lib/agnosys.cyr` carries both arch's syscall surfaces;
  sigil consumers (phylax 1.1.x next) pick the arch-correct
  path from their own predefines.
- **`.github/workflows/ci.yml`** env `CYRIUS_VERSION` bumped
  `5.6.42` → `5.7.48` so CI installs the matching toolchain.
- **`VERSION`** + **`cyrius.cyml [package].version`** bumped
  `2.9.4` → `2.9.5`.
- **18 src/* and tests/tcyr/* files reformatted** for the
  cyrius 5.7.x continuation-line indent rule. No semantic
  change; `cyrius fmt --check` was a no-op against the 5.6.42
  rule and would have diff'd against the new rule on first
  5.7.48 run.

### Verified

- `CYRIUS_DCE=1 cyrius build programs/smoke.cyr build/sigil`
  (x86_64) — clean, **0 duplicate-fn warnings** (was 374
  pre-fix).
- `cyrius build --aarch64 programs/smoke.cyr build/sigil-aarch64`
  — produces a well-formed `ELF 64-bit LSB executable, ARM
  aarch64`. 11 `syscall arity mismatch` warnings remain; 9
  are pre-existing cc5_aarch64 false-positives in
  `lib/syscalls_aarch64_linux.cyr`'s at-family wrappers
  (reproducible against a 4-line empty cyrius program; see
  cyrius CHANGELOG `_SC_ARITY` entries for prior fixes in
  the same family). The remaining 2 are likely the same
  class hitting sigil-side calls; tracked as a cyrius-side
  hygiene item, does not block this release.
- **23 test files / 617 assertions pass** (was a pre-fix
  state of 5 files crashing partway after the auto-prepend
  was disabled — `crypto.tcyr`, `hkdf.tcyr`, `security.tcyr`,
  `sigil.tcyr`, `verify.tcyr` aborted at the first
  `hash_data()` call site). All restored once
  `src/sha256.cyr` started pulling in the SHA-NI dispatch.
- `cyrius bench tests/bcyr/*.bcyr` — all benches run; no
  regressions vs 2.9.4 baseline (mldsa65_sign 4.91ms,
  mldsa65_verify 2.23ms, hkdf_extract 1µs).
- `cyrius distlib` — `dist/sigil.cyr` regenerated at
  **8781 lines (v2.9.5)**.
- 3 fuzz harnesses build + survive 100-iteration runs:
  `fuzz_ed25519`, `fuzz_integrity`, `fuzz_revocation`.
- Security scan: clean.

### Notes — pre-existing lint warnings surface on 5.7.x

Cyrius 5.7.x's `cyrlint` adds checks for line length (>120
chars), forward-referencing global var initializers, and
fn naming conventions in test harnesses; the existing 2.9.4
tree has 35 such warnings (long-line style + a benign
`var jsonl` / `var buf` / `var c` conflation in
`src/policy.cyr` where `cyrlint` mistakes function-local
vars for globals because two `fn`s in the same file share
local-var names). Sigil's CI does not gate on `cyrlint` (the
workflow has no Lint step), so these don't block the release.
Will be batched into a follow-up cleanup pass that also
considers wiring fmt/lint gates into the workflow to match
agnosys's pattern.

## [2.9.4] — 2026-04-27

### Changed — Build output renamed to align with package convention

- **`[build].output`**: `build/sigil-smoke` → `build/sigil`. The
  smoke-test program (still defined with `SIGIL_SMOKE`, still entry-pointed
  at `programs/smoke.cyr`) is now produced at the canonical
  `build/<package>` path that the genesis boot pipeline's
  `--iso-check` expects. Unblocks ISO assembly (sigil was the lone
  miss in an otherwise 25-of-26-ready boot chain).
- **`dist/sigil.cyr`** regenerated to carry the bumped version.

### Notes — roadmap left in the manifest

A `[build]` comment block in `cyrius.cyml` documents the next two
steps for sigil's boot-side artifact: a future patch will replace the
smoke-test build with a real library probe (no `SIGIL_SMOKE` define);
later still, the boot's `--iso-check` will look at `dist/sigil.cyr`
directly once that path has been hardened in test. The eventual
endgame is sigil folded into the Cyrius stdlib, like sandhi (5.7.0)
and mabda (3.4.19).

No source / behavior changes in 2.9.4. Crypto code, dispatcher
routing, and SHA-NI hot path are byte-identical to 2.9.3.

## [2.9.3] — 2026-04-25

Lands the byte-encoded SHA-NI compress that 2.9.2 staged the probe
for. `sha256_transform_ni` is now a real one-block compress derived
verbatim from the Linux kernel's `arch/x86/crypto/sha256_ni_asm.S`
(BSD/GPLv2 → GPL leg under sigil's GPL-3.0). On SHA-NI-capable
x86_64 hosts, sigil's SHA-256 dispatcher routes through the hardware
path; on hosts without the extension, the software FIPS 180-4 path
remains the implementation.

Bench numbers on the dev host (Cyrius 5.6.41) — software vs NI:

| input | software | SHA-NI | speedup |
| ----- | -------- | ------ | ------- |
| 64 B  | 10 µs    | 470 ns | ~21×    |
| 1 KB  | 88 µs    |  2 µs  | ~44×    |
| 64 KB | 5.32 ms  | 157 µs | ~34×    |

This closes out the SHA-256 hot-path entry from the roadmap. sit's
`status-100files` and `add-1MB` paths (the ones that motivated the
work) pick up the win automatically through the dispatcher.

### Added

- **Real `sha256_transform_ni` body in `src/sha_ni.cyr`.** Replaces
  the 2.9.2 `-1` stub with a SHA-NI single-block compress. The
  function packs sigil's 8-byte-per-h_i ctx layout into a contiguous
  packed-dword state buffer at module-global scratch, runs the
  kernel's 16-iteration ping-pong loop (PSHUFB byte-swap, SHA256RNDS2
  pairs interleaved with SHA256MSG1/MSG2 schedule updates), then
  unpacks back to ctx with zero-extending 64-bit stores so the
  software path's `store64` invariant survives. State, K table, and
  PSHUFFLE_BYTE_FLIP_MASK live in module-global aligned scratch
  initialized lazily on first call (`_sha_ni_init`). The K constants
  are embedded directly rather than read from `sha256.cyr`'s table
  so this module has no init-order dependency.
- **`_sha_ni_align16` helper.** `alloc()` is 8-byte-aligned but
  PSHUFB and PADDD with m128 operands raise #GP on misaligned
  addresses. The helper rounds an alloc'd pointer up to a 16-byte
  boundary; init over-allocates each scratch buffer by 16 bytes and
  uses the aligned slot.
- **Cross-path test ring in `tests/tcyr/sha_ni.tcyr`.** FIPS 180-4
  vectors (empty, "abc", 56-byte two-block, 1KB, 64KB) routed
  through the dispatcher with `_sha_ni_cache` forced to 0 (software)
  pin the software path's correctness. Cross-path equality at 56B /
  1KB / 64KB hashes each input twice (once with `_sha_ni_cache=0`,
  once with `_sha_ni_cache=1`) and asserts byte-equal digests —
  catches any opcode-encoding regression deterministically. Test
  also includes `lib/ct.cyr` and `lib/keccak.cyr` so the stdlib
  symbols sigil's chain references are resolved (was an oversight).
- **`tests/bcyr/sigil.bcyr` SHA-256 throughput rows** at 64B / 1KB
  / 64KB for both software and NI paths. Captured in
  `benches/history.csv` under the `v2.9.3` label.
- **`docs/development/issues/archive/2026-04-25-sha-ni-compress-design.md`.**
  Pre-implementation design doc covering instruction semantics, the
  state-layout impedance between sigil's ctx and SHA-NI's XMM
  registers, the kernel-derived 16-iteration loop structure, and
  the encoding plan. Lives under `docs/development/issues/` per the
  project convention for in-flight design notes.

### Changed

- **`sha256_transform_ni` return contract.** Was `-1` (no-op
  fall-through to software) in 2.9.2; now `0` (hashed in hardware).
  The dispatcher in `sha256_transform` already handled both return
  values, so callers see no surface change — only behavior change
  is faster digests on SHA-NI hosts.

### Removed

- **SHA-256 hot-path roadmap entry.** Shipped, moves to this entry.

## [2.9.2] — 2026-04-25

Lays the SHA-NI hardware-acceleration foundation surfaced by sit
v0.6.4's perf review (2026-04-25). Sigil's current SHA-256 tops out
at ~12 MB/s on 64KB inputs versus ~1 GB/s on x86_64 SHA-NI hardware
— ~80x headroom — and is the dominant cost in sit's `status-100files`
and `add-1MB` flows. This release ships the CPUID probe + dispatch
wire-point so the byte-encoded SHA-NI compress can land in 2.9.3 as
a drop-in replacement for the stubbed `sha256_transform_ni` body
without touching the dispatcher or the public surface.

The split (foundation in 2.9.2, compress in 2.9.3) keeps the
risky-encoding step contained: a wrong opcode in a SHA-256 transform
produces silent wrong-hash digests, exactly the failure mode the
"Sigil IS the trust boundary" constraint forbids. Shipping the probe
ahead of the compress lets consumers (sit, daimon, kavach) pick up
the dispatch infrastructure now and the throughput win on the next
patch without a second wave of integration churn.

### Added

- **`src/sha_ni.cyr` — SHA-NI CPUID probe + dispatch entry point.**
  `sha_ni_available()` runs CPUID leaf 7 sub-leaf 0 and returns 1
  when EBX bit 29 (SHA extensions) is set, 0 otherwise. The probe
  result is cached in `_sha_ni_cache` (sentinel = 2 means uncached),
  matching `_aes_ni_cache` discipline so the CPUID instruction is
  paid exactly once per process. `sha256_transform_ni(ctx)` is a
  sentinel stub in 2.9.2: it returns `-1` to signal "not implemented"
  so the dispatcher in `sha256_transform` falls through to the
  software FIPS 180-4 path on every host. 2.9.3 replaces the stub
  body with the byte-encoded Intel SHA-NI sequence (load ABEF/CDGH
  state, byte-swap message dwords via PSHUFB, 16 message-schedule
  iterations × 4 rounds via SHA256RNDS2/MSG1/MSG2, store result).
- **`tests/tcyr/sha_ni.tcyr` — probe contract + dispatcher
  regression test.** Confirms `sha_ni_available()` returns 0 or 1
  (not the uncached sentinel 2) and is stable across calls; locks
  in the 2.9.2 stub contract that `sha256_transform_ni` returns -1;
  cross-checks `sha256("abc", 3, ...)` through the dispatcher
  matches the FIPS 180-4 `ba7816bf...f20015ad` vector to verify the
  new wire-point in `sha256_transform` doesn't regress the software
  path.

### Changed

- **`src/sha256.cyr:172` — `sha256_transform` dispatch wire-point.**
  Adds an `if (sha_ni_available() == 1) { if (sha256_transform_ni(ctx) == 0) { return 0; } }`
  prelude. With the 2.9.2 stub returning -1 unconditionally, the
  software path runs on every host — measured no regression
  (existing 605 → 609 tests, all passing). When 2.9.3 replaces the
  stub body, the dispatcher needs no change to pick up the
  hardware path.
- **`src/lib.cyr` and `cyrius.cyml` modules list — `src/sha_ni.cyr`
  added before `src/sha256.cyr`.** Same dependency-order pattern as
  `src/aes_ni.cyr` → `src/aes_gcm.cyr`. The dist bundle stays
  self-contained.
- **`docs/development/roadmap.md` — SHA-256 hot-path entry added
  under Road to v3.0 / Sigil-internal.** Records the sit v0.6.4
  source attribution, the 12 MB/s → 1 GB/s headroom, the
  cyrius 5.5.22+ inline-asm gate now being clear, and the staged
  delivery plan (foundation 2.9.2 / compress 2.9.3).
- **`VERSION` and `cyrius.cyml` 2.9.1 → 2.9.2.**
- **`cyrius.cyml` cyrius pin 5.5.30 → 5.6.40.** The pin had drifted
  out of sync with the actively-installed toolchain (`cyrius --version`
  reports 5.6.40); refreshing `lib/` via `cyrius deps` confirmed all
  17 vendored stdlib modules now match the 5.6.40 install file-by-
  file. `lib/alloc.cyr` picks up the v5.6.34 heap-grow rounding fix
  (round to next 1MB boundary instead of stepping by exactly
  0x100000) that prevents SIGSEGV on `alloc(>1MB)` near the brk
  grow-point. The pin bump is documentation: `cyrius deps` already
  uses whatever toolchain is on PATH, but the pin advertises what
  the codebase has been validated against. 5.6.40 supersedes 5.5.30
  with the cumulative 5.5.31..5.6.40 stdlib + frontend deltas.
- **`cyrius.cyml` `[deps] stdlib` adds `"bench"`.** Previously
  `lib/bench.cyr` was tracked in git but missing from the deps list,
  so `cyrius deps` wouldn't repopulate it after a clean. The bench
  harness (`tests/bcyr/sigil.bcyr`) includes it directly. Adding to
  the deps list keeps `lib/` rebuildable from a clean state.

### Notes for consumers

- **No public-surface change.** Existing `sha256()`, `hash_data()`,
  `hash_file()` calls continue to behave identically; the probe is
  internal. Consumers don't need to update import sites.
- **No throughput delta in 2.9.2.** sit's `status-100files` and
  `add-1MB` flows are still software-bound until 2.9.3 lands the
  compress. The release surfaces the foundation early so 2.9.3 is
  a focused crypto-correctness patch with the integration already
  exercised.
- **3.0 compatibility.** The 3.0 branch will pick this up via a
  main → 3.0 merge. The dispatch wire-point is orthogonal to the
  3.0 PQC + parallel-batch-verify scope, so no merge conflicts
  expected.

## [2.9.1] — 2026-04-21

Activates the AES-NI hardware dispatch staged in 2.9.0, now that
Cyrius 5.5.21's 16-byte array-global alignment fix has shipped.
`aes256_encrypt_block` delegates to the NI path at runtime on
AES-NI hosts and falls back to the FIPS 197 §5.1 software path
otherwise. Also bumps the Cyrius toolchain pin to 5.5.30 and
closes out a latent stdlib-include gap in the ML-DSA sampling
test.

### Changed

- **`src/aes_gcm.cyr` — AES-NI dispatch live.** `aes256_encrypt_block`
  calls `aes_ni_available()` on entry; when AES-NI is reported
  AND the `round_keys` pointer is 16-byte aligned, it delegates
  to `aes256_encrypt_block_ni`. Otherwise it falls through to the
  software FIPS 197 §5.1 path below. The 16-alignment guard is
  load-bearing: the NI path's PXOR / AESENC memory-operand forms
  #GP on unaligned round-key pointers, and while Cyrius 5.5.21
  guarantees 16-alignment for array globals and `fl_alloc` returns
  16-aligned blocks, bump-`alloc(240)` is only 8-aligned.
  Upstream callers that already followed CLAUDE.md's
  "fl_alloc-for-round-keys" discipline now get the NI speedup
  transparently; any caller using `alloc(240)` keeps running the
  software path without crashing. The security guarantees
  (constant-time tag compare, round-key zeroization, no branches
  on secret data) are unchanged.
- **`src/aes_gcm.cyr` now `include`s `src/aes_ni.cyr`** at the
  top. Prior arrangement required every consumer to list both
  files; omitting the NI include let cc5 silently stub
  `aes_ni_available` / `aes256_encrypt_block_ni` and crash at
  first call. Folding the dependency in makes `src/aes_gcm.cyr`
  self-contained.
- **`src/aes_ni.cyr` — probe caches CPUID result, dispatch live.**
  Replaces the 2.9.0 pin of `_aes_ni_cache = 0`. First call to
  `aes_ni_available()` runs the CPUID leaf-1 probe and caches
  0 or 1 in the global; later calls return the cached answer.
  Module header rewritten to drop the "deferred pending Cyrius
  fix" narrative — 5.5.21 closed out the failure mode.
- **`cyrius.cyml` cyrius pin 5.5.11 → 5.5.30.** Picks up the
  array-global alignment fix (5.5.21) that unblocked AES-NI, the
  `cyrfmt --write` flag (5.5.22), the per-arch `sys_*` routing
  in `lib/io.cyr` (5.5.18), the macOS `lib/alloc_macos.cyr`
  delegation (5.5.16), the u64-keyed `lib/hashmap.cyr` variant
  (5.5.20), and the expanded reserved-keyword diagnostic (5.5.26).
  NSS/PAM/fdlopen stdlib work (5.5.23–5.5.30) is irrelevant to
  sigil's single-threaded crypto core.
- **`CLAUDE.md` quirks section refreshed to 5.5.30.** Quirk #4
  updated to list the full reserved-keyword set cc5 5.5.26
  diagnoses (`match`, `in`, `default`, `shared`, `object`,
  `case`, `else`). New quirk #6 documents the 16-byte alignment
  guarantee for `var x[N]` with `N > 8` since 5.5.21.

### Fixed

- **`tests/tcyr/mldsa_sample.tcyr` — add missing
  `src/mldsa_encode.cyr` include.** `src/mldsa_sample.cyr:242`
  calls `_mldsa_polyz_unpack` which is defined in
  `src/mldsa_encode.cyr`. The test was pulling sample without
  encode, so cc5 stubbed the symbol and the run looped through
  the first three `test_group()` headers forever (undefined-
  function crash-back-to-main). With the include added, the
  test completes cleanly with 16 passed, 0 failed. Found via
  the CLAUDE.md "main restart loop" quirk.
- **`fuzz/fuzz_ed25519.fcyr` — add missing `lib/ct.cyr`
  include.** Same class of defect as the mldsa_sample fix:
  `lib/ct.cyr` defines `ct_select`, which `src/ed25519.cyr`
  uses during scalar multiplication (`_ge_table_select` for the
  constant-time fixed-base lookup). The fuzz harness included
  `src/ct.cyr` (`ct_eq` / `ct_eq_32`) but not `lib/ct.cyr`, so
  cc5 stubbed `ct_select` and the first `ed25519_sign` or
  `_ed_B_table` build at runtime SEGV'd. With `lib/ct.cyr`
  added, all 11 fuzz assertions pass — canonical-S reject,
  single-byte corruption rejection, multi-byte corruption
  rejection, point-decoding edge cases. Same include
  hardening applied to `fuzz_integrity.fcyr` and
  `fuzz_revocation.fcyr` defensively (they didn't trip on
  5.5.30 but they include `src/ed25519.cyr` and could regress
  on future ed25519 changes that pull ct_select into an
  earlier code path).
- **`.github/workflows/ci.yml` cyrius pin 5.2.1 → 5.5.30.**
  CI was running six minors behind the sigil source; the
  `lib/hashmap.cyr` u64-key branch added in 5.5.20 and the
  macOS `lib/alloc.cyr` selector added in 5.5.16 were
  unparseable under 5.2.1, producing the `expected '=', got var`
  error at line 808 of the preprocessed include stream on
  `cyrius build programs/smoke.cyr`. Matches the new pin in
  `cyrius.cyml`.

### Performance

Single-threaded, Linux x86_64 with AES-NI, `cyrius bench` via
`scripts/check.sh`:

| benchmark                       | 2.9.0 (software) | 2.9.1 (AES-NI)  | delta       |
|---------------------------------|------------------|-----------------|-------------|
| aes256_encrypt_block            | 4 µs             | **11 ns**       | **363×**    |
| aes_gcm_encrypt_1kb             | 1.223 ms         | **900 µs**      | 26% faster  |
| aes_gcm_decrypt_1kb_valid       | 1.230 ms         | **901 µs**      | 27% faster  |
| aes_gcm_decrypt_1kb_forged      | 1.228 ms         | **904 µs**      | 26% faster  |

`aes256_key_expansion` stays on the software path (no NI
counterpart used) at ~1 µs. GCM gains are modest compared to the
raw block-encrypt win because GHASH (bit-by-bit GF(2^128)
multiply) dominates 1 KB runs — a future NI/CLMUL-assisted GHASH
would close that gap.

### Verified

- FIPS 197 §C.3 AES-256 single-block vector matches on both the
  hardware path (via `aes256_encrypt_block_ni` directly) and the
  dispatcher. `tests/tcyr/aes_ni.tcyr` — 4 passed, 0 failed.
- Full test suite on cc5 5.5.30: aes_gcm 15, aes_ni 4, agnosys
  26, bigint 13, crypto 25, ed25519 20, ed25519_bug 3, field 18,
  hkdf 13, mldsa_encode 20, mldsa_ntt 10, mldsa_params 39,
  mldsa_poly 32, mldsa_reduce 42, mldsa_rounding 28,
  mldsa_sample 16, mldsa 17, security 39, sha512 3, sigil 96,
  types 78, verify 48. All green.

## [2.9.0] — 2026-04-20

Ships **HKDF** (RFC 5869) on top of the existing HMAC-SHA256
primitive — the key-derivation building block majra's planned
QUIC transport needs. Stages the AES-NI hardware-acceleration
scaffold (CPUID probe + AESENC opcode sequences) but defers the
live dispatch into `aes_gcm_encrypt` to a follow-up release; see
the Deferred section below.

### Added — HKDF-SHA256 (`src/hkdf.cyr`)

- **`hkdf_extract(salt, salt_len, ikm, ikm_len, prk_out)`** — RFC
  5869 §2.2 extract step. One HMAC-SHA256 call; 32-byte PRK
  output. Empty salt is handled per spec (HashLen zero bytes
  substituted), so callers can pass `(0, 0)` cleanly.
- **`hkdf_expand(prk, prk_len, info, info_len, out, out_len)`** —
  RFC 5869 §2.3 expand step. Iterative HMAC over
  `T(i-1) || info || i`; emits up to `out_len` bytes of OKM. The
  RFC cap of `255 * HashLen = 8160` bytes is enforced (returns
  `-2` on overflow). Scratch buffer holding `T(i-1) || info || i`
  and every `T(i)` intermediate is zeroized before free.
- **`hkdf(salt, salt_len, ikm, ikm_len, info, info_len, out, out_len)`** —
  extract+expand one-shot convenience wrapper. The intermediate
  PRK lives on the stack, is consumed by the expand step, and is
  zeroized before return — callers never see it.
- **Globals for cross-call state** — the expand loop's scratch
  pointer, info pointer, output pointer, counter, and produced
  count live in `_hkdf_*` globals. The deeply nested HMAC→SHA-256
  call chain clobbers locals on cc5 across module boundaries
  (we hit this during TC2 bring-up); globals are the sigil-wide
  standard workaround for this exact pattern (see sha256.cyr,
  ed25519.cyr, aes_gcm.cyr for the same treatment).

### Verified against RFC 5869 Appendix A

- **TC1** (standard IKM + salt + info, 42-byte OKM): PRK + OKM
  match.
- **TC2** (80-byte IKM + 80-byte salt + 80-byte info, 82-byte OKM
  across three expand rounds): PRK + OKM match.
- **TC3** (no salt, no info, 42-byte OKM): PRK + OKM match.
- Edge: `out_len > 8160` returns `-2`. Edge: `out_len == 0`
  returns 0 and writes nothing.

Total assertions in `tests/tcyr/hkdf.tcyr`: **13/13 pass**.

### Added — benchmarks

Added to `tests/bcyr/sigil.bcyr`; raw numbers from a single host
on 5.4.12-1:

| Bench              | Mean     | Notes                                  |
| ------------------ | -------- | -------------------------------------- |
| `hkdf_extract`     | 21us     | 64B IKM + 32B salt, one HMAC-SHA256    |
| `hkdf_expand_4kb`  | 2.807ms  | Derive 4096B of OKM (128 HMAC rounds)  |

The `hkdf_extract` number tracks the 10-20µs band for HMAC-SHA256
over a single short message. `hkdf_expand_4kb` is an HMAC-per-32B
loop (128 rounds to fill 4 KB); the ~22µs per round matches the
extract cost. Both are entirely limited by SHA-256 throughput.

### Deferred — AES-NI hardware acceleration

The AES-NI bring-up staged but did not wire in fully. The
scaffold lives in `src/aes_ni.cyr`:

- `aes_ni_available()` — CPUID leaf 1 ECX bit 25 feature probe.
- `aes256_encrypt_block_ni(round_keys, in, out)` — byte-accurate
  `AESENC`/`AESENCLAST` sequence over the 14 round keys.
- Round-key layout-compatible with the software encryptor, so
  the dispatch is a one-line switch once the blocker clears.

**Why it didn't ship live:** cc5-5.4.12 has a codegen anomaly
where an inline-asm store into a caller-supplied output pointer
observably works when the emitting function is in the same
compilation unit as the caller, but does NOT observable-write
when the function is pulled in via `include` from a separate
source module. The byte sequence emitted is byte-for-byte
identical (verified via `objdump`); the disassembly shows the
`mov [rdi], rcx` and `movq [rdi], 0x12345678` instructions at
the expected offsets; the caller's post-call reload from its
local slot reads the pre-call zero. Reproduced on three minimal
programs — module-scope does not write, inline does. Filed as a
cyrius bug.

Until the bug clears, `aes_ni_available()` is pinned to 0 and
the GCM dispatch stays on the well-tested software path. The
scaffold asm is stable and ships in `dist/sigil.cyr` so the
2.9.1 activation is a one-line change. Software GCM numbers
(~1.2ms/KB encrypt) are unchanged from 2.8.4.

### Changed

- **`cyrius.cyml` [package] description** — adds "HKDF" to the
  primitive list: Ed25519, SHA-256/512, HMAC, **HKDF**,
  AES-256-GCM, integrity, audit.
- **`src/lib.cyr` and `cyrius.cyml` [lib] modules** — add
  `src/hkdf.cyr` after `src/hmac.cyr` and `src/aes_ni.cyr` after
  that. Dist bundle now ships 17 modules (15 + HKDF + AES-NI).

### Verified

- `cyrius build programs/smoke.cyr build/sigil-smoke` — clean.
- All 14 `.tcyr` suites pass (hkdf new + aes_ni stub new + 12
  existing): **396 assertions, 0 failures** (up from 381 in
  2.8.4).
- `cyrius build tests/bcyr/sigil.bcyr build/bench && ./build/bench`
  runs clean; HKDF rows captured alongside the existing 17.
- `cyrius distlib` emits `dist/sigil.cyr` with `v2.9.0` header;
  bundle includes hkdf.cyr and aes_ni.cyr.

## [2.8.4] — 2026-04-19

Two bundled changes: a **toolchain refresh** to bring sigil onto
the current Cyrius pin, and a new **AES-256-GCM** AEAD primitive
that completes sigil's symmetric-crypto surface for the AGNOS
ecosystem. The symmetric primitive is the AEAD that majra's
`ipc_encrypted.cyr` consumes; before 2.8.4 majra hand-rolled a
stub.

### Added — AES-256-GCM AEAD (`src/aes_gcm.cyr`)

- **AES-256 block cipher** — FIPS 197, forward direction only (GCM
  never invokes the inverse). Full 256-byte Rijndael S-box, 14-round
  Nk=8 key schedule producing 240 bytes of round keys. The S-box
  and Rcon tables ship as hex string literals decoded once into an
  `alloc`-backed buffer at first use, keeping the fixup cost off
  the hot path.
- **GHASH** — bit-by-bit GF(2^128) multiplication under the GCM
  reduction polynomial `x^128 + x^7 + x^2 + x + 1`. Constant-time
  by construction (exactly 128 shift+xor per block, no data-
  dependent branches). Table-based acceleration is deferred as a
  perf-only follow-up.
- **`aes_gcm_encrypt(key, iv, aad, aad_len, pt, pt_len, ct_out, tag_out)`**
  and **`aes_gcm_decrypt(...) -> ERR_NONE | ERR_INTEGRITY_MISMATCH`**.
  12-byte IV (96-bit RFC fast path). 16-byte authentication tag.
  Arbitrary-length IV is a deferred follow-up.
- **AEAD contract honoured** — decrypt computes the expected tag
  first, compares in constant time via `ct_eq`, and zeroes
  `pt_out` on tag failure so plaintext never escapes. The
  CTR-mode pass runs unconditionally to keep the valid-tag and
  forged-tag decrypt paths within ~1% of each other (see
  benchmark numbers below).
- **Key material zeroization** — the 240-byte round-key schedule
  and every intermediate scratch (`H`, `Y`, `S`, `J0`, counter,
  zero block, length block) is overwritten with zeros before free
  on every call. Matches sigil's existing Ed25519 / HMAC hygiene.
- **Software-only.** No inline asm / no AES-NI — Cyrius doesn't
  support inline asm today. A hardware path is a future patch
  once the toolchain exposes the intrinsics.

### Verified against NIST SP 800-38D

- **TC1** (empty PT + empty AAD, zero key + zero IV):
  tag = `530f8afbc74536b9a963b4f1c4cb738b`.
- **TC2** (single zero block PT, zero key + IV):
  CT = `cea7403d4d606b6e074ec5d3baf39d18`,
  tag = `d0d1c8a799996bf0265b98b5d48ab919`.
- **TC14** (64-byte PT, no AAD, NIST AES-256 vector):
  CT + tag match the published fixture.
- **TC15** (20-byte AAD + 60-byte PT, partial final block):
  CT + tag = `...76fc6ece0f4e1768cddf8853bb2d551b`.
- Decrypt roundtrip passes; single-bit tag flip returns
  `ERR_INTEGRITY_MISMATCH` and the plaintext output buffer is
  zero at the head, middle, and tail (no leak).

Total assertions in `tests/tcyr/aes_gcm.tcyr`: **15/15 pass**.
Total sigil assertion count across all suites: **381** (up from
366 in 2.8.3).

### Added — benchmarks

Added to `tests/bcyr/sigil.bcyr`; raw numbers from a single
host under 2.8.4:

| Bench                          | Mean     | Notes                                 |
| ------------------------------ | -------- | ------------------------------------- |
| `aes256_key_expansion`         | 1us      | 32-byte key → 240-byte schedule       |
| `aes256_encrypt_block`         | 4us      | 16-byte single-block encrypt          |
| `aes_gcm_encrypt_1kb`          | 1.216ms  | 64-block CTR + GHASH                  |
| `aes_gcm_decrypt_1kb_valid`    | 1.220ms  | Valid tag; full decrypt               |
| `aes_gcm_decrypt_1kb_forged`   | 1.229ms  | Flipped-bit tag; full CT pass still runs |

The valid-vs-forged gap is **<1%**. That's the empirical proof
that the tag verification is constant-time and there is no
early-exit on the auth path. If a future edit drops this below
1% or drifts it above 10%, treat as a regression.

### Changed — toolchain refresh

- **`cyrius` pin: 5.2.1 → 5.4.8** in `cyrius.cyml`. Picks up the
  larger fixup table (16384 up from 8192), reliable compound
  assignment, negative-literal support, and the stdlib evolution
  of the past two minor versions. The `CLAUDE.md` compiler-quirks
  section has been rewritten to reflect cc5 reality — most of
  the cc3-era workarounds (hand-emitted byte 13 for `\r`, `(0 - N)`
  for negative literals, the 256 initialized-global cap, the 8192
  fixup cap) are no longer needed. Still genuinely present:
  occasional local clobbering across deeply nested call chains,
  and `fl_alloc` vs `alloc` discipline.
- **Vendored stdlib refreshed.** `lib/json.cyr` and `lib/string.cyr`
  had drifted under 5.4.8 — copied fresh from `~/.cyrius/lib/` via
  the established sync-if-different pattern. `lib/agnosys.cyr`
  stays unique to sigil (it wraps the AGNOS kernel interface
  layer; not vendored upstream).

### Verified

- `cyrius build programs/smoke.cyr build/sigil-smoke` — clean,
  smoke run exits 0.
- All 12 `.tcyr` suites pass (aes_gcm new + 11 existing):
  **381 assertions, 0 failures.**
- `cyrius distlib` emits `dist/sigil.cyr` with `v2.8.4` header,
  15 bundled modules (includes aes_gcm), 5780 lines.

## [2.8.3] — 2026-04-17

### Fixed — dist bundle was referencing un-bundled agnosys symbols

Cyrius 5.2.1 added a compile-check to `cyrius distlib`: after
concatenating the declared modules, it compiles the resulting bundle
standalone to catch undefined-symbol references. The first run
against sigil 2.8.2 flagged the bundle as NOT self-contained.

The 2.8.2 bundle (from 2.8.2's manifest) included all 18 src modules,
four of which wrap agnosys (`tpm.cyr`, `ima.cyr`, `secureboot.cyr`,
`certpin.cyr`) and reference enums like `TPM_SHA256`, `SB_ENABLED`,
`CERTPIN_VALID` plus functions like `tpm_seal`, `secureboot_detect_state`
that come from `lib/agnosys.cyr`. Those includes are stripped by
`distlib`, so a consumer pulling only `dist/sigil.cyr` could not
compile — the bundle silently referenced symbols a consumer had
no way to provide unless they also pulled agnosys and included
its bundle first in the right order.

This was a real regression introduced in 2.5.0 when the agnosys
wrappers landed (the hand-maintained `scripts/bundle.sh` happened
not to list them, which — by accident — kept the bundle self-
contained through 2.8.0. 2.8.2's manifest-driven `distlib` adopted
every module including the wrappers, exposing the issue.)

Cyrius' CHANGELOG 5.2.1 entry called this out and held their stdlib
fold-in at sigil 2.1.2 pending a fix. This release is that fix.

### Changed — bundle scope narrowed

- **`[build] modules`** in `cyrius.cyml` now explicitly excludes
  the four agnosys-wrapping modules. The bundle ships as the
  self-contained core: crypto (SHA-256/512, HMAC, Ed25519),
  constant-time compare, bigint, trust engine, integrity verifier,
  revocation list + CRL, audit log, verification engine. 14
  modules / 5118 lines.
- **Consumers who want the AGNOS kernel-interface layer** (TPM
  seal/unseal, IMA status, Secure-Boot detection, certificate
  pinning) should include sigil via `src/lib.cyr` against a git-
  pinned checkout — that pulls agnosys as a proper dep and gets
  all 18 modules in the correct order. The `dist/sigil.cyr` path
  is now documented as "core library only".
- The manifest comment on `modules = [...]` makes the exclusion
  explicit so a future maintainer doesn't re-add the wrappers and
  break the bundle again.

### Changed — toolchain bump

- **`cyrius` pin: 5.2.0 → 5.2.1** (`cyrius.cyml` +
  `.github/workflows/ci.yml`). Picks up the `distlib` compile-check
  that caught this issue, plus `cyrius deps --lock` / `--verify`
  and `cyrius publish`.

### Verified

- `cyrius distlib` → clean exit (no self-containment warning),
  `dist/sigil.cyr: 5118 lines (v2.8.3)`.
- 11/11 `.tcyr` pass, 3/3 fuzz OK, 12/12 benches run, smoke
  exit 0 (library behaviour is unchanged — agnosys wrappers are
  still built and tested via `src/lib.cyr`).

## [2.8.2] — 2026-04-17

### Fixed — distribution bundle was missing 3 modules

`scripts/bundle.sh` hand-listed the src modules to concatenate
into `dist/sigil.cyr`. The list hadn't been updated since 2.5.0,
so the last three shipped bundles (2.5.0 – 2.8.1) silently
omitted `src/ima.cyr`, `src/secureboot.cyr`, and `src/certpin.cyr`
— the entire agnosys-wrapper layer. Consumers pulling the bundle
got sigil's crypto + trust core but none of the TPM / IMA /
Secure-Boot / certpin sigil_* wrappers.

No runtime impact on sigil's own `cyrius build` / `cyrius test`
paths (those use `src/lib.cyr` directly), and no reported
downstream incident — the bundle consumers are the other AGNOS
crates and they've been pulling via `[deps.sigil]` modules that
end up resolving through `src/lib.cyr` on their side. But any
consumer that copied `dist/sigil.cyr` verbatim would be missing
the wrappers.

### Changed — `scripts/bundle.sh` → `cyrius distlib`

Cyrius 5.2.0 shipped `cyrius distlib` as the official library-
distribution command, reading `[build] modules` (or `[lib] modules`)
from `cyrius.cyml`. Removes the per-repo hand-maintained bundle
script — the module list now lives in one place, is the same
list the language tooling uses for dep resolution, and can't
drift away from `src/lib.cyr` silently.

- Added `[build] modules = [...]` to `cyrius.cyml` listing all
  18 src/ modules in dependency order (same order as
  `src/lib.cyr`'s includes). Comment in the manifest makes the
  "keep both files in sync" invariant explicit.
- Removed `scripts/bundle.sh`. The canonical regen path is now
  `cyrius distlib`.
- Regenerated `dist/sigil.cyr` — went from 5296 lines / 15
  modules (2.8.1) to 5420 lines / 18 modules (this release).

### Verified

- `cyrius distlib` → `dist/sigil.cyr: 5420 lines (v2.8.2)`.
- Bundle now contains all 18 src/ modules (was 15) — verified via
  `grep -c '^# --- '`.
- No remaining references to `scripts/bundle.sh` outside
  historical CHANGELOG entries.
- 11/11 `.tcyr` pass, 3/3 fuzz OK, smoke exit 0 (library
  behavior unchanged — only the packaging path moved).

## [2.8.1] — 2026-04-17

### Security — HIGH

- **`ed25519_generate_keypair` silent entropy failure.** The
  pre-2.8.1 implementation had two unchecked paths in the
  `/dev/urandom` read:
  - `file_open("/dev/urandom", 0, 0)` — no check of the returned
    `fd`. On failure (`fd = -1`), the subsequent `file_read(-1, …)`
    returned an error code, and `seed[32]` stayed with whatever
    bytes were on the stack at that frame's location.
  - `file_read(fd, &seed, 32)` — single unchecked call. A short
    read (e.g. 16 bytes actually delivered) left the upper half
    of the seed uninitialised.
  Either path would silently derive an Ed25519 key from
  partial / stale entropy. `trust.cyr`'s own `generate_keypair`
  already had the correct short-read loop (2.1.x); this one had
  been missed because it was reached only through
  `programs/smoke.cyr` and `tests/tcyr/ed25519.tcyr`'s
  "random keypair" block, which always ran on a host with a
  functional `/dev/urandom`.

  **Fix**: mirror the loop pattern from `trust.cyr:generate_keypair`.
  Bail on open failure (zero sk_out/pk_out, return 0). Accumulate
  reads in a `got < 32` loop. On any short or failing read, close
  the fd, zeroise the seed and outputs, return 0. Success returns
  1 (new return-value contract; prior caller convention of
  "always 0" is upheld for null-output scenarios by explicit
  zeroisation so the failure is deterministic rather than silent).

  **Impact assessment**: no evidence this bit any shipped key —
  `ed25519_generate_keypair` is the only path affected, and every
  CI host plus the reference dev machine has a live `/dev/urandom`.
  Keys issued in practice came through a successful 32-byte read.
  The fix removes the trap without requiring key rotation on
  existing deployments.

  **Regression guard**: `tests/tcyr/ed25519.tcyr` now asserts the
  success return value is `1`. A refactor that silently drops the
  contract fails the gate.

### Changed

- **Roadmap restructured as "road to 3.0".** The 2.x milestones
  are done; `docs/development/roadmap.md` now explicitly splits
  v3.0 scope into (a) items blocked on Cyrius 5.2.x / 5.3.x
  (SHAKE for ML-DSA-65, `ct_select`, `secret var`), (b) items
  blocked on Cyrius 5.3.x threading (parallel batch verify), and
  (c) sigil-internal cleanups that batch into a single 3.0
  breaking bump. Cross-reference: the mirror items in
  `cyrius/docs/development/roadmap.md` under `v5.2.x / v5.3.x —
  Sigil 3.0 enablers`.

### Documentation

- `SECURITY.md` supported-versions table refreshed (was stuck at
  2.0.x/2.1.x, now 2.6.x – 2.8.x).
- `CLAUDE.md` status block: stale "2.0.0 → 2.7.1" range replaced
  with "2.0.0 → current".

### Verified

- 11/11 `.tcyr` pass (20 asserts in `ed25519.tcyr`, was 19 —
  adds the return-value contract).
- 3/3 fuzz harnesses OK.
- 12/12 benches run; numbers stable (ed25519_keypair ~990 µs,
  sign ~1.1 ms, verify ~6.9 ms — within noise of 2.8.0).
- Clean-build sweep from `rm -rf build`.
- Security grep (`sys_system`, `memcmp`, `strcpy`, `strcat`,
  unchecked short-read in crypto paths, path traversal, TODO/
  FIXME/XXX) → clean after the entropy fix. Only matches were
  doc comments referencing `\uXXXX`.

## [2.8.0] — 2026-04-17

### Added — certificate pinning (via agnosys)

Sigil now ships a thin certpin facade over agnosys 1.0.0. The
agnosys README had listed sigil as a consumer of
`agnosys[tpm, ima, certpin]` since 0.98; TPM / IMA / Secure-Boot
landed in 2.5.0 and certpin closes the remaining module.

Same wrapper pattern as `src/tpm.cyr` / `src/ima.cyr` /
`src/secureboot.cyr`: agnosys owns the wire format and the
constant-time byte compare, sigil exposes a narrow Result-free
surface that's safe to call on the hot path.

- **`src/certpin.cyr`** — new module, 4 public functions:
  - `sigil_cert_pin_status(host, actual_pin, pin_set, at)` — raw
    `CERTPIN_*` enum (VALID / MISMATCH / EXPIRED / NO_PIN_CONFIGURED).
    `at = 0` skips the expiry window check.
  - `sigil_cert_pin_check(host, actual_pin, pin_set)` — fast
    predicate. 1 iff VALID at `clock_epoch_secs()`. Collapses the
    no-pin and mismatch cases to 0; use the raw status function
    when the caller needs to distinguish them for first-use-trust
    policy.
  - `sigil_cert_pin_status_name(status)` — static C-string
    ("valid" / "mismatch" / "expired" / "no_pin" / "unknown") for
    logs and audit-event details. Names are advisory and must NOT
    be parsed back.
  - `sigil_cert_pin_compute(cert_path)` — wraps
    `certpin_compute_spki_pin`, unwraps the agnosys Result to a
    C-string or 0. Shells out to `openssl` via agnosys; intended
    for pin-set construction at config time, not per-connection
    use.
- **`src/lib.cyr`** now includes `src/certpin.cyr` after the
  other agnosys wrappers and before `src/verify.cyr`.

### Test coverage

- **`tests/tcyr/agnosys.tcyr`** adds 14 new certpin assertions
  (26 total, was 12). Purely in-memory pin-set fixtures — no
  network, no files, no openssl required on the CI host:
  - Status-enum name mappings for all 4 CERTPIN_* codes plus
    unknown-fallback.
  - VALID path: active entry, correct pin, deterministic `now`
    timestamp.
  - MISMATCH path: active entry, wrong pin.
  - NO_PIN_CONFIGURED path: unknown host.
  - EXPIRED path: entry with `expires=1`, `now=1 000 000`.
  - `sigil_cert_pin_compute` on a missing file returns 0
    without propagating an agnosys `Err`.

### Verified

- 11/11 `.tcyr` pass (`agnosys.tcyr`: 26 assertions, was 12).
- 3/3 fuzz harnesses OK.
- 12/12 benches run; no regressions.
- `./build/sigil-smoke` exit 0.

### Note

This closes the originally-planned 2.x roadmap. Remaining items in
`docs/development/roadmap.md` (PQC, hybrid signatures, parallel
batch verify, scatter-store for the fixed-base comb) are all
"Future" — they depend on Cyrius or AGNOS work that hasn't landed.

## [2.7.0] — 2026-04-17

### Added — JSON load paths (round-trip support)

Both persistence paths in sigil used to be write-only: you could
save a trust store or append to an audit log, but reloading either
after a restart meant starting from scratch. This release completes
the round-trip for both.

- **`sv_load_trust_store(sv, path)`** in `src/verify.cyr`. Parses
  the JSON array emitted by `sv_save_trust_store`, rebuilding
  `{content_hash, path, artifact_type, trust_level}` records into
  the verifier's trust-store map. Returns the number of artifacts
  loaded, or 0 on IO / parse failure. Signatures and
  `signer_key_id` are NOT restored (the save path never wrote
  them) — loaded artifacts come back as present-but-unsigned,
  matching the existing serialized form. A subsequent
  `sv_verify_artifact` will report them as "not in trust store"
  until re-signed.
- **`alog_load_from_file(log, path)`** in `src/audit.cyr`. Reads
  the JSON Lines stream from `alog_append_to_file` back into an
  `AuditLog`. Each line is parsed as a flat JSON object with
  fields `type`, `timestamp`, `path?`, `key_id?`, `content_hash?`,
  `passed?`. Lines whose `type` is an unknown event name are
  skipped rather than aborting — a newer writer must not take
  down an older reader doing forensic replay. Returns the number
  of events loaded, or `-1` on IO failure.
- **`audit_event_type_from_name(name)`** — inverse of
  `audit_event_name(t)`, used by the loader and exposed for
  consumers that want to match on named events.
- Both loaders reuse `_rj_parse_string` from `src/policy.cyr`
  (the escape-aware reader written for `rl_from_jsonl` in 2.5.0)
  — unified handling for `\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`,
  and `\u00XX` matches what `json_write_escaped` emits.

### Test coverage

- **`sigil.tcyr`** adds `audit jsonl load` (5 assertions + a
  missing-file guard): write 3 events, reload them, deep-check
  the first and last, then verify a nonexistent file returns -1
  without crashing. Assertion count 82 → 92.
- **`verify.tcyr`** adds `trust-store save+load` (5 assertions):
  save two artifacts at different trust levels, load into a fresh
  `SigilVerifier`, assert both trust levels survive. Plus a JSON
  escape round-trip (path containing `"` and `\`) and a
  missing-file check. Assertion count 37 → 43.

### Added — final parity closeout

One last `rust-old/` sweep before removal surfaced two remaining
missing surfaces. Both landed in this release so the rust-old
reference can be deleted with no outstanding parity debt.

- **`hash_file_with(path, algorithm)`** in `src/trust.cyr`. Mirror
  of `hash_data_with` but for on-disk content — dispatches to
  SHA-256 or SHA-512 by `HASH_ALG_*`. Unknown algorithm falls
  back to SHA-256 (same policy as `hash_data_with`). Uses
  streaming 4 KB reads, same as `hash_file`.
- **`sv_verify_package(sv, path, expected_hash)`** in
  `src/verify.cyr`. Package install-time verification path:
  wraps `sv_verify_artifact(sv, path, ARTIFACT_PACKAGE)` and —
  when `expected_hash` is non-zero — layers a constant-time
  content-hash match. Mismatch adds a failing `"expected_hash"`
  trust-check and fails the whole result. Pass `0` as
  `expected_hash` to verify without a known hash.
  - Note vs. Rust: the Rust `verify_package` had an early-exit
    when `policy.verify_on_install` was false. That gate is
    dropped here — `verify_on_install` has been a user-set
    policy knob for several releases and consumers enforce it
    themselves before calling in.

### Removed — `rust-old/` reference tree

6 552 lines of Rust across 13 files (audit / chain / error /
integrity / lib / policy / tests / tpm / trust / types / verify
plus Cargo manifests). Preserved through the 2.x series for
cross-port audits; the last gap surfaced by this 2.7.0 sweep is
closed above. Removal clears the repo root of Rust artifacts and
takes `rust-old/target/` off the `.gitignore`. The
cross-implementation benchmark baseline in
`benchmarks-rust-v-cyrius.md` stays as archival reference — it
is never rebuilt per release.

- `CLAUDE.md` — dropped the "Rust source preserved in `rust-old/`"
  TDD discipline line and the "Ported from: Rust v1.0.0" status
  block now reads "removed in 2.7.0 after parity closeout".
- `SECURITY.md` — `rust-old/` pointer replaced with the same
  closeout reference.
- `.gitignore` — `/rust-old/target/` entry removed.

### Test coverage

- **`sigil.tcyr`** adds `hash_file_with` (4 assertions: SHA-256,
  SHA-512, unknown-algo fallback, missing-file). Assertion count
  92 → 96.
- **`verify.tcyr`** adds `verify_package` (3 groups × ~2 checks:
  no expected hash → no `expected_hash` check surfaced; matching
  hash → check passes; mismatched hash → check fails + whole
  result fails). Assertion count 43 → 48.

### Verified

- 11/11 `.tcyr` pass. 3/3 fuzz. 12/12 benches. Smoke exit 0.
- `./build/sigil-smoke` unchanged (loaders + new parity fns are
  opt-in — not on the hot path).

## [2.6.0] — 2026-04-17

### Changed — agnosys 1.0.0

- **`[deps.agnosys]` bumped `0.98.0` → `1.0.0`**. Agnosys 1.0 froze
  its public API and landed 139 module-prefix renames pre-freeze
  (see agnosys `CHANGELOG`). The renames affected `certinfo_*`,
  `security_*`, `journal_*`, `verity_*`, `boot_*`, `fw_*`, `nft_*`,
  and `checked_syscall`. **Sigil is unaffected**: the modules we
  wrap (`tpm_*`, `ima_*`, `secureboot_*`) were listed in agnosys'
  "already clean" set, and we don't wrap `certpin` yet (queued for
  2.7.0+). All 11 `.tcyr` files still pass against the new tag, no
  sigil source changed for this bump.

### Breaking — Tier 2 dead-field cleanup

Completes the dead-code sweep started in 2.5.0. These fields had
no read path (setter/getter defined, no caller) but their backing
storage was still allocated on every instance. A downstream audit
across 8 AGNOS consumer repos found zero real callers for any of
the removed names (argonaut's vendored `lib/sigil.cyr` copies the
bundle — those definitions regenerate with the new layout).

- **`TrustedArtifact`: 80 → 48 bytes.** Dropped:
  - `signature_len` field + getter — Ed25519 signatures are always
    exactly 64 bytes; the param was hard-coded `64` at the one
    call site.
  - `signature_algorithm` field + `artifact_sig_alg` /
    `artifact_set_sig_alg` — always `SIG_ALG_ED25519`. Re-introduce
    when hybrid/PQC dual signatures land.
  - `verified_at` field + `artifact_verified_at` /
    `artifact_set_verified_at` — written by `sv_sign_artifact`,
    never read.
  - `metadata` field + `artifact_metadata` / `artifact_set_metadata`
    — never populated.
  - **API change**: `artifact_set_signature(a, sig, sig_len)` →
    `artifact_set_signature(a, sig)`. One caller (internal).
- **`IntegrityMeasurement`: 48 → 24 bytes.** Dropped `actual_hash`,
  `measured_at`, `error_msg` fields + `meas_actual` / `meas_at` /
  `meas_error` getters. `iv_verify_all` no longer writes them.
  Measurement state is now just `(path, expected, status)`.
- **`IntegrityReport`: 40 → 32 bytes.** Dropped `checked_at` field
  + `ireport_checked_at`. Callers can stamp their own `clock_epoch_secs()`
  at report time if needed.
- **`IntegritySnapshot`: 16 → 8 bytes.** Dropped `exported_at` field
  + `isnap_exported_at`. Same rationale.
- **`AttestationResult`: 24 → 16 bytes.** Dropped `quote_signature`
  field + `attest_quote_sig` / `attest_set_quote_sig`. No `tpm_quote`
  wrapper exists yet; re-introduce with one.
- **Integrity policy / verification-result / etc. (getters only,
  no struct change)**: removed `ipolicy_count` (use `vec_len(load64(p))`
  — there was no semantic difference), `ipolicy_measurements`,
  `attest_passed`, `vresult_verified_at`, `pcr_index`,
  `key_id_from_public_hex` (duplicate of `generate_keypair` key-id
  logic).
- **`ireport_summary`** function removed — 35-line formatter nobody
  was calling. Consumers can build the summary string from
  `ireport_total` / `ireport_verified` / vec lengths in three lines.

### Verified

- 11/11 `.tcyr` files pass (unchanged from 2.5.0 — no semantic changes).
- 3/3 fuzz harnesses OK under 30 s CI budget.
- 12/12 benches run; numbers stable.
- `./build/sigil-smoke` exit 0 against agnosys 1.0.0.

### Source stats (vs 2.5.0)

- Functions in `src/`: 372 → **352** (-20 dead getters/setters/fns).
- Struct-layout savings per `SigilVerifier` instance: ~104 bytes
  less heap per stored artifact (`TrustedArtifact` -32 B, and each
  `IntegrityMeasurement` -24 B). Not huge in absolute terms, but
  the API surface is now honest about what sigil actually persists.

## [2.5.0] — 2026-04-16

### Added — AGNOS kernel integration

Sigil now consumes `agnosys 0.98.0` for the AGNOS-native TPM / IMA /
Secure-Boot surface. This replaces the placeholder stubs that shipped
through the 2.x line and makes sigil a real trust-verification node
on AGNOS hosts rather than a paper spec.

- **Cyrius toolchain bumped** 5.1.13 → 5.2.0 (sigil's `cyrius.cyml`
  and `.github/workflows/ci.yml` in lock-step; agnosys requires
  5.2.0).
- **`[deps.agnosys]`** added to `cyrius.cyml`, pinned to tag
  `0.98.0`, consuming `dist/agnosys.cyr` (20 modules, 9769 lines,
  includes stripped so the bundle composes cleanly with sigil's
  stdlib graph). New stdlib deps pulled in to support agnosys:
  `string`, `tagged`, `process`, `fs`.
- **`src/tpm.cyr`** rewritten as a thin wrapper:
  - `tpm_available()` → `tpm_detect()` (SYS_ACCESS on
    `/dev/tpmrm0` then `/dev/tpm0`).
  - `tpm_seal_data(data, len, pcr_indices, output_dir)` →
    `tpm_seal(TPM_SHA256, ...)`. Result unwrapped to a pointer/0.
  - `tpm_unseal_data(sealed, buf, buflen)` → `tpm_unseal`.
    Same pattern.
  - Both refuse cleanly (`return 0`) when `tpm_available() == 0`
    so tests/dev hosts without a TPM don't crash.
  - `tpm_random` stays on `/dev/urandom`. We deliberately do NOT
    route through `tpm_get_random` — that shells out to
    `/usr/bin/tpm2_getrandom` and adds a fork/exec per key gen.
    Linux `getrandom(2)` is cryptographically adequate for Ed25519
    scalar generation.
- **`src/ima.cyr`** — new. Thin wrapper over agnosys
  `ima_get_status`. Public API:
  - `sigil_ima_snapshot()` → 24-byte struct with `active`,
    `measurement_count`, `policy_loaded`.
  - `sigil_ima_available()` / `sigil_ima_measurement_count()` /
    `sigil_ima_policy_loaded()` convenience predicates.
- **`src/secureboot.cyr`** — new. Thin wrapper over agnosys
  `secureboot_detect_state`:
  - `sigil_sb_state()` returns an agnosys `SB_*` enum
    (`SB_ENABLED` / `SB_DISABLED` / `SB_SETUP_MODE` /
    `SB_NOT_SUPPORTED`).
  - `sigil_sb_enforcing()` → 1 iff `SB_ENABLED`. Policy code can
    require this for the `TRUST_SYSTEM_CORE` admit path.
  - `sigil_sb_state_name()` → static C-string for logs.
- **`src/lib.cyr`** now includes `lib/agnosys.cyr`, `src/ima.cyr`,
  `src/secureboot.cyr` in dependency order.

### Test coverage

- **`tests/tcyr/agnosys.tcyr`** — new. 12 assertions across TPM /
  IMA / Secure-Boot wrappers. Every assertion targets the
  *unavailable* path so the suite passes on CI hosts without
  hardware (no /dev/tpm, no /sys/kernel/security/ima, no EFI).
  Hosts WITH these facilities still satisfy the assertions and
  additionally exercise the agnosys shell-outs.
- 11/11 `.tcyr` files pass (was 10). Fuzz 3/3 OK. 12/12 benches
  still run.

### Performance

No change — 2.5.0 is an integration release, not a crypto release.
Numbers (single-run on the same host as 2.4.2):

| op | 2.4.2 | 2.5.0 | Δ |
|---|---|---|---|
| `ed25519_keypair` | 1.33 ms | 0.99 ms | (noise, −25%) |
| `ed25519_sign` | 1.14 ms | 1.11 ms | ~flat |
| `ed25519_verify` | 7.18 ms | 6.68 ms | (noise) |
| `fp_inv` | 273 us | 258 us | ~flat |
| `sha256_4kb` | 257 us | 248 us | ~flat |

### Breaking

- **`tpm_seal_data` takes a fourth parameter**: `output_dir`
  (directory for tpm2_create output files — `sealed.ctx`,
  `sealed.pub`, `sealed.priv`). The previous stub was 3-arg.
  Consumer repos must update call sites. No public consumer is
  currently calling this (stub era), so impact should be nil.
- **`TrustStoreDiff` vecs now carry `ArtifactChange` records**
  instead of raw `TrustedArtifact` pointers (see "Added — Rust
  parity" below). Consumers iterating `tsdiff_added/removed/
  changed` must switch to `ac_content_hash` / `ac_path` /
  `ac_old_trust_level` / `ac_new_trust_level` accessors. No
  downstream repo uses these yet — verified by audit.
- **`sv_snapshot_trust_store` returns a map of `SnapshotEntry`
  records** (trust-level + path captured by value) rather than a
  map of live artifact pointers. Previous snapshots silently
  aliased the live store, so trust-level changes on an artifact
  pointer were invisible to a subsequent `sv_diff_trust_store`.
  New layout makes diffs meaningful.

### Added — Rust parity (fold-ins of audit-flagged gaps)

Pulled forward before 2.5.0 tag cut. A `rust-old/` sweep revealed
six Rust surfaces that had not been ported. Three are security-
relevant and are now landed here; three are ergonomic and also
landed since they're small.

- **`Crl::to_json` / `from_json` → `crl_to_jsonl` /
  `crl_from_jsonl`** (`src/policy.cyr`). JSON Lines format: first
  line is the header object, subsequent lines are entries in the
  same format as `rl_to_jsonl`. Includes `crl_save(path)` and
  `crl_load(path)` convenience wrappers. Deliberate JSONL (not JSON
  array) because `lib/json.cyr` parses one object at a time — JSONL
  matches the existing `alog_append_to_file` convention, converts
  to/from standard JSON via `jq -s`.
- **`RevocationList::to_json` / `from_json` → `rl_to_jsonl` /
  `rl_from_jsonl`** (`src/policy.cyr`). Rebuilds the
  `revoked_keys` / `revoked_hashes` indexes on load. Malformed
  lines are skipped and counted via `rl_load_bad_count()` rather
  than aborting an import — a single bad line must not take down
  a CRL refresh. `rl_save(path)` / `rl_load(path)` wrappers
  included. **MEDIUM severity fix**: without this, a revocation
  list could not survive a process restart or travel between
  hosts, defeating the "revoke key/artifact" trust control.
- **`KeyMetadata.allowed_artifact_types`** (`src/trust.cyr`,
  `src/verify.cyr`). New field on `KeyVersion` (grows 88 → 96
  bytes) with `kv_add_allowed_type` / `kv_clear_allowed_types` /
  `kv_is_type_allowed`. Surfaced in `sv_verify_artifact` as a
  dedicated `"allowed_type"` trust-check independent of signature
  validity. Unset list = unrestricted (Rust `Default` behavior).
  **MEDIUM severity fix**: constrains the blast radius of a
  compromised publisher key — a key scoped to `ARTIFACT_PACKAGE`
  cannot be abused to sign a kernel image.
- **`ArtifactChange` records in `TrustStoreDiff`**
  (`src/verify.cyr`). `tsdiff_added/removed/changed` now hold
  32-byte `ArtifactChange` records with both `old_trust_level`
  and `new_trust_level` (`-1` for "n/a" — added artifacts have
  `old = -1`, removed artifacts have `new = -1`). Required
  companion change: snapshots now capture trust levels by value
  (see Breaking above) so diffs can actually compare them.
- **`MeasurementStatus` display names** (`src/integrity.cyr`).
  The enum + per-entry status field already existed from the
  original port; this release just adds coverage for the
  `Pending` / `FileNotFound` / `Error` name strings and a direct
  `FILE_NOT_FOUND` path test against a missing file.
- **`hash_data_with(data, len, algorithm)`** (`src/trust.cyr`,
  `src/hex.cyr`). Dispatches to `sha256_hex` or `sha512_hex` by
  `HASH_ALG_*`; unknown algorithm falls back to SHA-256 rather
  than returning 0 (a trust engine must never silently skip
  hashing). Added `sha512_hex` helper in `hex.cyr`. The SHA-512
  path is rarely used today but the `HashAlgorithm` enum always
  offered it as a policy option.

### Removed — dead-code sweep

`rust-old/` parity landed the full public API; a `cyrius build`-DCE
audit plus a source-level cross-reference then showed 26 functions
with zero callers anywhere in `src/`, `tests/`, `programs/`, `fuzz/`,
or `benches/`. All removed in this release. Downstream consumer
repos (`daimon`, `kavach`, `ark`, `aegis`, `phylax`, `mela`) checked
clean for every one of these names.

- **Orphaned internal helpers (4)**: `_uadd_overflow` (inlined into
  `u256_mul_full` in 2.2.0 but the body was left behind);
  `compute_file_hash` (shim over `hash_file`); `measure_system_component`
  and `verify_pcr_measurements` in `src/tpm.cyr` (orphaned by the
  2.5.0 rewrite over agnosys).
- **Unused error constructors (9)**: `err_crypto`, `err_integrity`,
  `err_invalid_input`, `err_io`, `err_key_not_found`, `err_revocation`,
  `err_serialization`, `err_sig_invalid`, and `sigil_err_name`.
  Callers always used `sigil_err(code, msg)` directly.
- **Cosignature feature (6)**: `cosignature_new`, `cosig_key_id`,
  `cosig_signature`, `artifact_add_cosigner`, `artifact_cosigners`,
  `artifact_cosigner_count`. The Rust port left the hooks in place
  but nothing ever signed or verified with multiple keys.
  `TrustedArtifact` shrinks from 96 → 80 bytes (drops `+80
  cosigners` and `+88 cosigner_count`).
- **Free-helper stubs (2)**: `trust_policy_free`, `trust_check_free`.
  The bump allocator doesn't support individual free, so these
  were lying.
- **HMAC convenience wrappers (2)**: `hmac_sign`, `hmac_verify`.
  `hmac_sha256` stays (still used by `tests/tcyr/crypto.tcyr` and
  `security.tcyr` as its own test surface).
- **Misc (3)**: `ct_eq_64` (no 64-byte constant-time compare site;
  signatures already compared as 32-byte halves or by full verify);
  `trust_level_gt` (only `trust_level_ge` was used); `stats_counts`.

### Changed — duplication cleanup

- **`u256_load_le` / `u256_store_le`** added to `src/bigint_ext.cyr`.
  Seven inline copies of the little-endian byte ↔ u256 loop
  removed from `src/ed25519.cyr` (~80 lines out).
  Sites: `ge_from_bytes`, `ge_to_bytes`, `sc_reduce` (×2 — lo+hi),
  `ed25519_sign` (×2 — load `a`, store `S`), `ed25519_verify`
  (load `S`). RFC 8032 vectors still pass.

### Fixed — JSON escape in 2.5.0 serialization

- **`_json_escape_cstr` helper** in `src/policy.cyr`. Earlier in
  2.5.0 I landed `rl_to_jsonl` / `crl_to_jsonl` writing string
  fields (`reason`, `revoked_by`, `issuer`, `key_id`,
  `content_hash`) raw — an embedded `"` or `\` produced invalid
  JSON that the parser silently truncated. Fixed before the
  release ships. Writer escapes `"`, `\`, `\n`, `\r`, `\t`, `\b`,
  `\f`, and control chars below 0x20 as `\u00XX`. Parser decodes
  the same set, including `\uNNNN`. Added a round-trip test
  exercising embedded quotes + backslash + newline.

### Test coverage

- **`tests/tcyr/sigil.tcyr`**: 55 → 78 assertions → 82 assertions
  (added JSONL escape round-trip). Added
  `hash_data_with` vectors (incl. SHA-512 FIPS 180-4
  "hello world" vector), RL/CRL JSONL round-trips (in-memory +
  file), `MeasurementStatus` name coverage, and the
  `FILE_NOT_FOUND` status path.
- **`tests/tcyr/verify.tcyr`**: 20 → 37 assertions. Added
  `allowed_type` unrestricted / restricted paths (with the full
  `sv_verify_artifact` pipeline) and `ArtifactChange` diff records
  for both added and changed artifacts.
- **Total new assertions in 2.5.0**: ~45 across six files
  (Rust-parity fold-ins + JSON escape round-trip).
- **Source stats**: 395 → 372 functions in `src/` (net -23 after
  adding `u256_load_le`, `u256_store_le`, `_json_escape_cstr`);
  dead source removed is ~120 lines, dedup saves another ~80.
- Smoke exits 0, fuzz 3/3 OK, bench 12/12 run, benchmark numbers
  stable (no perf impact from the cleanup).

## [2.4.2] — 2026-04-16

### Test coverage

Closes the two remaining 2.4.x items from `docs/development/roadmap.md`:
RFC 8032 TEST 1024 and the fuzz-corpus expansion.

- **RFC 8032 §7.1 TEST 1024** — 1023-byte message vector. Message
  bytes live in `tests/data/rfc8032/test_1024.hex` (2046 hex chars,
  no newline, extracted directly from the RFC text with byte-exact
  `sed` range). Loaded at runtime via `file_read_all`, decoded with
  `hex_decode`, then the test asserts the derived public key
  (`278117fc…d426e`), the signature bytes
  (`0aab4c90…a188a03`), and positive verify. Exercises the full
  sign/verify path on a multi-block SHA-512 input (16 transform
  blocks just for the message, plus framing).
- **`fuzz_ed25519` corpus expanded** from 3 assertions to 11:
  - **Multi-byte mutations** — 500 rounds of 5 simultaneous
    random-byte flips across `(sig, msg, pk)`. Asserts zero false
    accepts; a single false accept here would indicate a
    catastrophic algebraic break.
  - **Canonical-S reject path** (RFC 8032 §5.1.7 / §8.4) — three
    crafted signatures with `S = L`, `S = L + 1`, and
    `S = 2^256 − 1` replacing the `S` half of a valid signature.
    All must be rejected to prevent signature malleability.
  - **Point-decoding edge cases** — verify is called with an
    all-zero `pk`, an all-ones `pk`, and a pk with only the
    x-parity bit flipped. The first two must return 0 or 1 (no
    crash) and the parity-flipped pk must fail verification.
- Test-count deltas: `ed25519.tcyr` 15 → 19 assertions;
  `fuzz_ed25519` 3 → 11 assertions.
- 10/10 `.tcyr` files still pass; 3/3 fuzz harnesses OK under the
  30 s CI budget.

### Added

- `tests/data/rfc8032/` — first bundled test-data directory. Future
  large-input vectors (e.g. Ed25519ctx, SHAKE-based vectors if they
  ever land) follow the same pattern: hex file under `tests/data/`,
  loaded via `file_read_all` at test start.

## [2.4.1] — 2026-04-16

### Infrastructure

CI workflow brought forward to Cyrius 5.1.13 and the native `cyrius`
toolchain. No library/code changes — tests, benches, and fuzz
results are identical to 2.4.0.

- **`.github/workflows/ci.yml`** rewritten:
  - `CYRIUS_VERSION` bumped `3.3.4` → `5.1.13`.
  - Install path switched from `git clone MacCracken/cyrius` + raw
    `cc3` binary copy to the official `install.sh`
    (`curl … /scripts/install.sh | CYRIUS_VERSION=… sh`), which
    populates `~/.cyrius/bin/cyrius` matching local dev.
  - Every job now runs `cyrius deps` before building so the
    git-pinned sakshi 2.0.0 declared in `[deps.sakshi]` is resolved
    into `lib/sakshi.cyr`. Previously the CI would fail to locate
    that include.
  - Build job compiles the 2.2.0 smoke entry
    (`cyrius build -D SIGIL_SMOKE programs/smoke.cyr`) and runs the
    resulting binary; exit 0 is the gate.
  - Test / bench / fuzz jobs call `cyrius test`, `cyrius bench`,
    and `cyrius build` directly — no more manual
    `cat file | cc3 > out` plumbing.
  - Fuzz time budget raised from 10 s → 30 s per harness to give
    the 2000-round `fuzz_ed25519` xorshift sweep realistic headroom
    on cold runners.
  - Security scan regex tightened: previously matched the phrase
    "private key" in comments. Now requires `(private_key|secret_key|
    SECRET)` **plus** an assignment to a ≥32-char hex literal, and
    skips `test` / `example` / `rfc8032` files so RFC test vectors
    don't trip the scan.
- **`.github/workflows/release.yml`** is unchanged. It already
  consumes `ci.yml` via `workflow_call`, so it inherits the
  toolchain refresh automatically. The version-sync check
  (introduced post-2.2.0) already reads `cyrius.cyml`.

### Verified locally

- `cyrius build -D SIGIL_SMOKE programs/smoke.cyr build/sigil-smoke`
  → exit 0.
- `cyrius test` over `tests/tcyr/*.tcyr` → 10/10 pass, same as 2.4.0.
- `CYRIUS_DCE=1 cyrius bench tests/bcyr/sigil.bcyr` → 12 benches,
  numbers consistent with 2.4.0.
- `cyrius build fuzz/*.fcyr` + run with 30 s cap → 3/3 OK.

## [2.4.0] — 2026-04-16

### Breaking

- **Removed `sv_set_cache_enabled` and `sv_clear_cache`** from the
  SigilVerifier API. These were stubs: they wrote to fields at `+48`
  (`cache_enabled`) and `+64` (`cache`) but no read path consulted
  them. No in-tree or downstream consumer uses either function
  (verified across the 6 local AGNOS app repos). A verification
  cache inside a trust-boundary module without strict invalidation
  on revocation / policy change / key rotation is a CVE shape — if
  a caller ever needs caching, it belongs at a layer above sigil
  with domain-specific invalidation semantics. Deferred as a
  breaking change in the 2.1.2 CHANGELOG; now done.
- **`SigilVerifier` struct: 72 → 56 bytes.** The `cache_enabled` and
  `cache` slots are gone and `audit_log` moved from `+56` to `+48`.
  Consumers that hold raw offsets into the struct must recompile;
  anyone using the accessor functions (`sv_audit_log` etc.) is
  unaffected.

### Test coverage

- **RFC 8032 §7.1 TEST 2** (1-byte message `0x72`) and **TEST 3**
  (2-byte message `0xaf82`) added to `tests/tcyr/ed25519.tcyr`. Each
  vector verifies the derived public key, the signature bytes (not
  just verify-accepts), and the positive verify path. Signature
  bytes of TEST 1 are now also asserted (previously just printed).
- **`fp_inv` property tests** in `tests/tcyr/field.tcyr`: direct
  `fp_inv(a) · a ≡ 1 (mod p)` over a spread of inputs (1, 2, 7,
  `0xdeadbeef`, a 256-bit pseudo-random value, `p−1` self-inverse).
  Regression guard for the 2.2.0 Bernstein addition chain.
- **`fuzz/fuzz_ed25519.fcyr`**: new harness. Generates a valid
  (pk, msg, sig) triple, then 2000 rounds of deterministic
  single-byte corruption across sig/msg/pk via xorshift64 PRNG.
  Asserts every corrupted verify returns 0 or 1 (no crash, no OOB)
  and that ≥95% of corruptions are rejected.
- Test count: `ed25519.tcyr` 8 → 15 assertions; `field.tcyr` 10 →
  18 assertions. 10/10 test files still pass.
- **TEST 1024** (1023-byte message) deferred — requires bundled
  test-data file rather than an inline 2046-char hex literal.
  **TEST SHA(abc)** is ed25519ph (prehash variant); sigil only
  implements pure Ed25519, so it is out of scope.

### Added

- **`ed25519_verify` benchmark** in `tests/bcyr/sigil.bcyr`.
  Baseline ~7.2 ms: the fast `[S]B` (fixed-base table, ~1.1 ms) plus
  the CT variable-base `[h]A` (~5.4 ms) plus `ge_from_bytes` and
  SHA-512 framing. 12 benchmarks total (was 11).

### Backlog

- **CI is on Cyrius 3.3.4** (`.github/workflows/ci.yml` env var).
  The project targets 5.1.13. The workflow also uses `cc3` directly
  and bypasses `cyrius deps`, so it would not resolve sakshi 2.0.0.
  Noted for a dedicated 2.4.x infrastructure patch — too broad to
  bundle into a coverage release.

## [2.3.0] — 2026-04-16

### Performance

Fixed-base scalar multiplication for the Ed25519 base point `_ed_B`.
`ed25519_keypair` and `ed25519_sign` drop roughly **4–5×** with no
loss of constant-time discipline.

- **`_ed_B_table`** (128 KB): 64 windows × 16 precomputed points ×
  128 bytes each. Built at `ed25519_init` by repeatedly doubling and
  adding `_ed_B` — one-time init cost (~8 ms on this host), cached for
  process lifetime. Layout: `table[i][k] = k · 16^i · B`.
- **`ge_scalarmult_base(r, s)`**: 4-bit windowed comb. 64 iterations;
  each iteration does one constant-time `_ge_table_select` over all
  16 entries of row `i` and one `ge_add`. No doublings on the hot
  path.
- **`_ge_table_select`**: iterates all 16 entries unconditionally and
  uses `ge_cmov` with a branchless `eq = 1 iff k == digit` test
  (`((diff | -diff) >> 63) ^ 1`). Memory-access pattern is independent
  of the secret nibble.
- **Call sites rewired**: `ed25519_keypair` (L516), `ed25519_sign`
  (L599), `ed25519_verify` (L718). `ge_scalarmult` (variable base) is
  still used by verify for `[h]A` where `A` is the public key — that
  path retains the 2.2.1 CT loop.

| op | 2.2.1 | 2.3.0 | Δ |
|---|---|---|---|
| `ed25519_keypair` | 5.57 ms | 1.33 ms | **−76%** |
| `ed25519_sign` | 5.73 ms | 1.14 ms | **−80%** |
| `ge_scalarmult` (var-base) | 5.25 ms | 5.17 ms | ~flat |
| `fp_inv` | 265 us | 267 us | ~flat |
| `sha256_4kb` | 256 us | 255 us | ~flat |
| `ct_eq_32b` | 87 ns | 89 ns | ~flat |

### Test coverage

- Added three `ge_cmov` regression assertions to `tests/tcyr/ed25519.tcyr`
  (bit=0 unchanged, bit=1 copies, bit=1 same-value stable) so the CT
  primitive is exercised directly and not only transitively via RFC
  8032 vector 1.
- 8 assertions pass across `ed25519.tcyr` (was 5 before).
- All 10 `.tcyr` files pass.

### Memory

Process heap grows by ~128 KB after first `ed25519_*` call. This is
a one-shot bump-allocator reservation; the binary is unchanged in
size. Consumers that never call Ed25519 (e.g. pure SHA-256 users) do
not pay this cost — `_build_ed_B_table` is called from
`ed25519_init`, which is called from `ed25519_keypair`, `_sign`, and
`_verify` only.

### Trade-offs

The fixed-base table is not scatter-stored across cache lines, so a
cache-timing attacker on the same host could in principle recover
which 128-byte block was selected per window. In a hardened
multi-tenant scenario this would matter; for AGNOS's single-tenant
trust-verification role it does not. Adding scatter-load protection
is listed on the 2.4.x+ backlog (see `docs/development/roadmap.md`).

## [2.2.1] — 2026-04-16

### Security

Closes the secret-data branch in `ge_scalarmult` (`src/ed25519.cyr`).
The previous loop read bit `i` of the secret scalar `s` and took a
different code path depending on its value (`if (bit == 1)` → one
extra `ge_add`). On a shared host this yields a timing side-channel
that can reveal the Hamming weight of `s` and, with enough samples,
the scalar itself. Listed on the roadmap as v0.2.0 "Constant-time
scalar multiplication" — now done.

- **`ge_cmov(dst, src, bit)`**: branchless conditional move over a
  128-byte extended point using `mask = -bit` and bitwise XOR-select.
  No branches on `bit`; `dst` receives `src` iff `bit == 1`.
- **`ge_scalarmult`**: every iteration unconditionally computes
  `ge_add(tmp, r, q)` then `ge_cmov(r, tmp, bit_i)`. Doubling of `q`
  is likewise unconditional. No branch or memory-access pattern
  depends on any bit of `s`.

### Performance

The constant-time loop replaces ~128 conditional adds with 256
unconditional adds + 256 `ge_cmov` calls. This is the expected price
of closing the side-channel — recorded here, not treated as a
regression:

| op | 2.2.0 | 2.2.1 | Δ |
|---|---|---|---|
| `ge_scalarmult` | 3.46ms | 5.25ms | +51% |
| `ed25519_keypair` | 3.87ms | 5.57ms | +44% |
| `ed25519_sign` | ~4.0ms | 5.73ms | +43% |
| `fp_inv` | 252us | 265us | ~flat |
| `sha256_4kb` | 251us | 256us | ~flat |

`ed25519_verify` also goes through the constant-time path; verify
takes public data so constant-time is not required but harmless. The
planned 2.3.0 fixed-base precomputed table for `_ed_B` will claw back
the scalarmult cost (and then some) for keypair/sign specifically.

### Verified

- 10/10 `.tcyr` files pass, including RFC 8032 Ed25519 test vector 1
  (which exercises a mix of `bit=0` / `bit=1` iterations — a buggy
  `ge_cmov` would corrupt the public key).
- `./build/sigil-smoke` → exit 0.
- `tests/bcyr/sigil.bcyr`: all 11 benchmarks run.

## [2.2.0] — 2026-04-16

### Changed

Scaffold refactor aligning sigil with the shared AGNOS application layout
(sakshi 2.0.0, patra), plus two purely computational crypto-hot-path
optimizations. 245 assertions across 10 `.tcyr` files pass (including
RFC 8032 Ed25519 test vector 1); 11 benchmarks run.

### Performance

Two non-algorithmic wins in `src/bigint_ext.cyr`:

- **`fp_inv` via Bernstein addition chain** (254 squarings + 11 multiplies
  = 265 `fp_mul` calls) replaces the generic `fp_pow(a, p-2)` chain
  (~512 `fp_mul` calls). `fp_inv` 601 → 252us (**−58%**).
- **`_uadd_overflow` inlined** inside the `u256_mul_full` 4×4 inner
  loop (32 function calls eliminated per `fp_mul`). Amplifies into every
  downstream op.

Cumulative bench deltas (vs 2.1.2 baseline):

| op | 2.1.2 | 2.2.0 | Δ |
|---|---|---|---|
| `fp_inv` | 601us | 252us | **−58%** |
| `sc_reduce` | 36us | 29us | −19% |
| `ge_double` | 9us | 7us | −22% |
| `ge_scalarmult` | 3.99ms | 3.46ms | −13% |
| `ed25519_keypair` | 4.67ms | 3.87ms | **−17%** |
| `ed25519_sign` | ~5.0ms | ~4.0ms | **~−20%** |
| `sha256_4kb` | 254us | 251us | ~flat |
| `ct_eq_32b` | 88ns | 85ns | ~flat |

Deferred (documented for 2.3.0):

- **Fixed-base scalar-mult table** for `_ed_B` (16–64KB precomputed
  multiples) — would roughly halve keypair/sign cost at a binary-size
  tradeoff.
- **Montgomery ladder / always-add** constant-time `ge_scalarmult` —
  security fix, not a perf win. The current implementation branches on
  the secret scalar bit (`src/ed25519.cyr` L191). Listed on the roadmap
  (v0.2.0 carried forward).

- **`cyrius.cyml` replaces `cyrius.toml`**. Declares `[build] entry =
  "programs/smoke.cyr"` with `defines = ["SIGIL_SMOKE"]`, the stdlib
  surface via `[deps] stdlib = [...]`, and sakshi via `[deps.sakshi]
  git = ...`.
- **`cyrius = "5.1.13"`** — pinned from 4.5.0. The vendored `lib/*.cyr`
  stdlib files have been refreshed from `~/.cyrius/versions/5.1.13/lib/`.
- **`programs/smoke.cyr`** — new CI/smoke entry point exercising
  SHA-256, constant-time compare, Ed25519 keypair/sign/verify, and
  error-object plumbing. Guarded by `#ifdef SIGIL_SMOKE`. Exits 0 on
  success.
- **Sakshi dep is git-pinned to `2.0.0`** (previously a vendored copy
  of 0.9.0). Resolved via `cyrius deps` into
  `~/.cyrius/deps/sakshi/2.0.0/dist/sakshi.cyr`; `lib/sakshi.cyr` is
  now a managed symlink and is gitignored. Tag 2.0.0 is not yet
  folded into the Cyrius stdlib distribution — remove this block once
  it is.

### Infrastructure

- **`.gitignore`**: `/lib/sakshi.cyr` added (dep-cache symlink).
- **Build flow**: `cyrius deps && cyrius build -D SIGIL_SMOKE
  programs/smoke.cyr build/sigil-smoke`. `scripts/bundle.sh` unchanged
  and still produces `dist/sigil.cyr` with the current VERSION.

### Verified

- `./build/sigil-smoke` → exit 0.
- 10/10 `.tcyr` files pass (unchanged from 2.1.2).
- `tests/bcyr/sigil.bcyr` runs all 11 benchmarks; numbers comparable
  to pre-refactor baseline (sha256_4kb ≈ 260us, ed25519_sign ≈ 5.1ms).

## [2.1.2] — 2026-04-13

### Security

Closeout pass for the 2.1.x series. Shipped as the last patch before
2.2.0 per the CLAUDE.md closeout checklist. Addresses LOW findings
from `docs/audit/2026-04-13-audit.md` and finishes the stale-doc
sweep.

- **LOW (L11) — `ireport_summary` buffer headroom**: `src/integrity.cyr`
  enlarges the output buffer from 128 to 192 bytes. Worst-case write
  (4 × 19-digit i64 + fixed text) is ~120 bytes; new size gives safe
  headroom for any future format change.
- **LOW (L12) — `_sv_key_authorized` OOB memeq**: `src/verify.cyr`
  now bounds-checks `strlen(path) >= plen2` before calling
  `memeq(path, prefix, plen2)`. Previously, a path shorter than the
  pin prefix could read past its allocation. Bounded by the next
  heap object but still undefined behavior.

### Documentation

- **`SECURITY.md` Cryptographic Implementations**: replaced the stale
  Rust crate list (`ed25519-dalek`, `sha2`, `subtle`, `rand`) with
  the current self-hosted implementations per file, referencing the
  standards (RFC 8032, FIPS 180-4, RFC 2104). Rust `rust-old/` noted
  as reference-only.
- **`SECURITY.md` Supported Versions**: 0.2.x → 2.0.x / 2.1.x.
- **`CLAUDE.md` Status**: "Porting from Rust — TDD-first" is no
  longer accurate post-2.0 release. Updated to
  "Released (2.x), security hardening active" and retitled the TDD
  section to match (porting-specific language removed).

### Fixed

- **`src/verify.cyr` cache stubs marked**: `sv_set_cache_enabled` and
  `sv_clear_cache` write to SigilVerifier fields at +48 and +64 but
  no read path consults them. Identified during dead-code audit.
  Removal is a breaking change — documented as a stub and deferred
  to 2.2.0. No behavior change in 2.1.2.
- **`src/sha512.cyr` inner-loop line length**: the 80-round SHA-512
  inner loop's `t1` update was a single ~200-char line. Split into
  two additions against the same global (safe — no local-variable
  involvement, so the Cyrius local-clobber constraint does not
  apply). No measurable performance change.

### Chore

- **`cyrius fmt`** applied to `src/audit.cyr`, `src/trust.cyr`,
  `src/verify.cyr`. Re-indent of existing blocks; no behavioral
  diffs.
- **`cyrius lint`** clean across all `src/*.cyr`. Two residual
  warnings in `tests/tcyr/sha512.tcyr` (128-char NIST test-vector
  strings that can't be meaningfully wrapped) are accepted as
  advisory.
- **Clean build verified**: `rm -rf build && cyrius build` passes
  from scratch.

### Test coverage

- **245 assertions** across 10 `.tcyr` files (unchanged from 2.1.1;
  L11/L12 covered by existing buffer/length regression tests).
- CI `Security Scan` grep: clean.
- Fuzz harnesses: exit 0.

### Remaining / deferred to 2.2.0
- SigilVerifier cache fields removal (breaking) or wire-up.
- CI security-scan regex is coarse (matches "private key" as a
  comment phrase); tighten to require an assignment + hex literal.

## [2.1.1] — 2026-04-13

### Security

Second security hardening pass — MEDIUM findings from
`docs/audit/2026-04-13-audit.md`. Defense-in-depth against memory
disclosure and log injection.

- **MEDIUM (M6) — HMAC stack buffers zeroed on return**: `hmac_sha256`
  (`src/hmac.cyr`) now `memset`s `kprime`, `ipad`, `opad`, and
  `inner_hash` to zero before returning. Previously the derived-key
  material `K'`, `K' ⊕ 0x36`, `K' ⊕ 0x5c` could be recovered from
  stack frames via later process memory reads.
- **MEDIUM (M7) — Ed25519 secret scalars zeroed on return**:
  `ed25519_keypair` and `ed25519_sign` (`src/ed25519.cyr`) now zero
  `_kp_hash`, `_kp_scalar`, `_sign_az`, `_sign_nhash`, `_sign_r_scalar`,
  and `_sign_a_scalar` after use. These globals held the private
  scalar `a`, the per-signature nonce `r`, and the full `H(sk)`
  expansion — leaking any one recovers the private key.
- **MEDIUM (M9) — JSON injection in persistence paths**: new
  `json_write_escaped` helper in `src/trust.cyr` escapes `"`, `\`,
  and control bytes (`\b`, `\t`, `\n`, `\f`, `\r`, `\u00XX`) when
  writing user-controlled strings. `keyring_save` and
  `sv_save_trust_store` route all `key_id`, `public_key_hex`,
  `content_hash`, and `artifact_path` writes through it. Previously,
  a `"` or newline in any field corrupted the JSON and could forge
  adjacent records when re-parsed.

### Fixed

- **`sv_save_trust_store` wrote literal `"0"` for numeric fields**:
  discovered during M9 review — the function called `fmt_int(n)`
  (which prints to stdout and returns 0, not a C-string) and then
  wrote the returned `0` pointer into the JSON. Type and trust level
  fields were therefore always truncated/incorrect, and numbers leaked
  to process stdout at save time. Switched to `fmt_int_buf`. Same
  class of bug that caused the 2.1.0 fuzz harness SIGSEGV (H5).

### Added

- **`json_write_escaped(fd, s, slen)`**: public helper in
  `src/trust.cyr` for any persistence path that serializes
  user-controlled strings.
- **`tests/tcyr/security.tcyr`** extended: 18 new assertions covering
  HMAC/Ed25519 zeroization determinism and JSON escape output bytes
  for each problematic input.

### Test coverage

- **245 assertions** across 10 `.tcyr` files (was 227 in 2.1.0).
- Benchmarks within 2% of 2.1.0 (zeroization adds ~200ns per call,
  below `ed25519_sign` resolution).

### Remaining
- LOW findings (L11, L12) deferred to 2.1.2 closeout pass.

## [2.1.0] — 2026-04-13

### Security

Dedicated security hardening pass against the CLAUDE.md Security
Hardening checklist. Full audit: `docs/audit/2026-04-13-audit.md`.
This release fixes all CRITICAL and HIGH findings.

- **CRITICAL (C1) — silent weak keys on entropy failure**: `generate_keypair`
  (`src/trust.cyr`) and `tpm_random` (`src/tpm.cyr`) now check the
  `/dev/urandom` fd and `file_read` return values. Previously, if the
  fd open or read failed or returned a short count, keys were derived
  from uninitialized stack memory with no error signal. Both functions
  now loop until the requested byte count is filled and return 0 on
  any failure.
- **CRITICAL (C2) — silent fallback to zero public key**: `hex_decode`
  (`src/hex.cyr`) now rejects odd-length input and non-hex characters
  (returns 0 sentinel). Previously, `_hex_nibble` silently mapped
  invalid chars to 0, and `sv_verify_artifact` blindly consumed the
  result as a 32-byte public key. A tampered or truncated `public_key_hex`
  would decode to all zeros, opening a path to small-subgroup / zero-pk
  verification. `sv_verify_artifact` (`src/verify.cyr`) also validates
  `strlen(pk) == 64` and decode success before calling verify.
- **HIGH (H3) — Ed25519 signature malleability**: `ed25519_verify`
  (`src/ed25519.cyr`) now rejects signatures whose S scalar is
  outside `[0, L)`, per RFC 8032 §5.1.7 / §8.4. Without this check,
  an attacker could produce `(R, S+L)` as a second valid signature
  for the same `(pk, msg)` tuple.
- **HIGH (H4) — path traversal + buffer overflow in `keyring_save`**:
  `keyring_save` (`src/trust.cyr`) now validates key IDs via
  `_is_safe_key_id` (ASCII alnum, `_`, `-`, max 64 chars) and rejects
  any path whose total length exceeds the 256-byte buffer. Previously,
  a `key_id` of `../etc/passwd` or a name longer than 245 chars could
  escape `keys_dir` or overflow the heap path buffer.
- **HIGH (H5) — fuzz harness SIGSEGV masked as OK**: `scripts/check.sh`
  removed `|| true` that was swallowing crash exits. `fuzz/fuzz_integrity.fcyr`
  and `fuzz/fuzz_revocation.fcyr` rewritten — previous versions called
  `fmt_int(i)` (which prints to stdout and returns 0, not a C-string)
  and then dereferenced the result. Fuzz keys all collapsed to the same
  string and the trailing `strlen(0)` read eventually crashed on exit.
  Now use `fmt_int_buf` into a local buffer; fuzz binaries exit 0.

### Added
- **`docs/audit/2026-04-13-audit.md`**: full security audit report
  with severity, file, line, and fix plan for all 12 findings.
- **`tests/tcyr/security.tcyr`**: 21 regression tests covering each
  2.1.0 fix — hex decode validation, `hex_is_valid` predicate, Ed25519
  S ≥ L rejection (malleability), and `_is_safe_key_id` boundary cases.
- **`hex_is_valid(hex_str, hex_len)`**: new public predicate in
  `src/hex.cyr` for callers that want to validate before decoding.

### Changed
- `hex_decode` is now fallible and returns `0` on invalid input.
  **Breaking** for callers that assumed success — re-check call sites
  if you consume `hex_decode` outside sigil. Consumers inside sigil
  (`verify.cyr`) updated.
- `generate_keypair` now returns `0` on entropy failure. Callers MUST
  null-check the returned key_id before proceeding.

### Performance

No regressions vs 2.0.1 baseline (all within 3%):

| Benchmark         | 2.0.1     | 2.1.0     |
|-------------------|-----------|-----------|
| sha256_4kb        | 296us     | 286us     |
| sha512_4kb        | 156us     | 154us     |
| sc_reduce         | 52us      | 49us      |
| ge_scalarmult     | 5.773ms   | 5.457ms   |
| ed25519_keypair   | 6.923ms   | 6.405ms   |
| ed25519_sign      | 6.968ms   | 6.663ms   |
| ed25519 verify    | (S<L check: ~1us overhead, below benchmark resolution) |

### Test coverage
- **227 assertions** across 10 `.tcyr` files (was 206 in 2.0.1). New
  file: `security.tcyr` (21 assertions).
- Both fuzz binaries now exit cleanly; previously exited 139 (SIGSEGV).

## [2.0.1] — 2026-04-10

### Added
- **`dist/sigil.cyr`**: Bundled single-file distribution (4,259 lines). All 15 source
  modules concatenated with include lines stripped. Self-contained — no relative path
  resolution needed. Used by `cyrius deps` for stdlib integration.
- **`scripts/bundle.sh`**: Generates `dist/sigil.cyr` from source. Run before tagging
  a release.

## [2.0.0] — 2026-04-10

### Changed — Ed25519 Trust Layer
- **Trust signing switched from HMAC-SHA256 to Ed25519** — `sign_data` and `verify_data`
  now use real asymmetric cryptography. Verification uses the public key (not secret key).
  `generate_keypair` produces 64-byte Ed25519 sk + 32-byte pk via `ed25519_keypair`.
- **`verify_signature` renamed to `verify_data`** — takes `(data, len, sig, public_key)`
  instead of `(data, len, sig, secret_key)`. All callers updated.
- **`sv_verify_artifact` uses public key** — fetches `kv_public_key_hex` from keyring,
  decodes to 32-byte pk, verifies with `ed25519_verify`.
- **Signature size**: 64 bytes (Ed25519) instead of 32 bytes (HMAC-SHA256).

### Fixed
- **`sc_reduce` constant off-by-one**: `r256modL` ended in `951c`, correct value is `951d`.
  Caused wrong nonce/hash scalar reduction for every Ed25519 signature.
- **`sc_reduce` truncated reduction**: only did 2 levels of `hi * R` reduction (comment said
  "third level small enough to ignore" — wrong). Rewrote as iterative loop that converges
  fully (~64 iterations for 512-bit input). Carry from `u256_add` now propagated into hi.
- **`sc_muladd` allocation churn**: pre-allocated 64-byte product buffer as global.
- **`u256_sub` borrow propagation**: when `b_limb = 0xFFFFFFFFFFFFFFFF` and `borrow_in = 1`,
  the overflow to 0 silently lost the borrow. Fixed with `_sub_limb` helper that handles
  the `bl == (0-1)` case. Critical for Ed25519 since p's limbs 1,2 are all-F.
- **`u256_add` unrolled**: replaced loop with `_add_limb` helpers to avoid nested while loop
  codegen bug (Known Gotcha #6).
- **`u512_mod_p` allocation churn**: pre-allocated all temporaries (aH, aL, 38, lowp, r,
  extra, prod) as globals. Eliminates ~80KB heap churn per `fp_pow` call.
- **`fp_pow`/`fp_inv` pre-allocated**: result, base, tmp buffers allocated once.
- **Benchmark suite rewritten**: old suite called nonexistent `sha256_hex`, missing all
  crypto benchmarks. New suite: 11 benchmarks (SHA-256/512, fp_mul, fp_inv, sc_reduce,
  ge_double, ge_scalarmult, ed25519_keypair, ed25519_sign, ct_eq, hex_encode).
- **`ed25519_bug.tcyr` expected value corrected**: wrong pk for RFC 8032 test vector 1.

### Added
- **CI workflow** (`.github/workflows/ci.yml`): 5 jobs — build, test, bench, fuzz, security.
  Installs cc3 from cyrius repo tag.
- **Audit script** (`scripts/check.sh`): test suite + benchmarks + fuzz in one command.
- **Fuzz harnesses updated**: added bigint/ed25519 includes and `ed25519_init()`.
- **`rust-old/` restored**: 6,552 lines of Rust reference code recovered from git history.

### Stats
- **9 test suites, 206 assertions, 0 failures**
- **11 benchmarks**: ed25519_sign 5.7ms, ed25519_keypair 5.4ms, fp_mul 1us, sha256 300us
- **Requires Cyrius >= 3.3.4**

## [0.1.0] — 2026-04-10

### Added — Cyrius Port
- **Full port from Rust to Cyrius** — all 10 modules ported with 206 passing tests
- **Ed25519 (RFC 8032)**: keypair generation, signing, verification — byte-exact match with RFC test vectors. Built on `bigint.cyr` (4-limb u256) with custom field arithmetic over p = 2^255 - 19
- **SHA-256 (FIPS 180-4)**: streaming hash, one-shot convenience, file hashing
- **SHA-512**: required by Ed25519 for key expansion and nonce generation
- **HMAC-SHA256 (RFC 2104)**: proper ipad/opad construction, sign/verify convenience
- **Constant-time comparison**: bitwise OR accumulation, no early exit on data
- **Hex encode/decode**: for hash and key serialization
- **TrustLevel ordering**: SystemCore > Verified > Community > Unverified > Revoked with rank-based comparison
- **TrustPolicy**: builder pattern with enforcement mode, minimum trust level, hash algorithm, verification flags
- **TrustedArtifact**: path, type, hash, signature, signer, trust level, cosigners, metadata
- **VerificationResult**: artifact + checks vector + passed flag
- **SigilError**: 8 error codes (KeyNotFound, SignatureInvalid, Revocation, IntegrityMismatch, InvalidInput, IO, Serialization, Crypto)
- **PublisherKeyring**: key storage, lookup by ID/role/publisher, key rotation with overlap, chain validation, JSON persistence
- **IntegrityVerifier**: file hash measurement, verify single/all, baseline add/remove, snapshot export/import
- **RevocationList**: key and hash revocation with temporal `revoked_after` semantics, merge, O(1) lookups via hashmap index
- **CRL**: distributable certificate revocation list with version/issuer/freshness
- **AuditLog**: structured events (ArtifactVerified, ArtifactSigned, RevocationAdded, KeyRotated), JSON lines file output
- **SigilVerifier**: main trust engine — artifact verification (hash + signature + revocation + key pin + policy), signing, batch verification, compliance report, trust store snapshot/diff/persistence, boot chain verification
- **TPM module**: PcrMeasurement, AttestationResult, runtime TPM detection, system component measurement, PCR verification, seal/unseal stubs, TPM RNG with urandom fallback
- **Key zeroization**: secret key buffers zeroed after use
- Zero external dependencies (Cyrius stdlib + sakshi only)

### Removed
- Rust v1.0.0 source (was in `rust-old/`)
- Rust CI workflows, fuzz targets, cargo config, deny.toml, codecov.yml
- Rust benchmark baselines preserved in `benchmarks-rust-v-cyrius.md` for comparison

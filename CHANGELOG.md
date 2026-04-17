# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

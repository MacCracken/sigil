# Sigil — Claude Code Instructions

## Project Identity

**Sigil** (Latin: seal) — System-wide trust verification for AGNOS

- **Type**: Flat library (single-file compilation via `include`)
- **License**: GPL-3.0-only
- **Language**: Cyrius (ported from Rust)
- **Version**: SemVer, version file at `VERSION`
- **Status**: Released (2.x), security hardening active

## Genesis Layer

This project is part of **AGNOS** — an AI-native operating system. The genesis repo at `/home/macro/Repos/agnosticos` owns system-level docs, roadmap, and CI/CD.

- **Recipes**: `MacCracken/zugot` (Hebrew: pairs that enter the ark)
- **Standards**: `agnosticos/docs/development/applications/first-party-standards.md`
- **Shared crates**: `agnosticos/docs/development/applications/shared-crates.md`

## What Sigil Is

Sigil is the **single crypto/trust boundary** for the AGNOS operating system. It owns:
- Ed25519 signing and verification (publisher keyring)
- SHA-256 file integrity measurement and verification
- HMAC-SHA256 (RFC 2104) and AES-256-GCM (NIST SP 800-38D) AEAD
- Trust chain: boot chain → agent binaries → configs → packages
- Revocation list management
- Trust levels, policies, and enforcement modes

Future: PQC (ML-KEM, ML-DSA) when Cyrius implementations mature.

## Consumers

daimon, kavach, ark, aegis, phylax, mela, stiva, argonaut, and all consumer apps that need trust verification.

## Architecture

```
src/
  lib.cyr         — public API entry point (includes all modules)
  types.cyr       — TrustLevel, TrustPolicy, TrustedArtifact, VerificationResult, enums
  error.cyr       — SigilError codes, Result pattern
  trust.cyr       — Ed25519 keyring, sign/verify, key rotation, hash_data
  integrity.cyr   — File hash measurement baselines, IntegrityVerifier
  verify.cyr      — SigilVerifier (the main trust engine)
  chain.cyr       — Boot chain verification
  policy.cyr      — RevocationEntry, RevocationList, CRL
  audit.cyr       — Structured audit event logging
  tpm.cyr         — TPM interface (when agnosys exports available)
  ed25519.cyr     — Ed25519 implementation (RFC 8032)
  ct.cyr          — Constant-time comparison utilities
  aes_gcm.cyr     — AES-256-GCM AEAD (FIPS 197 + NIST SP 800-38D)
```

## Development Process

### P(-1): Scaffold Hardening (before any new features)

0. Read roadmap, CHANGELOG, and open issues — know what was intended
1. Cleanliness check: `cyrius build`, `cyrlint`, all tests pass
2. Benchmark baseline: `cyrius bench`
3. Internal deep review — gaps, optimizations, correctness, docs
4. External research — vidya entry, domain completeness, crypto best practices (RFC 8032, FIPS 180-4, RFC 2104)
5. **Security audit** — review all crypto paths, key handling, constant-time comparisons, buffer sizes, pointer validation. Run against known CVE patterns for Ed25519/SHA-256/HMAC. File findings in `docs/audit/YYYY-MM-DD-audit.md`
6. Additional tests/benchmarks from findings
7. Post-review benchmarks — prove the wins (compare against `benchmarks-rust-v-cyrius.md`)
8. Documentation audit
9. Repeat if heavy

### Work Loop (continuous)

1. **P(-1)** — Research: vidya entry before implementation
2. Work phase — implement in Cyrius, test, benchmark
3. `cyrius build` — verify compilation
4. `cyrius test` — run .tcyr test files
5. `cyrius bench` — run .bcyr benchmark files
6. Internal review — performance, memory, correctness
7. **Security check** — any new crypto code, key material handling, or input parsing reviewed for timing side-channels, buffer safety, and zeroization
8. Documentation — update CHANGELOG, roadmap, docs
9. Version check — VERSION and cyrius.cyml in sync
10. Return to step 1

### Security Hardening (before release)

Run a dedicated security audit pass before any version release. Sigil IS the trust boundary — this is non-negotiable:

1. **Input validation** — every function that accepts external data (signatures, hashes, file content, keys) validates bounds, lengths, and formats before use
2. **Buffer safety** — every `var buf[N]` and `alloc(N)` verified: N is in BYTES, max access offset < N, no adjacent-variable overflow
3. **Constant-time audit** — every hash/signature/MAC comparison uses bitwise OR accumulation with no early exit; no branches on secret data
4. **Key material zeroization** — every private key, HMAC key, and intermediate secret buffer overwritten with zeros before free
5. **Syscall review** — every `syscall()` and `sys_*()` call reviewed: arguments validated, return values checked, error paths handled
6. **Pointer validation** — no raw pointer dereference of untrusted input without bounds checking
7. **No command injection** — no `sys_system()` or `exec_cmd()` with unsanitized input. Use `exec_vec()` with explicit argv instead
8. **No path traversal** — file paths from external input validated against allowed directories. No `../` escape
9. **Known CVE check** — review Ed25519, SHA-256, HMAC implementations against current CVE databases
10. **File findings** — all issues documented in `docs/audit/YYYY-MM-DD-audit.md` with severity, file, line, and fix

Severity levels:
- **CRITICAL** — exploitable immediately, remote or privilege escalation, key leakage, signature forgery
- **HIGH** — exploitable with moderate effort, timing side-channel on secret data
- **MEDIUM** — exploitable under specific conditions
- **LOW** — defense-in-depth improvement

### Closeout Pass (before every minor/major bump)

Run a closeout pass before tagging x.Y.0 or x.0.0. Ship as the last patch of the current minor (e.g. 0.3.5 before 0.4.0):

1. **Full test suite** — all .tcyr pass, zero failures
2. **Benchmark baseline** — `cyrius bench`, save CSV; compare against `benchmarks-rust-v-cyrius.md`
3. **Dead code audit** — check for unused functions, remove dead source code
4. **Stale comment sweep** — grep for old version refs, outdated TODOs
5. **Security re-scan** — grep for new `sys_system`, unchecked writes, non-constant-time compares, missing zeroization, buffer size mismatches
6. **Downstream check** — all consumers (daimon, kavach, ark, aegis, phylax, mela, stiva, argonaut) still build and pass tests with the new version
7. **CHANGELOG/roadmap sync** — all docs reflect current state, version numbers consistent
8. **Version verify** — VERSION, cyrius.cyml, CHANGELOG header all match
9. **Full build from clean** — `rm -rf build && cyrius deps && cyrius build` passes clean

### Task Sizing

- **Low/Medium**: Batch freely — multiple items per work loop cycle
- **Large**: Small bites only — break into sub-tasks, verify each before moving to the next
- **If unsure**: Treat as large

### TDD Discipline

- Write tests FIRST for new modules/features, then implement until they pass
- Benchmarks alongside, not after — regressions vs `benches/history.csv` are a release blocker

## Key Design Constraints

- **Sigil IS the trust boundary** — every crypto decision lives here
- **Own the crypto** — Ed25519 (RFC 8032), SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104), AES-256-GCM (FIPS 197 + NIST SP 800-38D) implemented in Cyrius, no external deps
- **Inherit from libro** — SHA-256, hex encode/decode, constant_time_eq, key zeroization pattern. Improve: proper HMAC (not simplified), add Ed25519 asymmetric signing
- **Constant-time comparison** — bitwise OR accumulation for hash/signature comparison, no early exit
- **Key material zeroization** — overwrite key buffers with zeros before free
- **No timing side-channels** — crypto paths must not branch on secret data
- **Zero external dependencies** — Cyrius stdlib only (plus sakshi for tracing)
- **`fl_alloc` for structs, `alloc` for hashmaps** — freelist supports individual free; bump allocator for long-lived collections
- **Globals for cross-call state** — Cyrius single-pass compiler clobbers locals; use globals when values must survive nested calls
- **All types JSON-serializable** — `#derive(Serialize)` on all public types
- **Runtime feature detection** over compile-time gating (follow libro pattern)
- **Target size** — compiled binary contribution should be small and measurable

## Known Cyrius Compiler Quirks (5.5.32)

Most cc3-era workarounds documented in earlier sigil versions are
now resolved under cc5. Quirks still worth knowing:

1. **Local variable clobbering** — still possible across deeply
   nested call chains in cc5, though rarer than cc3. Not a
   guaranteed bug. If a local's value looks wrong after a
   function call, promote it to a global as a workaround. The
   sha256 / ed25519 / aes_gcm modules all use this pattern for
   their round-state.
2. **`fl_alloc` vs bump `alloc` discipline** — `fl_alloc` +
   `fl_free` for per-call scratch (round keys, GCM tables).
   `alloc()` for init-time tables that live the whole program
   (S-box, rcon, fixed-base combs). Never call `free()` on an
   `alloc()` block — the freelist and bump allocators are
   separate heaps and `free` only exists on the freelist side.
3. **`var buf[N]` is N bytes, not N elements** — for 80 i64
   values, declare `var buf[640]`. This is intentional, not a
   bug, but tripping on it is easy.
4. **Reserved keywords as identifiers** — `match`, `in`,
   `default`, `shared`, `object`, `case`, `else` all reject as
   variable/field/fn names. Under 5.5.26 the diagnostic is
   explicit ("expected identifier, got reserved keyword
   '<name>' — rename the variable/field/fn"); older releases
   printed "got unknown" and were confusing. If a rename-at-a-
   distance diagnostic still reads unclearly, check the token
   isn't one of these.
5. **Fixup table cap: 16384** — up from 8192 in cc3. Individual
   `store8` init blocks of 256+ entries will still hit this
   (see the S-box init in `src/aes_gcm.cyr` which instead
   decodes from a hex string literal). Split into multiple
   compilation units if you must hand-unroll.
6. **Array globals are 16-byte-aligned (since 5.5.21)** — any
   `var x[N]` with `N > 8` is placed on a 16-byte boundary by
   the x86 fixup pass. That removes the previous #GP trap on
   SSE m128 operands (PXOR / MOVDQA / AESENC m128-form) loading
   from round-key globals. Shape-sensitivity to "preceding
   globals in the TU" — the workaround used in sigil 2.9.0's
   `_aes_ni_cache = 0` staging — is no longer needed. Re-enable
   the AES-NI dispatch and re-test; if any residual silent-
   discard remains it's a separate fixup/CP bug not covered by
   the alignment patch.
7. **Stdlib thread-safety (5.5.31/32)** — atomics + race-free
   mutex are available (`lib/atomic.cyr`, `lib/thread.cyr`);
   `string.cyr` is safe by construction. **But:** `alloc`,
   `hashmap`, and `vec` are NOT thread-safe. A multi-threaded
   sigil path (e.g. parallel `sv_verify_batch` fan-out) must
   either pre-allocate all per-worker scratch in the main
   thread before spawn, or mutex-wrap every call into
   containers shared across workers. Alloc-from-worker with no
   mutex will corrupt the bump pointer. Prefer the
   pre-allocate-upfront pattern — it sidesteps the whole
   problem and the verify hot path only reads read-only
   globals (fixed-base comb, round-key tables).

### Resolved under cc5 (stop treating as bugs)

- **`\r` escape sequence** — works since 4.x. Don't hand-emit
  byte 13 with `store8(buf, 13)`.
- **Negative literals `-1`, `-N`** — work since 3.10.3. No need
  for `(0 - N)`.
- **Compound assignment `+=`, `-=`, `*=`, etc.** — work since 3.10.3.
- **Undefined functions** — cc5 still resolves them as a fall-
  through stub that crashes at call time rather than a compile-
  time error. The aes_gcm bring-up hit this: a stray `free(...)`
  call (from muscle memory, no such function in sigil's world)
  crashed at runtime with a segfault loop. When a test silently
  "restarts main" forever, suspect an undefined-function call.
- **256-initialized-global cap** — removed.
- **`map_get` after `map_set` in deep call chains** — resolved.

## DO NOT

- **Do not commit or push** — the user handles all git operations
- **NEVER use `gh` CLI** — use `curl` to GitHub API only
- Do not add unnecessary dependencies (there should be close to zero)
- Do not skip benchmarks before claiming performance improvements
- Do not store private keys in plaintext
- Do not branch on secret data in crypto paths
- Do not use `sys_system()` with unsanitized input — command injection risk
- Do not trust external data (signatures, hashes, file content, keys) without validation
- Do not skip key zeroization — every secret buffer overwritten before free

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, LICENSE

docs/ (required):
  architecture/overview.md — module map, data flow, consumers
  development/roadmap.md — completed, backlog, future

docs/ (when earned):
  adr/ — architectural decision records
  audit/ — security audit reports (YYYY-MM-DD-audit.md)
  guides/ — usage guides, integration patterns
  sources.md — source citations for algorithms (Ed25519, SHA-256, etc.)
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). Performance claims MUST include benchmark numbers. Breaking changes get a **Breaking** section with migration guide. Security fixes get a **Security** section with CVE references where applicable.

## Current Status

- **Ported from**: Rust v1.0.0 (149 tests, 12 benchmarks); original
  Rust source removed in 2.7.0 after parity closeout. See the
  2.0.0 → current CHANGELOG entries for the port audit trail.
- **Rust benchmark baseline**: `benchmarks-rust-v-cyrius.md`
  (archived comparison, not rebuilt per release).
- **Version**: see `VERSION` for current.
- **Phase**: Released, security audit workflow active.

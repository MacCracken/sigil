# Sigil — Claude Code Instructions

> **Core rule**: this file is **preferences, process, and procedures** — durable rules that change rarely. Volatile state (current version, test counts, in-flight slots, consumers, recently shipped releases) lives in [`docs/development/state.md`](docs/development/state.md), bumped every release. **Do not inline state here.**

## Project Identity

**Sigil** (Latin: seal) — system-wide trust verification for AGNOS.

- **Type**: Flat library (single-file compilation via `include`)
- **License**: GPL-3.0-only
- **Language**: Cyrius (toolchain pin in `cyrius.cyml [package].cyrius`)
- **Version**: `VERSION` at project root is the source of truth — do not inline the number here
- **Genesis repo**: [agnosticos](https://github.com/MacCracken/agnosticos)
- **Standards**: [first-party-standards.md](https://github.com/MacCracken/agnosticos/blob/main/docs/development/planning/first-party-standards.md) · [first-party-documentation.md](https://github.com/MacCracken/agnosticos/blob/main/docs/development/planning/first-party-documentation.md)
- **Shared crates**: [shared-crates.md](https://github.com/MacCracken/agnosticos/blob/main/docs/development/planning/shared-crates.md)

## Goal

Sigil is the **single crypto / trust boundary** for AGNOS. It owns:

- Ed25519 signing and verification (publisher keyring)
- ECDSA P-256 / P-384 verification (TEE attestation chains) **and** RFC 6979 deterministic signing (`src/ecdsa_sign.cyr`)
- SHA-256 / SHA-384 / SHA-512 hashing (file integrity, signature schemes)
- HMAC-SHA256 (RFC 2104) and HKDF-SHA256 (RFC 5869)
- AES-256-GCM (FIPS 197 + NIST SP 800-38D) AEAD
- ML-DSA-65 (FIPS 204) post-quantum signing (default-on since 3.7.6; `-D SIGIL_PQC` is now a back-compat no-op)
- X.509 + PEM parsing for TEE attestation
- TEE attestation orchestrators for Intel SGX DCAP v3, Intel TDX v4, AMD SEV-SNP
- Trust chain: boot chain → agent binaries → configs → packages
- Revocation list management
- Trust levels, policies, and enforcement modes

## Current State

> Volatile state lives in [`docs/development/state.md`](docs/development/state.md) — current version, test/assertion counts, in-flight work, recently shipped releases, consumers, audit floor. Refreshed every release.
> Historical release narrative lives in [`CHANGELOG.md`](CHANGELOG.md) (per-tag chronology).

This file (`CLAUDE.md`) is durable rules only.

## Scaffolding

Sigil was scaffolded as a port from Rust v1.0.0 (original Rust source removed in 2.7.0 after parity closeout). New crypto primitives go in their own module under `src/`; new consumer-facing surface goes through `src/verify.cyr`. **Do not manually create project structure** — follow the existing module layout and `src/lib.cyr` include order.

## Quick Start

```bash
cyrius build programs/smoke.cyr build/sigil          # full build (smoke probe)
for t in tests/tcyr/*.tcyr; do cyrius test "$t"; done # full test suite
cyrius bench tests/bcyr/sigil.bcyr                    # benchmarks (where applicable)
CYRIUS_DCE=1 cyrius build ...                         # DCE release build
```

## Key Principles

- **Sigil IS the trust boundary** — every crypto decision lives here. Don't push crypto choices onto consumers.
- **Own the crypto** — Ed25519 (RFC 8032), ECDSA P-256/P-384 (FIPS 186-4), SHA-2 family (FIPS 180-4), HMAC (RFC 2104), HKDF (RFC 5869), AES-256-GCM (FIPS 197 + NIST SP 800-38D), ML-DSA-65 (FIPS 204) implemented in Cyrius, no external deps. See [`docs/sources.md`](docs/sources.md) for the citation index.
- **Constant-time on secret data** — bitwise-OR accumulation for hash/signature/MAC compares; no early-exit branches on key material.
- **Key zeroization** — every private key, HMAC key, PRK, and intermediate secret buffer overwritten before free. Prefer `secret var` (cyrius 5.3.5) for compiler-guaranteed zeroization on scope exit. **Exception — per-worker banked scratch:** arrays banked across `cbank()` lanes (`src/crypto_scratch.cyr`) must be **plain `var` + an explicit per-lane `memset`**, *never* `secret var`. A `secret var` whole-array wipe on scope exit zeroizes *all* lanes, clobbering a concurrent worker's in-flight lane (the 3.8.0 ChaCha20/X25519 banking bug — caught by `banking_concurrent.tcyr`). See quirk #9 and ADR 0004.
- **Zero external dependencies** — Cyrius stdlib only (plus `sakshi` for tracing, plus `agnosys` for kernel interfaces).
- **`fl_alloc` for individually-freed scratch, `alloc` for init-once tables** — never `free()` a bump-allocated block (heaps don't cross).
- **All types JSON-serializable** — `#derive(Serialize)` on every public type for cross-process logging.
- **Runtime feature detection** over compile-time gating — AES-NI, SHA-NI dispatchers detect at boot, not at compile time.
- **Test after every change** — `cyrius build` then the relevant `.tcyr` file. Zero failures.

## Rules (Hard Constraints)

- **NO UNILATERAL DECISIONS — every decision is the user's (Robert), and must be approved BEFORE acting (added 2026-06-03).** The assistant has no standing authority to decide scope, what ships, what is "good enough," or what is left out. **No deferral, descope, split, reorder, cut, or "defer to a later version" of ANY work item without first requesting approval and receiving an explicit go-ahead.** Surface every option and the full set of affected/remaining items, then wait. Never bury a deferred or backlog item — name it explicitly and get sign-off. When in doubt, ask; do not assume.
- **Read the genesis repo's CLAUDE.md first** — [agnosticos/CLAUDE.md](https://github.com/MacCracken/agnosticos/blob/main/CLAUDE.md).
- **Do not commit or push** — the user handles all git operations.
- **NEVER use `gh` CLI** — use `curl` against the GitHub API if needed.
- Do not add unnecessary dependencies (close to zero).
- Do not store private keys in plaintext.
- Do not branch on secret data in crypto paths.
- Do not use `sys_system()` with unsanitized input — command-injection risk. Use `exec_vec()` with explicit argv.
- Do not trust external data (signatures, hashes, file content, keys, X.509/PEM bytes, TEE quote bytes) without validation.
- Do not skip key zeroization — every secret buffer overwritten before free.
- Do not skip benchmarks before claiming performance improvements.
- Do not hardcode the toolchain version anywhere outside `cyrius.cyml [package].cyrius`.

## Process

### P(-1): Scaffold Hardening (before any new features)

0. Read roadmap, CHANGELOG, and open issues — know what was intended.
1. Cleanliness check: `cyrius build`, `cyrlint`, all tests pass.
2. Benchmark baseline: `cyrius bench`.
3. Internal deep review — gaps, optimizations, correctness, docs.
4. External research — vidya entry, domain completeness, crypto best practices (relevant RFCs / FIPS).
5. **Security audit** — review all crypto paths, key handling, constant-time comparisons, buffer sizes, pointer validation. Run against known CVE patterns for Ed25519 / SHA-256 / HMAC / AES-GCM / X.509. File findings in `docs/audit/YYYY-MM-DD-audit.md` (or `YYYY-MM-DD-<version>-audit.md` for multi-cycle days).
6. Additional tests / benchmarks from findings.
7. Post-review benchmarks — prove the wins.
8. Documentation audit — see [`docs/doc-health.md`](docs/doc-health.md).
9. Repeat if heavy.

### Work Loop (continuous)

1. **P(-1)** — Research: vidya entry before implementation.
2. Work phase — implement in Cyrius, test, benchmark.
3. `cyrius build` — verify compilation.
4. `cyrius test` — run the relevant `.tcyr` file(s).
5. `cyrius bench` — run benchmarks if perf-sensitive.
6. Internal review — performance, memory, correctness.
7. **Security check** — any new crypto code, key-material handling, or input parsing reviewed for timing side-channels, buffer safety, and zeroization.
8. Documentation — update CHANGELOG, roadmap, `docs/development/state.md`, any ADR the change earned.
9. Version check — `VERSION` and `cyrius.cyml` in sync.
10. Return to step 1.

### Security Hardening (before release)

Run a dedicated security audit pass before any version release. Sigil IS the trust boundary — this is non-negotiable:

1. **Input validation** — every function that accepts external data (signatures, hashes, file content, keys) validates bounds, lengths, and formats before use.
2. **Buffer safety** — every `var buf[N]` and `alloc(N)` verified: N is in BYTES, max access offset < N, no adjacent-variable overflow.
3. **Constant-time audit** — every hash / signature / MAC comparison uses bitwise OR accumulation with no early exit; no branches on secret data.
4. **Key material zeroization** — every private key, HMAC key, and intermediate secret buffer overwritten with zeros before free.
5. **Syscall review** — every `syscall()` and `sys_*()` call reviewed: arguments validated, return values checked, error paths handled.
6. **Pointer validation** — no raw pointer dereference of untrusted input without bounds checking.
7. **No command injection** — no `sys_system()` or `exec_cmd()` with unsanitized input. Use `exec_vec()` with explicit argv.
8. **No path traversal** — file paths from external input validated against allowed directories. No `../` escape.
9. **Known CVE check** — review Ed25519 / SHA-256 / HMAC / AES-GCM / X.509 implementations against current CVE databases.
10. **File findings** — all issues documented in `docs/audit/YYYY-MM-DD-audit.md` with severity, file, line, and fix.

Severity levels:

- **CRITICAL** — exploitable immediately; remote or privilege escalation; key leakage; signature forgery.
- **HIGH** — exploitable with moderate effort; timing side-channel on secret data.
- **MEDIUM** — exploitable under specific conditions.
- **LOW** — defense-in-depth improvement.

### Closeout Pass (before every minor/major bump)

Run a closeout pass before tagging `x.Y.0` or `x.0.0`. Ship as the last patch of the current minor (e.g. `0.3.5` before `0.4.0`):

1. **Full test suite** — all `.tcyr` pass, zero failures.
2. **Benchmark baseline** — `cyrius bench`, save CSV; compare against the prior closeout.
3. **Dead code audit** — check for unused functions, remove dead source code.
4. **Stale comment sweep** — grep for old version refs, outdated TODOs.
5. **Security re-scan** — grep for new `sys_system`, unchecked writes, non-constant-time compares, missing zeroization, buffer size mismatches.
6. **Downstream check** — all consumers listed in `docs/development/state.md` still build and pass tests with the new version.
7. **CHANGELOG / roadmap / state.md sync** — all docs reflect current state, version numbers consistent.
8. **Version verify** — `VERSION`, `cyrius.cyml`, CHANGELOG header all match.
9. **Full build from clean** — `rm -rf build && cyrius deps && cyrius build` passes clean.

### Task Sizing

- **Low / Medium**: batch freely — multiple items per work loop cycle.
- **Large**: small bites only — break into sub-tasks, verify each before moving on.
- **If unsure**: treat it as large.

### TDD Discipline

- Write tests **first** for new modules / features, then implement until they pass. The 3.4.0 PEM decoder and 3.4.1 `snp_report_verify_full` shipped this way — match the pattern.
- Benchmarks alongside, not after — regressions vs `benches/history.csv` are a release blocker.

## Known Cyrius Compiler Quirks

Most cc3-era workarounds documented in earlier sigil versions are now resolved under cc5/cc6. Quirks still worth knowing live as numbered architecture notes under [`docs/architecture/`](docs/architecture/) so they're discoverable from the affected module's docs:

1. **`var X[N]` inside a function is a static global, not a stack-local** — confirmed by cyrius `src/frontend/parse_fn.cyr:2886` and `tests/tcyr/var_array_semantics.tcyr` (still true under cycc 6.0.52). Same-function array reuse across sequential calls works iff each call fully writes the buffer before reading; concurrent threads share the array. This used to force the `_sigil_batch_mutex` to serialise batch verify; **3.6 dropped the mutex** by giving each worker a private *bank* (lane) of every racing array via thread-local storage (`src/crypto_scratch.cyr`, cyrius 6.0.52 `lib/thread_local.cyr`) — see ADR 0001. **3.9.6: `cbank()` now AUTO-ASSIGNS a lane per thread on first use** (atomic counter → lanes `1..63`, bank 0 = main/serial), so concurrent callers — notably cyrius `tls_native`/sandhi TLS workers — get disjoint lanes with NO `crypto_bank_set` call; `SIGIL_CRYPTO_BANKS` is now 64 (every banked `var X[N]` is sized `N*64`). This closed the concurrent-TLS-handshake crash — see ADR 0007. Scalar `var x = ...` locals ARE per-call.
2. **`fl_alloc` vs bump `alloc` discipline** — `fl_alloc` + `fl_free` for per-call scratch; `alloc()` for init-once tables that live the whole program. Never `free()` an `alloc()` block — separate heaps.
3. **`var buf[N]` is N bytes, not N elements** — for 80 i64 values declare `var buf[640]`. Intentional, not a bug.
4. **Reserved keywords as identifiers** — `match`, `in`, `default`, `shared`, `object`, `case`, `else`, and `secret` (the `secret var` qualifier) all reject as variable / field / fn / **parameter** names. The error is `expected identifier, got unknown` reported at the offending `fn`/`var` line (3.6.1: a `secret` parameter in `tls12_prf.cyr` tripped this — renamed to `sec`).
5. **Fixup-table cap: 16384** — up from 8192 in cc3. Individual `store8` init blocks of 256+ entries can hit this; see `src/aes_gcm.cyr`'s S-box init for the workaround (decode from hex string literal).
6. **Array globals are 16-byte-aligned (since 5.5.21)** — any `var X[N]` with N > 8 lands on a 16-byte boundary. Removes the prior SSE-load #GP shape sensitivity for AES-NI round-key globals.
7. **Stdlib thread-safety (5.5.31/32)** — atomics + race-free mutex are available; `string.cyr` is safe by construction. **But:** `alloc`, `hashmap`, and `vec` are NOT thread-safe. Multi-threaded sigil paths must pre-allocate per-worker scratch on the main thread before spawn.
8. **Preprocessor output cap (was 1 MB, raised in cyrius 6.0.87)** — through 3.7.5 the sigil + stdlib + agnosys + mldsa expansion sat just over the 1 MB cap, so PQC was a `-D SIGIL_PQC` cmdline opt-in. **6.0.87 raised the cap**: the full unconditional build now compiles clean, so **3.7.6 made PQC default-on** (dropped the `#ifdef SIGIL_PQC` in `src/lib.cyr`; the flag is now a no-op). The `dist/sigil.cyr` bundle always included mldsa (via `[lib].modules`), so this only changed the `src/lib.cyr` build path. If a future stdlib growth re-approaches the cap, re-gate or split the bundle.
9. **Banked per-worker secret scratch = plain `var` + per-lane `memset`, never `secret var` (since 3.8.0)** — function-scope `var X[N]` arrays are static globals (quirk #1); concurrent crypto paths therefore bank them across `cbank()` lanes (`var X[N*SIGIL_CRYPTO_BANKS]; var Xb = &X + cbank()*N;`, `src/crypto_scratch.cyr`). A banked array that holds secret state (x25519's clamped scalar `k`; chacha20's keystream `st`/`ws`/`ks`) **must not** be `secret var`: the compiler's whole-array zeroize-on-exit wipes every lane, clobbering a sibling worker's live lane (a real intermittent corruption — the `banking_concurrent.tcyr` race-detector flagged it at 1–2 mismatches/run). Use plain `var` and `memset` **only the calling worker's own lane** (`memset(Xb, 0, N);`) before return — that preserves per-call secret zeroization without touching another lane. The proven `fp_mul`/`fp_inv` banking is plain `var` for the same reason. See ADR 0004.

## CI / Release

- **Toolchain pin**: `cyrius = "X.Y.Z"` in `cyrius.cyml [package]`. **No separate `.cyrius-toolchain` file** and no hardcoded version strings elsewhere.
- **Dead code elimination**: release builds run with `CYRIUS_DCE=1`. Binary size is a release metric.
- **Tag filter**: release workflow triggers on semver-only tags. Non-numeric tags do not ship.
- **Version-verify gate**: release asserts `VERSION == cyrius.cyml version == git tag` before building.
- **State sync**: release post-hook bumps `docs/development/state.md`. If the hook doesn't, fix the hook — don't hand-maintain state.

## Docs

- [`docs/adr/`](docs/adr/) — architecture decision records. *Why did we choose X over Y?*
- [`docs/architecture/`](docs/architecture/) — module map + non-obvious invariants. *What can't I derive from the code alone?*
- [`docs/audit/`](docs/audit/) — per-cycle security audit reports.
- [`docs/development/roadmap.md`](docs/development/roadmap.md) — forward-looking work + closed cycles.
- [`docs/development/state.md`](docs/development/state.md) — **live state snapshot, refreshed every release.**
- [`docs/doc-health.md`](docs/doc-health.md) — fresh / stale / archive ledger across the doc tree.
- [`docs/sources.md`](docs/sources.md) — RFC / FIPS / NIST citation index for every crypto primitive.
- [`CHANGELOG.md`](CHANGELOG.md) — source of truth for all changes.

New quirks and constraints land in `docs/architecture/` as numbered items (`NNN-kebab-case.md`). New decisions land in `docs/adr/` using [`template.md`](docs/adr/template.md). **Never renumber either series.**

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md,
  SECURITY.md, CODE_OF_CONDUCT.md, LICENSE,
  VERSION, cyrius.cyml

docs/ (minimum):
  adr/                      ADR series (README + template + NNNN-*.md)
  architecture/             Module map + numbered invariants (README + NNN-*.md)
  audit/                    Per-cycle security audits (YYYY-MM-DD-*.md)
  development/
    roadmap.md              Forward-looking work
    state.md                Live state snapshot (refreshed per release)
  doc-health.md             Whole-tree doc-currency ledger
  sources.md                RFC / FIPS / NIST citation index

docs/ (when earned):
  security/                 Threat model + security architecture (broader than SECURITY.md)
  guides/                   Task-oriented how-tos
  examples/                 Runnable examples
  benchmarks.md             Perf history (current: benches/history.csv + benchmarks-rust-v-cyrius.md)
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). Performance claims **must** include benchmark numbers. Breaking changes get a **Breaking** section with migration guide. Security fixes get a **Security** section with CVE references where applicable. Maintain an `[Unreleased]` section at the top for in-flight changes between releases.

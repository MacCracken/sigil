# Sigil Roadmap

Forward-looking work only. For shipped items and version history
see [CHANGELOG.md](../../CHANGELOG.md). The 2.x cycle's originally
scoped plan is complete; the 3.0 cycle's working scope sits in
[`3.0-scope.md`](3.0-scope.md); the 3.2 cycle's working scope sits
in [`3.2-scope.md`](3.2-scope.md) and the TEE-attestation sub-arc
in [`3.2-tee-arc.md`](3.2-tee-arc.md).

## Shipped — foundation for 3.0

The 3.0 branch carries the parallel-batch infrastructure and the
breaking-change cleanups; the 2.9.x line on `main` (merged into
3.0 on 2026-05-01) carries the crypto-pillar work that was
originally framed as "blocked on Cyrius" in earlier roadmaps.
Briefly:

- **PQC primitives.** ML-DSA-65 (NIST FIPS 204) sign/verify in
  `src/mldsa.cyr` with RFC-style test vectors; hybrid Ed25519 +
  ML-DSA-65 dual signatures via `sigil_verify_hybrid` and
  `SIG_ALG_HYBRID`. Behind `-D SIGIL_PQC` (1 MB preprocessor cap;
  see CLAUDE.md quirk #8).
- **Hardware crypto hot paths.** AES-NI (2.9.1, 363× block-encrypt
  speedup) and SHA-NI (2.9.3, 21–44× compress speedup) with
  CPUID-probed dispatch and software fallback. Both constant-time,
  alignment-guarded, no public surface change.
- **Key-derivation.** HKDF-SHA256 (RFC 5869) on top of the
  existing HMAC-SHA256 primitive.
- **Constant-time hardening.** `ct_select` from `lib/ct.cyr`
  adopted in `ge_cmov`; `ct_eq_32` / OR-accumulation discipline
  audited across every signature / hash / MAC compare.
- **aarch64 portability** via agnosys 1.0.4 — per-arch syscall
  surfaces; sigil itself stays a pure crypto + trust library.
- **Parallel batch verify infrastructure**, default-on at
  `count >= _SIGIL_BATCH_PARALLEL_THRESHOLD` (228/228 tests,
  mutex-wrap shape; correctness preserved, no throughput win
  yet — alloc-free rewrite lives in 3.1). The original
  `-D SIGIL_BATCH_PARALLEL` cmdline gate was dropped once cyrius
  5.5.37 raised the fixup-table cap.
- **Breaking changes for 3.0.0:** `TRUST_COMMUNITY` enum variant
  removed (slot 2 unassigned for persisted-state compat);
  `alog_append_to_file` → `alog_save`, `alog_load_from_file` →
  `alog_load`.

## Shipped — 3.1.x line

The 3.1 cycle re-scoped from its originally-planned "alloc-free
verify hot path" rewrite into a stdlib-modernisation arc as
cyrius advanced through 5.10.x → 5.11.x → 6.0.x. The hot-path
rewrite carries forward to 3.2.0 (see below).

- **3.1.0 (2026-05-06)** — SemVer-label correction for 3.0.2's
  removal of `src/ct.cyr` and the public `ct_eq` / `ct_eq_32`
  symbols (correctly a minor bump, not a patch). No code delta
  vs 3.0.2.
- **3.1.1 (2026-05-11)** — stdlib annotation pass: every public
  fn in `src/*.cyr` carries a `: i64` return-type annotation
  matching cyrius's v5.11.x annotation arc. Parse-only, zero
  runtime / codegen change. Cyrius pin bumped 5.9.20 → 5.11.4.
- **3.1.2 (2026-05-21)** — cyrius pin bumped 5.11.4 → 6.0.1
  (cc6 stdlib-resolution path bug fixes + UEFI fn-call UD2
  emit fix); sakshi 2.2.3 → 2.2.5; agnosys 1.0.4 → 1.2.7
  (multi-profile distlib); `lib/slice.cyr` added to the stdlib
  set (agnosys 1.2.7 uses first-class slice subscripts). CI
  `CYRIUS_VERSION` env synced to the new pin. The 3.1.2 ship
  implicitly resolved the open argonaut/libro aarch64
  ed25519-verify P1
  ([`issues/archive/2026-05-10-ed25519-verify-aarch64-accepts-wrong-pk.md`](issues/archive/2026-05-10-ed25519-verify-aarch64-accepts-wrong-pk.md))
  and silenced the x86_64 surface of the majra NI `[rbp-N]`
  drift P1 — the structural fix for the latter carries forward
  to 3.2.0 as defense-in-depth.

## Road to v3.2

**Working scope:** [`3.2-scope.md`](3.2-scope.md). **Cyrius pin:**
**6.0.1** (synced across `cyrius.cyml` and CI during the 3.1.2
ship-cut). cc6's annotation pass + stdlib-resolution fixes are
the load-bearing toolchain features for the cycle.

3.2 splits into a tight 3.2.0 batch followed by an independent
patch series (3.2.x TEE attestation arc). Sequencing rationale:
3.2.0 closes out the 3.1 carry-over and the silenced-but-
structural NI bug; the TEE arc opens once the foundation is
clean.

### 3.2.0 batch — defense + hot-path

Scope and closeout criteria in [`3.2-scope.md`](3.2-scope.md).
Headline items:

- **NI dispatch parameters off the stack frame.** Migrate the
  hardcoded `[rbp-N]` parameter loads in `src/aes_ni.cyr` and
  `src/sha_ni.cyr` to module-level globals. Defense-in-depth
  for [`issues/2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md`](issues/2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md)
  — the bug currently does not reproduce under cyrius 6.0.1
  (24/24 tests pass on 3.1.2) but the structural defect
  remains.

- **Alloc-free `sv_verify_artifact` rewrite.** The originally-
  scoped 3.1 work item. Lifts `alloc` / `vec_push` / `map_get`
  out of the mutex-wrapped parallel-batch worker body so the
  3.0 batch-verify infrastructure delivers actual throughput
  (target: ≥ 3× at 4 workers). **Cyrius prerequisite:**
  confirm cc6's `alloc` / `vec` / `hashmap` thread-safety
  status before starting — quirk #7 floor was 5.5.32; cc6's
  stdlib pass may have advanced it.

- **Three-way bench.** Serial / 3.0 mutex-wrap / 3.2 alloc-
  free comparison row added to `benches/history.csv`.

- **`cyrlint` cleanup + CI gate.** Re-run against cc6's
  expanded `cyrlint`, address surviving warnings, wire into
  `.github/workflows/ci.yml` matching the agnosys / yukti
  pattern.

- **Downstream re-test sweep.** Re-poll phylax against the new
  floor (cyrius 6.0.1 + sigil 3.1.2 → 3.2.0) for
  [`issues/2026-05-11-tlsh-distance-segfault-phylax.md`](issues/2026-05-11-tlsh-distance-segfault-phylax.md).
  Most likely toolchain-folded by the cc6 cut; needs phylax-
  side bisect to confirm. Argonaut/libro aarch64 path also
  needs a real-silicon confirmation to fully close out the
  archived ed25519-verify P1.

## Towards v3.3 — per-worker crypto state

The 3.2.0 alloc-free rewrite removed the allocator from the
parallel-batch worker body but discovered the **deeper**
bottleneck: every crypto module (`sha256.cyr`, `ed25519.cyr`,
`aes_gcm.cyr`) uses module-level globals for working state as
a cyrius local-clobbering workaround (CLAUDE.md quirk #1).
Concurrent workers running `sha256_transform` race on
`_sha_ctx` / `_sha_a..h` / `_sha_t1/t2` / `_sha_i` /
`_sha256_W`; equivalent globals in the other modules.

The 3.0 mutex-wrap and 3.2.0 alloc-free paths both serialise
on `_sigil_batch_mutex` precisely because of these globals —
verified during 3.2.0 dev (mutex-off → 30/228 batch_parallel
fail; mutex-on → pass).

**3.3 work item: lift crypto module state to per-call scratch.**

- [ ] **`sha256.cyr` — per-call scratch.** Move `_sha_ctx`,
      `_sha_a..h`, `_sha_t1/t2`, `_sha_i`, `_sha256_W` from
      module globals into a caller-provided scratch block.
      Audit every call site for the cyrius local-clobbering
      pattern that originally motivated the globals (quirk #1
      — promote-to-global was the recommended workaround).
      cycc 6 may have improved the codegen enough that locals
      survive; verify before declaring done.

- [ ] **`ed25519.cyr` — per-call scratch.** Same shape.
      ed25519_verify is the dominant verify-path cost
      (~6.4 ms per artifact under SHA-NI on the dev host)
      and the load-bearing item for parallel speedup.

- [ ] **`aes_gcm.cyr` — per-call scratch.** Same shape. AES-GCM
      isn't on the batch-verify hot path today, but the same
      refactor closes a future parallel-encrypt scenario.

- [ ] **Drop `_sigil_batch_mutex` once the three modules
      ship.** Re-bench `sv_verify_batch_64` against the 3.2.0
      `v3.2.0-allocfree` baseline; the target remains 3×+ at
      4 workers. Add CSV row `v3.3-parallel-crypto`.

The 3.3 cycle could open immediately after 3.2.0 tags or
defer behind the 3.2.x TEE arc — sequencing decision deferred
to when the arc closes.

### 3.2.x sub-arc — TEE attestation

Scope, sequencing, and module surface in
[`3.2-tee-arc.md`](3.2-tee-arc.md). Origin:
[`issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md`](issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md)
(kavach P1, sigil-side P3 — enhancement, no current forcing
function). The arc opens once 3.2.0 ships and tags
independently per-bite:

| Tag    | Module surface                                  | Unblocks |
|--------|-------------------------------------------------|----------|
| 3.2.1  | ECDSA P-256 verify                              | foundation |
| 3.2.2  | Minimal X.509 cert-chain walker                | foundation |
| 3.2.3  | `src/sgx.cyr` — quote parse + verify           | kavach SGX backend |
| 3.2.4  | `src/sev_snp.cyr` — VCEK chain + report verify | kavach SEV backend |
| 3.2.5  | `src/tdx.cyr` — TD-quote (shares SGX chain)    | kavach TDX backend |
| 3.2.6  | `src/seal.cyr` — SGX sealing                   | kavach SGX persistence |

Each bite is independently shippable. If the arc stalls (kavach
roadmap shifts, or a higher-priority sigil item like ML-KEM-768
jumps the queue), the incomplete arc parks cleanly at the last
shipped minor — no half-implemented module surface in tree.

## Sigil-internal — unscheduled

- [ ] **Scatter-store for the fixed-base comb.** Distribute the
      128-byte point entries across cache lines so a cache-timing
      attacker on the same host cannot recover which nibble was
      selected per window. Not needed for AGNOS's single-tenant
      deployment; queue if the threat model shifts to multi-tenant.

- [ ] **CLMUL-assisted GHASH.** GCM 1 KB encrypt / decrypt sits
      around 700 µs after AES-NI landed (2.9.1) — GHASH (bit-by-bit
      GF(2^128) multiply) now dominates. PCLMULQDQ / VPCLMULQDQ
      can close the gap. Same byte-encoding pattern as SHA-NI /
      AES-NI; depends on cyrius inline-asm support being on the
      same level as the existing NI dispatchers.

- [ ] **`secret var` ambient adoption.** ~20 `memset(..., 0, ...)`
      sites across `src/hkdf.cyr` / `src/aes_gcm.cyr` /
      `src/mldsa.cyr` (counted post-merge); roughly 8 are true
      private-key / PRK / round-key / GHASH-state buffers, the
      rest are intermediate scratch. `secret var` (cyrius 5.3.5)
      gives compiler-guaranteed zeroization. Land in-place when
      a future edit touches one of those call sites — no separate
      pass needed.

- [ ] **`cyrlint` cleanup + workflow gate.** 2.9.5 release notes
      document 35 lint warnings under 5.7.x's expanded `cyrlint`
      (line length > 120, the benign `policy.cyr` local-var
      shadow). Trim the warnings and wire `cyrlint` into
      `.github/workflows/ci.yml` to match agnosys's pattern.

## Possible future surfaces

Out-of-scope today; surface if a consumer asks for them:

- **ML-KEM-768 (PQC KEM).** Sigil is a verification / signing
  library; key agreement belongs in a sibling module (potential
  future `kem.cyr`) if any AGNOS consumer surfaces a need.
- **Dedicated `sigil_batch_verify_parallel` entry point.** Not
  needed if `sv_verify_batch` fans out by default at the
  threshold; one entry point is the simpler API.
- **Per-worker arena allocator (Option 3).** Middle-ground
  alternative to the alloc-free rewrite. Drops out of scope if
  Option 1 lands cleanly.

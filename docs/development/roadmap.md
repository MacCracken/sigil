# Sigil Roadmap

Forward-looking work only. For shipped items and version history
see [CHANGELOG.md](../../CHANGELOG.md). The 2.x cycle's originally
scoped plan is complete; the in-flight 3.0 cycle's working scope
sits in [`3.0-scope.md`](3.0-scope.md) (folded into CHANGELOG once
3.0.0 tags).

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

## Road to v3.1

v3.1 is defined by **making parallel batch verify actually fast**.
The 3.0 landing shipped the spawn / join / shard / mutex
infrastructure but the mutex wraps the full `sv_verify_artifact`
call chain because its downstream hits `alloc` / `vec_push` /
`map_get`, none of which are thread-safe under cyrius (CLAUDE.md
quirk #7). Measured 0.96× – 1.04× vs serial — correctness
preserved, no throughput win. Real parallelism on the dominant
`ed25519_verify` (~6.4 ms per artifact under SHA-NI) requires
lifting the allocations out of the worker body.

**Cyrius toolchain status:** sigil is currently pinned to
**5.7.48**. The fixup-table cap raise (filed 2026-04-22, shipped
in cyrius 5.5.37) is in and the parallel-batch gate has already
been removed in 3.0. The remaining upstream blocker:

- Stdlib thread-safety on `alloc` / `vec` / `hashmap` — cyrius
  5.5.32 deferred the design (per-thread arena vs full spinlock
  vs CAS-bump-ptr were all in flight). Current status unknown
  post-5.7.48 — needs an upstream check before the 3.1 rewrite
  starts.

### 3.1 work items

- [ ] **Alloc-free verify hot path (Option 1 rewrite).** Rewrite
      `sv_verify_artifact` and its call chain to accept caller-
      provided scratch instead of allocating internally:
      - `hash_file` returns a caller-provided hex buffer rather
        than `alloc`-ing one per call
      - `hex_decode` writes into a caller-provided 32-byte buffer
      - `trust_check_new` + `vresult_add_check` → replace the
        per-check vec with a bounded fixed-size check array on
        `verification_result` (≤ 6 standard checks; size with
        headroom)
      - `verification_result_new` → in-place construction into a
        pre-allocated output slot
      - `map_get` on the trust store — document read-only-is-safe
        contract, or wrap in an rwlock
      Expected wins: 3× + speedup at 4 workers, lower per-artifact
      latency, cleaner thread-safety story, smaller attack
      surface.

- [ ] **Three-way bench.** Serial / 3.0 mutex-wrap parallel /
      3.1 alloc-free parallel comparison published in
      `tests/bcyr/batch_parallel.bcyr` output, with CSV row added
      to `benches/history.csv`.

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

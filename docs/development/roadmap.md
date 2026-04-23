# Sigil Roadmap

Forward-looking work only. For shipped items and version history
see [CHANGELOG.md](../../CHANGELOG.md). At v2.8.x the originally
scoped 2.x plan is complete; everything below is work toward 3.0.

**Shipped in 2.8.4:** AES-256-GCM AEAD primitive (`src/aes_gcm.cyr`)
— FIPS 197 block cipher + NIST SP 800-38D GCM mode, software-only.
Consumed by majra's `ipc_encrypted.cyr`. A hardware AES-NI path
remains future work (blocked on Cyrius inline-asm support).

## Road to v3.1

v3.1 is defined by **making parallel batch verify actually fast**.
The 3.0 landing shipped the spawn/join/shard/mutex infrastructure
gated behind `-D SIGIL_BATCH_PARALLEL`, with correctness preserved
(228/228 tests) but measured 0.96x – 1.04x vs serial — no
throughput win. The mutex wraps the full `sv_verify_artifact`
call chain because its downstream hits `alloc` / `vec_push` /
`map_get`, none of which are thread-safe under cyrius (quirk #7).
Actual parallelism on the dominant `ed25519_verify` (~8.4 ms per
artifact) requires lifting those allocations out of the worker
body.

**Target cyrius toolchain: 5.6.0.** The 3.1 work deliberately
waits for the cyrius 5.6 major bump rather than starting on
5.5.37 (which ships the fixup-cap raise). Rationale: 5.6 is
expected to bring broader language/stdlib improvements, and the
Option 1 rewrite is a big enough rework to warrant the
consolidated toolchain upgrade. If the cap raise in 5.5.37 is
the only 3.1 dependency that matters for a specific subtask,
that subtask can be cherry-picked earlier — but the full 3.1
cycle opens on 5.6.0.

- [ ] **Alloc-free verify hot path (Option 1 rewrite).** Rewrite
      `sv_verify_artifact` and its call chain to accept caller-
      provided scratch instead of allocating internally. Scope
      captured in `docs/development/3.0-scope.md` § Post-3.0
      follow-ups:
      - `hash_file` returns a caller-provided hex buffer rather
        than `alloc`-ing one per call
      - `hex_decode` writes into a caller-provided 32-byte
        buffer
      - `trust_check_new` + `vresult_add_check` → replace the
        per-check vec with a bounded fixed-size check array on
        `verification_result` (≤ 6 standard checks; size with
        headroom)
      - `verification_result_new` → allow in-place construction
        into a pre-allocated output slot
      - `map_get` on the trust store — document read-only-is-safe
        contract, or wrap in a rwlock
      Expected wins: 3x+ speedup at 4 workers (ed25519_verify
      truly parallel outside the mutex), lower per-artifact
      latency, cleaner thread-safety story, smaller attack
      surface.

- [ ] **Ungate `SIGIL_BATCH_PARALLEL`.** Conditional on the
      cyrius 16384 fixup-table cap lifting (tracked in
      `docs/development/issues/2026-04-22-cyrius-fixup-cap-raises.md`).
      When cyrius raises the cap, remove the gate in
      `src/verify.cyr` + `src/lib.cyr` so the parallel path is
      the default at `count >= _SIGIL_BATCH_PARALLEL_THRESHOLD`.
      Keep the flag for one cycle as a no-op compatibility
      shim, then drop it.

- [ ] **Bench the 3.1 rewrite against 2.9.1 and the 3.0 mutex-
      wrap baseline.** Three-way comparison (serial / 3.0 mutex-
      wrap parallel / 3.1 alloc-free parallel) published in
      `tests/bcyr/batch_parallel.bcyr` output, with CSV row
      added to `benches/history.csv`.

## Road to v3.0

v3.0 is defined by **post-quantum capability** and **parallel
batch verification**. Both require upstream work in Cyrius before
sigil can act — landed items in
[cyrius/docs/development/roadmap.md](../../../cyrius/docs/development/roadmap.md)
under "v5.2.x / v5.3.x — Sigil 3.0 enablers".

### Blocked on Cyrius 5.2.x

- [ ] **ML-DSA-65 signing / verification** — NIST FIPS 204
      (lattice-based post-quantum). Needs `lib/keccak.cyr`
      (SHAKE-128/256) in Cyrius stdlib for the XOF step.
      Once available, land as `src/mldsa.cyr` alongside
      `src/ed25519.cyr`, with its own RFC-style test vectors.
- [ ] **Hybrid Ed25519 + ML-DSA-65 dual signatures.** A `SigilVerifier`
      configured with a hybrid policy requires both algorithms to
      validate before admitting an artifact. Transitional: once
      PQC is mandated, the pure-Ed25519 path is deprecated. `TrustPolicy`
      gains a `required_signature_algorithms` vec.

### Blocked on Cyrius 5.3.x

- [ ] **Parallel batch verification.** `sv_verify_batch` currently
      serialises work on a single thread. Once Cyrius threading
      stabilises (`lib/thread.cyr` is present but sigil hasn't
      exercised it), batch verify fans out across cores. The
      fixed-base comb is already constant-time and thread-safe
      (read-only table), so the fan-out is clean.
- [ ] **Adopt `ct_select` builtin** from `lib/ct.cyr` once it
      lands. Drops `ge_cmov`'s inline mask arithmetic in favour
      of the stdlib primitive. Mechanical replacement; reduces
      the security-audit surface.
- [ ] **Adopt `secret var` for key material** when the language
      feature ships. 8 hot-path call sites in sigil currently end
      with a manual `memset(sk, 0, ...)` — a `secret` qualifier
      lets the compiler guarantee zeroization and catches forgetful
      edits at build time.

### Sigil-internal (no Cyrius blocker)

- [ ] **Scatter-store for the fixed-base comb.** Distribute the
      128-byte point entries across cache lines so a cache-timing
      attacker on the same host cannot recover which nibble was
      selected per window. Not needed for AGNOS's single-tenant
      deployment; queue as a hardening option if the threat model
      shifts to multi-tenant.
- [ ] **Dedicated `sigil_batch_verify_parallel` entry point.**
      Wrapper over `sv_verify_batch` once threading lands.

### 3.0 breaking changes (staged)

Cleanups that have been accumulating but were deferred to avoid
mid-minor breakage. All go out in a single 3.0 bump so downstream
consumers update once.

- [ ] **~~Drop `hmac.cyr` module entirely.~~** _Superseded — hmac
      stays sigil-internal as an HKDF implementation detail._
      The 2.9.0 HKDF landing made `src/hkdf.cyr` a direct
      consumer of `hmac_sha256` (4 call sites in the extract +
      expand paths), so the "no sigil-internal caller" premise
      no longer holds. New stance: `src/hmac.cyr` is a private
      primitive — consumers should call `hkdf_*` / future AEAD
      surfaces, not `hmac_sha256` directly. The module header
      in `src/hmac.cyr` documents this. No public surface
      change; tests retain the hmac-specific assertions as
      unit coverage of the primitive.
- [ ] **Remove the `TRUST_COMMUNITY` enum variant** if it remains
      unused after a 3.0 consumer audit. Grep today: one test
      reference, no production path.
- [ ] **Rename `alog_append_to_file` → `alog_save`** to match the
      `rl_save` / `crl_save` / `sv_save_trust_store` vocabulary.
      Keep `alog_load_from_file` → `alog_load`. Pure rename.

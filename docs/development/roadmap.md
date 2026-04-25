# Sigil Roadmap

Forward-looking work only. For shipped items and version history
see [CHANGELOG.md](../../CHANGELOG.md). At v2.8.x the originally
scoped 2.x plan is complete; everything below is work toward 3.0.

**Shipped in 2.8.4:** AES-256-GCM AEAD primitive (`src/aes_gcm.cyr`)
— FIPS 197 block cipher + NIST SP 800-38D GCM mode, software-only.
Consumed by majra's `ipc_encrypted.cyr`. A hardware AES-NI path
remains future work (blocked on Cyrius inline-asm support).

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
- [ ] **SHA-256 hot-path throughput investigation.** Surfaced by sit
      v0.6.4 perf review (2026-04-25). Sigil's current SHA-256 tops
      out at ~12 MB/s on 64KB inputs (10us at 64B, 87us at 1KB,
      5.27ms at 64KB per [sit's v0.6.4 bench snapshot](../../../sit/docs/benchmarks/2026-04-25-v0.6.4.md)).
      Modern x86_64 SHA-NI hardware paths hit ~1 GB/s — ~80x headroom.
      This is the dominant cost in sit's `status-100files` (100×
      hash_file_as_blob) and `add-1MB` (single 1MB blob hash =
      ~80ms of the 210ms total), so any throughput gain there
      directly improves user-visible sit latency. Likely investigation
      paths: (a) inline-asm SHA-NI when available; (b) hand-tuned
      ARMv8 SHA2 extension when available; (c) software-only
      micro-opts in the round function. cyrius 5.5.22+ exposes
      `asm { byte; … }` blocks per the `_thread_spawn` precedent,
      so the toolchain gate for hardware-path inline asm is cleared.
      Staged for delivery on the 2.9.x line as 2.9.2 (probe + NI
      compress) so sit picks up the throughput win without waiting
      on the 3.0 release. Tracking entry remains here until shipped;
      moves to CHANGELOG on completion.

### 3.0 breaking changes (staged)

Cleanups that have been accumulating but were deferred to avoid
mid-minor breakage. All go out in a single 3.0 bump so downstream
consumers update once.

- [ ] **Drop `hmac.cyr` module entirely.** `hmac_sha256` still
      ships but has no sigil-internal caller — only exercised by
      `tests/tcyr/crypto.tcyr` + `security.tcyr`. Ed25519 replaced
      HMAC in every sigil flow. Consumers that want HMAC should
      pull it from a dedicated stdlib module; sigil shouldn't be
      the carrier.
- [ ] **Remove the `TRUST_COMMUNITY` enum variant** if it remains
      unused after a 3.0 consumer audit. Grep today: one test
      reference, no production path.
- [ ] **Rename `alog_append_to_file` → `alog_save`** to match the
      `rl_save` / `crl_save` / `sv_save_trust_store` vocabulary.
      Keep `alog_load_from_file` → `alog_load`. Pure rename.

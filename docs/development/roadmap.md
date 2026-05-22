# Sigil Roadmap

Forward-looking work only. For shipped items and version history
see [CHANGELOG.md](../../CHANGELOG.md). For in-flight cycle scope:

- [`3.2-tee-arc.md`](3.2-tee-arc.md) — 3.2.x TEE attestation
  sub-arc (6-bite patch series, ECDSA → X.509 → SGX → SEV-SNP →
  TDX → SGX seal).
- [`3.2-scope.md`](3.2-scope.md) — 3.2.0 cycle history (closed).
- [`3.0-scope.md`](3.0-scope.md) — 3.0 cycle history (closed).

**Cyrius pin:** `6.0.1` (synced across `cyrius.cyml` and CI).

## Road to v3.2.x — TEE attestation arc

Patch series tracker in [`3.2-tee-arc.md`](3.2-tee-arc.md).
Origin: [`issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md`](issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md)
(kavach P1, sigil-side P3 — enhancement, no current forcing
function). Each minor in the arc tags independently on `main`:

| Tag    | Module surface                                  | Unblocks |
|--------|-------------------------------------------------|----------|
| 3.2.1  | ECDSA P-256 verify ✅ (2026-05-21)              | foundation |
| 3.2.2  | Minimal X.509 cert-chain walker                 | foundation |
| 3.2.3  | `src/sgx.cyr` — quote parse + verify            | kavach SGX backend |
| 3.2.4  | `src/sev_snp.cyr` — VCEK chain + report verify  | kavach SEV backend |
| 3.2.5  | `src/tdx.cyr` — TD-quote (shares SGX chain)     | kavach TDX backend |
| 3.2.6  | `src/seal.cyr` — SGX sealing (MRSIGNER/ISVSVN)  | kavach SGX persistence |

If the arc stalls (kavach roadmap shifts, or a higher-priority
sigil item like ML-KEM-768 jumps the queue), the incomplete arc
parks cleanly at the last shipped minor — no half-implemented
module surface in tree. The 3.3 cycle (below) can open in
parallel with or after this arc.

## Road to v3.3 — per-worker crypto state

The 3.2.0 alloc-free rewrite removed the allocator from the
parallel-batch worker body but discovered the *deeper*
bottleneck: every crypto module (`sha256.cyr`, `ed25519.cyr`,
`aes_gcm.cyr`) uses module-level globals for working state as
a cyrius local-clobbering workaround (CLAUDE.md quirk #1).
Concurrent workers running `sha256_transform` race on
`_sha_ctx` / `_sha_a..h` / `_sha_t1/t2` / `_sha_i` /
`_sha256_W`; equivalent globals in the other modules. The
3.2.0 ship verified this experimentally — mutex-off → 30/228
`batch_parallel.tcyr` fail; mutex-on → pass.

3.3 lifts those globals into per-call scratch so the
`_sigil_batch_mutex` can finally drop. Target: 3×+ throughput
at 4 workers on `sv_verify_batch_64`, the load-bearing item
that 3.2.0's alloc-free rewrite set up but couldn't close.

### 3.3 work items

- [ ] **`sha256.cyr` — per-call scratch.** Move `_sha_ctx`,
      `_sha_a..h`, `_sha_t1/t2`, `_sha_i`, `_sha256_W` from
      module globals into a caller-provided scratch block.
      Audit every call site for the cyrius local-clobbering
      pattern that originally motivated the globals (quirk
      #1 — promote-to-global was the recommended workaround).
      cycc 6 may have improved the codegen enough that locals
      survive; verify before declaring done.

- [ ] **`ed25519.cyr` — per-call scratch.** Same shape.
      `ed25519_verify` is the dominant verify-path cost
      (~6.4 ms per artifact under SHA-NI on the dev host) and
      the load-bearing item for parallel speedup.

- [ ] **`aes_gcm.cyr` — per-call scratch.** Same shape.
      AES-GCM isn't on the batch-verify hot path today, but
      the same refactor closes a future parallel-encrypt
      scenario.

- [ ] **Drop `_sigil_batch_mutex` once the three modules
      ship.** Re-bench `sv_verify_batch_64` against the 3.2.0
      `v3.2.0-allocfree` baseline; target ≥ 3× at 4 workers.
      Add CSV row `v3.3-parallel-crypto`.

**Sequencing decision:** 3.3 can open immediately after a
3.2.x TEE bite tags, or defer behind the full TEE arc.
Likely path: open after 3.2.2 (X.509 walker) lands — that
gives kavach a meaningful integration milestone while the
crypto refactor proceeds in parallel.

## Backlog — unscheduled

Items with a clear shape but no forcing function. Land
in-place when an adjacent edit touches the relevant module.

- [ ] **Scatter-store for the fixed-base comb.** Distribute
      the 128-byte point entries across cache lines so a
      cache-timing attacker on the same host cannot recover
      which nibble was selected per window. Not needed for
      AGNOS's single-tenant deployment; queue if the threat
      model shifts to multi-tenant.

- [ ] **CLMUL-assisted GHASH.** AES-GCM 1 KB encrypt/decrypt
      sits around 700 µs after AES-NI landed (2.9.1) — GHASH
      (bit-by-bit GF(2^128) multiply) now dominates.
      PCLMULQDQ / VPCLMULQDQ closes the gap. Same byte-
      encoding pattern as the existing SHA-NI / AES-NI
      dispatchers. Gated on the cyrius `asm`-block global-
      symbol pseudo (filed upstream as
      [`cyrius/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md))
      — without it CLMUL adds another `[rbp-N]`-coupled asm
      site to maintain.

- [ ] **`secret var` ambient adoption.** ~20 `memset(..., 0,
      ...)` sites across `src/hkdf.cyr` / `src/aes_gcm.cyr` /
      `src/mldsa.cyr` (counted post-3.0 merge); roughly 8 are
      true private-key / PRK / round-key / GHASH-state
      buffers, the rest intermediate scratch. `secret var`
      (cyrius 5.3.5) gives compiler-guaranteed zeroization.
      Land in-place when a future edit touches one of those
      call sites — no separate pass.

- [ ] **NI dispatch structural fix.** When the upstream
      cyrius `asm`-block global-symbol pseudo lands (issue
      linked above), migrate
      `src/aes_ni.cyr:aes256_encrypt_block_ni`,
      `src/aes_ni.cyr:_aes_ni_cpuid_probe`,
      `src/sha_ni.cyr:_sha_ni_compress_one`, and
      `src/sha_ni.cyr:_sha_ni_cpuid_probe` off hardcoded
      `[rbp-N]` parameter loads. The 3.2.0 runtime self-test
      gate catches misemits at boot; the structural fix
      removes the brittleness entirely. Keep the self-test
      gate even after the structural fix lands — defence-in-
      depth.

## Possible future surfaces

Out-of-scope today; surface if a consumer asks for them.

- **ML-KEM-768 (PQC KEM).** Sigil is a verification / signing
  library; key agreement belongs in a sibling module (potential
  future `kem.cyr`) if any AGNOS consumer surfaces a need.
  ML-DSA-65 (PQC sign) already shipped in 2.9.x behind
  `-D SIGIL_PQC`.

- **PQC-default builds.** PQC currently sits behind the
  `-D SIGIL_PQC` cmdline flag because the full sigil + stdlib
  + agnosys + mldsa expansion sits right at cyrius cc5's 1 MB
  preprocessor buffer cap (CLAUDE.md quirk #8). When cyrius
  raises this cap (or adds a flag to select a larger buffer),
  flip PQC to default-on and drop the cmdline gate.

- **P-384 ECDSA verify.** Some TDX deployments use P-384
  attestation keys. If the 3.2.5 `src/tdx.cyr` bring-up
  surfaces a real consumer need, slot `src/ecdsa_p384.cyr`
  between 3.2.5 and 3.2.6. Otherwise P-256 (shipping in
  3.2.1) covers the documented Intel / AMD chains.

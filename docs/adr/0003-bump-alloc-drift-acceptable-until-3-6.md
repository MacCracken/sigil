# 0003 — Per-call bump-alloc drift in `*_verify_full` orchestrators is acceptable until 3.6

**Status**: Accepted
**Date**: 2026-05-22

> **Amendment (2026-05-27):** the unified `_into` / Solinas cycle
> referenced below (and in the filename) as "3.6" was renumbered to
> **3.7** — and the parallel-verify "3.5" to "3.6" — when the 3.5
> slot was reassigned to the modern-crypto arc. Read "3.6" here as
> "3.7". The seven-LOW audit floor and the decision are unchanged;
> the ADR file is not renamed (NNNN index is immutable).

## Context

Seven open LOW audit findings (one in 3.2.2, one in 3.2.4, two
in 3.4.0, one in 3.4.1, plus two from `_sgxv_init` /
`_tdxv_init` carried forward from 3.2.3 / 3.2.5) all share the
same shape: a per-call init path allocates scratch via the
bump allocator without a matching free. For long-running
consumers (kavach's batch-attestation loop), the per-call drift
sums to ~5–8 KB per `*_verify_full` call. At sustained
throughput this is a real memory pressure.

The fix is the **unified `_into` API**: every parser /
verifier gets an `_into` variant that takes a caller-provided
scratch buffer, mirroring 3.2.0's `sv_verify_artifact_into`
and 3.4.0's `pem_decode_certs_into`. The fix is mechanical but
invasive — every `x509_cert_alloc`, every `_sgxv_init`,
every `_tdxv_init`, every `_snp_v_init`, every `_pem_init`,
and the three `*_verify_full` orchestrators all gain a
scratch parameter; their callers update.

The 3.4 cycle deliberately did not attempt this fix
incrementally because:

1. The seven findings are the same shape — fixing them
   one-by-one would touch the same modules seven times,
   producing seven LOC-churn patches.
2. The audit shape lets future-reader trace the LOWs as a
   batch ("these all close together in 3.6") rather than as
   independent findings.
3. The fix's natural sequencing pairs with the Solinas
   reduction work (also in roadmap 3.6): both touch the same
   modules and benefit from re-benchmarking together.

## Decision

Defer all seven bump-alloc-drift LOW findings to a single
unified `_into` API closure in the v3.6 cycle. Until then:

- Each new `*_verify_full`-shape orchestrator added in a 3.x
  cycle ships with a documented bump-alloc note in its module
  header (see `src/sgx.cyr`, `src/tdx.cyr`, `src/sev_snp.cyr`).
- Per-cycle audits explicitly carry the LOW finding forward,
  not as a new finding but as a tracked open item.
- `docs/development/state.md` maintains the running count
  under "Audit floor".

**Sequencing**: open 3.6 when a downstream consumer surfaces
a latency or memory-pressure complaint (kavach's batch flow,
ark's signature-heavy publisher workflow). Until then, the
verify path is fast enough for one-shot use, and the drift is
not exploitable.

## Consequences

- **Positive**: sigil ships `*_verify_full` end-to-end
  orchestrators in 3.4 without waiting for the perf
  refactor. Consumers get the API immediately; the perf
  cleanup arrives when it's earned.
- **Positive**: the 3.6 cycle has clear scope (Solinas
  reduction + unified `_into` API) instead of being
  scattered.
- **Negative**: the audit floor sits at 7 open LOWs across
  releases. Honest about the trade-off; the audit docs make
  the floor explicit and document why it's safe.
- **Negative**: any consumer benchmarking sigil in the 3.4–3.5
  window will see the drift in long-running workloads. The
  docs warn about it; no consumer has hit it as a blocker yet.
- **Neutral**: when 3.6 opens, the closure work is well-defined
  — every offending site is named, every shape is documented.
  The work itself is straightforward; the cycle's invasiveness
  is in the call-chain threading, not the algorithm.

## Alternatives considered

- **Fix each LOW as it's introduced** — rejected; produces
  seven LOC-churn patches across the same modules. The 3.4
  cycle would have shipped TEE-completion work plus a
  parallel _into-refactor stream, doubling the review surface.
- **Use `fl_alloc` / `fl_free` inside the verify_full
  orchestrators to free scratch at exit** — rejected; the
  underlying `x509_cert_alloc` and `_xx_init` paths use the
  bump allocator internally. Even with `fl_alloc` in the
  outer scope, the inner allocs still drift. Fixing this
  requires the unified `_into` API — same scope as 3.6.
- **Promote scratch to long-lived module globals** — rejected;
  this is what 3.3 attempted (in-function `var X[N]` arrays)
  and got bitten by the static-array semantics. Module
  globals are race-prone under concurrent verify_full calls
  (which is the explicit motivation for 3.5's caller-scratch
  refactor — see ADR 0001).

# 0001 — Retain `_sigil_batch_mutex` until caller-scratch lands

**Status**: Accepted
**Date**: 2026-05-22

## Context

The 3.3 cycle opened with the goal of dropping
`_sigil_batch_mutex` so `sv_verify_batch` could fan out across
worker threads in parallel. The mutex serialises every call
into the crypto modules' shared globals (sha256 round-state,
ed25519 group-element scratch, fp arithmetic temporaries),
which throttles batch throughput to single-threaded speed
regardless of how many workers a caller provides.

The implementation hypothesis was that cycc 6 had fixed
cc3-era local-clobbering, so in-function `var X[N]` array
declarations would be per-call stack arrays. Under that
hypothesis, the mutex drop is mechanical: replace named module
globals with in-function arrays and concurrent workers each
get their own scratch.

The hypothesis was wrong. Cyrius's
`src/frontend/parse_fn.cyr:2886`
("DON'T restore VCNT — arrays inside functions are globals
that persist") and the user-space probe at
`tests/tcyr/var_array_semantics.tcyr` establish that **array
declarations inside a function are static function-scope
globals**, not stack arrays. Storage is unchanged from the
3.2.x named-global form; concurrent workers still race.

The 3.3 cleanup itself was real (−190 LOC; init-guard
simplifications; SHA-512 alloc-free init variant), so the
cycle shipped as a cleanup-only release with the mutex
retained. The proper mutex-drop architecture requires threading
caller-provided scratch through every crypto entry point — a
substantially more invasive refactor.

## Decision

Retain `_sigil_batch_mutex` through the 3.3 and 3.4 cycles.
Queue the mutex drop for a dedicated 3.5 cycle whose scope is:

- **In**: caller-provided crypto scratch threaded through every
  top-level entry point (`sha256`, `sha512`, `ed25519_verify`,
  `ed25519_sign`, `aes_gcm_encrypt`, `aes_gcm_decrypt`,
  `hash_file_into`); scratch threaded through every internal
  primitive (`fp_*`, `ge_*`, `sha*_transform`, `sc_*`); per-
  worker scratch pool in `sv_verify_batch`; mutex drop with
  `batch_parallel.tcyr` mutex-off remaining 228/228 green.
- **Out**: cleanup-style refactors, opportunistic perf tuning,
  any work that doesn't sit on the critical mutex-drop path.

**Sequencing**: open 3.5 when there's a forcing function — a
downstream consumer hitting mutex contention, or an AGNOS
milestone that requires the parallel speedup. The refactor is
invasive enough that it should be done in one focused sprint,
not incrementally.

## Consequences

- **Positive**: 3.3 + 3.4 ship with a stable mutex behaviour
  that all consumers already tolerate. The 3.4 TEE-completion
  work landed cleanly on top of the retained mutex without any
  contention surprises. The 3.5 cycle has a clear, bounded
  scope when it opens.
- **Negative**: Batch verify is single-threaded-equivalent
  until 3.5 lands. For kavach's batch-attestation use case
  (which prompted the original 3.3 goal), this is a known
  ceiling; consumers needing throughput beyond it must serialise
  or run multiple sigil processes.
- **Neutral**: The 3.3 refactor's swap of named globals →
  in-function arrays had no functional advantage (same static
  storage), but the form is cleaner — locality of scope, no
  module-level pollution. 3.5's inverse pass will route every
  in-function array either to a slice of the scratch buffer or
  back to a proper module-level global where the data is
  truly read-only after init.

## Alternatives considered

- **Drop the mutex via in-function arrays anyway** — rejected
  after the static-array discovery. Concurrent workers would
  race silently; tests might pass under low contention and
  fail in production.
- **Worker-thread spawn with mutex-wrap on every primitive call** —
  rejected; mutex-wrapping every internal `fp_mul` / `ge_add`
  call would defeat the parallelism. The bottleneck is the
  shared state, not the call dispatch.
- **Library-owned per-thread-id scratch pool** — rejected for
  3.5's scope; introduces a thread-local mechanism sigil
  doesn't have today. Caller-provided scratch is simpler and
  matches the existing 3.2.0 `sv_verify_artifact_into`
  pattern.

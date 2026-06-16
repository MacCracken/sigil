# 0002 — ML-DSA-65 ships behind `-D SIGIL_PQC`

**Status**: Accepted — **resolved/superseded at 3.7.6 (PQC now default-on)**
**Date**: 2026-04-20

> **Resolution (2026-06-07, 3.7.6):** the trigger this ADR documented —
> "flip to default-on once the toolchain can build the unconditional
> expansion" — was met when **cyrius 6.0.87 raised the preprocessor
> output cap** (CLAUDE.md quirk #8). 3.7.6 dropped the `#ifdef SIGIL_PQC`
> gate in `src/lib.cyr`; **ML-DSA-65 is default-on and `-D SIGIL_PQC` is
> a back-compat no-op.** (The `dist/sigil.cyr` bundle always carried
> mldsa via `[lib].modules`, so only the `src/lib.cyr` build path
> changed.) This ADR is retained for the rationale; the decision it made
> is no longer in force.

## Context

ML-DSA-65 (FIPS 204, post-quantum signing) landed in sigil at
2.9.0. The implementation lives in eight `src/mldsa_*.cyr`
files: params, reduce, ntt, poly, rounding, encode, sample,
and the top-level `mldsa.cyr`. Total expansion: ~2,100 lines
of Cyrius on top of the existing ed25519 baseline.

Cyrius cc5 has a hard 1 MB cap on preprocessor output buffer
size (`src/frontend/lex.cyr:1436` checks `op > 1048576`). The
full sigil + Cyrius stdlib + agnosys + mldsa expansion sits
right at the cap:

- Default build (no flag): ~930 KB expansion, under cap.
- With `-D SIGIL_PQC` cmdline: ~1,047 KB, squeaks in by ~1 KB.
- Unconditional (no `#ifdef`): 1,049,596 B — **over cap by ~1 KB**.
- Moving the define from cmdline into source (e.g.
  `#define SIGIL_PQC 1` at the top of `src/lib.cyr`) costs
  extra expansion bytes in the IFDEF pass and overflows by
  another ~1 KB.

The cmdline-only opt-in path is the **only** form that fits
under cap with mldsa included.

## Decision

Gate the ML-DSA-65 modules behind `#ifdef SIGIL_PQC` in
`src/lib.cyr` and require consumers to pass `-D SIGIL_PQC` to
the `cyrius build` invocation. The flag is **cmdline-only** —
defining the symbol in source overflows the preprocessor cap.

Consumers that need PQC (daimon, kavach, future post-quantum
publishers) build with the flag; the default build keeps the
ed25519-only surface.

Test files reference the individual `src/mldsa_*.cyr` modules
directly (see `tests/tcyr/mldsa*.tcyr`), so the PQC code
remains exercised in CI regardless of the gate. The default
sigil build does NOT exercise mldsa.

**Cycle review**: when cyrius raises the `preprocess_out`
buffer cap beyond 1 MB (or adds a flag to select a larger
buffer), flip ML-DSA to default-on and drop the `#ifdef`
gate.

## Consequences

- **Positive**: sigil ships with PQC support for consumers
  that need it today, without forcing the default build to
  fight the preprocessor cap.
- **Negative**: PQC is **not** in the public default surface.
  Consumers must remember to pass `-D SIGIL_PQC`. Documentation
  in multiple places must call this out (README, CLAUDE.md,
  CHANGELOG entries that touch mldsa).
- **Neutral**: Test coverage is unaffected — `tests/tcyr/mldsa*.tcyr`
  always run regardless of the flag. The dist bundle
  `dist/sigil.cyr` includes the mldsa modules so a consumer
  including the bundle still gets PQC.

## Alternatives considered

- **Always include mldsa, accept the cap overflow** — rejected;
  the build doesn't compile. Not a real option until cyrius
  raises the cap.
- **Split mldsa into its own sibling repo / crate** — rejected
  for now. The agnosticos shared-crates pattern allows this
  but the natural seam is "post-quantum signature primitives"
  which is exactly what sigil owns. A separate `mldsa-sigil`
  crate would either duplicate sigil's RNG / hex / hashing
  surface or take a circular dep on it.
- **Compile-time strip via cyrius DCE only** — rejected; DCE
  works at codegen time, but the preprocessor expansion gate
  fires earlier. Sigil's `#ifdef` happens before any DCE pass
  can run.
- **Move ML-DSA-65 to `kem.cyr` for ML-KEM-768 as well** —
  deferred. ML-KEM (KEM, not signing) is a separate primitive
  and a separate scope decision; if a consumer surfaces a
  need, the new module gets the same flag treatment until the
  cyrius cap raises.

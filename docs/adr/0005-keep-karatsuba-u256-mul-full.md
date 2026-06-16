# 0005 — Keep Karatsuba `u256_mul_full`, retain schoolbook as the KAT oracle

**Status**: Accepted
**Date**: 2026-06-16

## Context

The EC-squeeze cycle (3.7.8–3.7.17) drove `ecdsa_p256_verify` from
24.7 ms toward a ~10.9 ms floor. One of the last levers (3.7.17)
replaced the 256×256→512 schoolbook multiply at the heart of the field
arithmetic (`src/bigint_ext.cyr`) with a one-level Karatsuba routine:
`z1 = (aL+aH)(bL+bH) − z0 − z2`, trading 16 64×64 partial products for
12. The textbook expectation is a 15–25% multiply speedup.

Measured, it delivered **~3–4%** on the verify benchmark. At 256 bits
the operand halves are 128-bit, and the host's 64-bit hardware multiply
already pipelines the schoolbook partials efficiently — the recursion
and the extra add/sub bookkeeping eat most of the theoretical win.
Karatsuba's advantage only opens up at much wider operands. The change
also required care to stay thread-safe under banking: the routine uses
only scalar locals plus a stateless `_u256k_mul128` helper, so it never
touches a static `var` array (and thus needs no bank lane of its own).

This raised the question: is a ~3–4% win worth carrying a more complex
multiply with a subtler thread-safety story?

## Decision

**Keep Karatsuba `u256_mul_full` as the production multiply; retain the
schoolbook implementation, renamed `_u256_mul_full_schoolbook`, as a
permanent differential KAT oracle** (200 random + 14 edge cases in
`tests/tcyr/ecdsa_p256.tcyr` cross-check the two byte-for-byte).

Robert's call: small efficiencies are real wins here; a measured,
test-guarded 3–4% on a hot verify path is kept, not reverted.

## Consequences

- **Positive** — a real, benchmarked ~3–4% on `ecdsa_p256_verify`, which
  compounds with the other 3.7.x levers toward the ~10.9 ms floor.
- **Positive** — the retained schoolbook gives a cheap, independent
  oracle: any future multiply change is differential-tested against a
  known-correct reference rather than only against external KATs.
- **Negative** — more code than schoolbook, and the all-scalar-locals
  thread-safety property is an invariant a future editor must preserve
  (a stray static `var` scratch would reintroduce a race). Documented in
  the module header + sources.md.
- **Neutral** — if a wider-operand path ever lands (RSA modexp limbs,
  P-384 field), the Karatsuba helper is already in place to extend.

## Alternatives considered

- **Revert to schoolbook** — rejected; discards a measured win for
  marginal simplicity. The differential oracle keeps the complexity
  honest.
- **Go to two-level / recursive Karatsuba** — rejected; at 256 bits the
  first level already under-delivers, so deeper recursion would lose,
  not gain. Reconsider only if operand widths grow.
- **Hand-written asm multiply (MULX/ADCX/ADOX)** — out of scope here;
  tracked as part of the parked "exotic lever" question for the ≤ 10 ms
  target (ADR 0006). Karatsuba is the portable, no-asm win available
  today.

# 0006 — Disposition of the EC scalar-mult ≤ 10 ms P-256 verify target

**Status**: Accepted
**Date**: 2026-06-16

> **Decided 2026-06-16 (Robert): option A — close the ≤ 10 ms target as
> "not reachable with current approaches."** Option B (exotic-lever
> investigation) is **not dropped** — it is parked to the roadmap
> backlog as a named, possible-future item, explicitly *not a current
> priority*, to revisit only if a consumer surfaces a hard latency
> requirement. This ADR preserves the lever analysis so a future reopen
> starts warm.

## Context

The v3.7 perf cycle set an aspirational target of `ecdsa_p256_verify`
under **10 ms**. Every known portable lever shipped across 3.7.8–3.7.17:

- fixed-base comb for `u1·G` + windowed `u2·Q` (3.7.8, ~2×);
- field-inversion addition-chains (fixed 2^k−1 chain + 4-bit window);
- affine comb-G table + `pt_add_mixed` (madd-2007-bl);
- `u2·Q` batch-inversion mixed-add;
- Karatsuba `u256_mul_full` (3.7.17, ADR 0005).

Result: `ecdsa_p256_verify` **12.50 → ~10.9 ms** (~13% cumulative over
the squeeze, ~2.3× over the pre-3.7.8 baseline). **≤ 10 ms is not
reached.** Analysis: at 256 bits the verify is doubling- and
inversion-bound, not multiply-bound, so Karatsuba caps at ~3–4% and the
remaining levers are exhausted. Crossing 10 ms needs an **exotic** lever,
none of which is currently scoped:

- a hand-written asm multiply (MULX/ADCX/ADOX) — needs the cyrius
  `asm`-block global-symbol pseudo (filed upstream, same gate as
  CLMUL-GHASH);
- an alternative point representation / batched-affine GLV endomorphism;
- a redesigned doubling formula.

Each is a multi-bite effort with its own audit surface, and the verify
is already fast enough for every current AGNOS consumer's one-shot use.

## Decision

**Option A — close the ≤ 10 ms P-256 verify target as "not reachable
with current approaches."** The ~2.3× delivered over the pre-3.7.8
baseline (24.7 → ~10.9 ms) is the shipped result; the target is
met-in-spirit, EC-perf work stops, and the ~10.9 ms floor stands. The
verify is fast enough for every current AGNOS consumer's one-shot use.

**Option B (exotic-lever investigation) is parked, not dropped.** It
moves to `docs/development/roadmap.md` as a named "Backlog — gated /
parked" item: scope an exotic lever (most likely the asm multiply, once
the upstream cyrius `asm`-block global-symbol pseudo lands) as a
dedicated bite with its own audit **only if a consumer surfaces a hard
latency requirement**. **Not a current priority.** A future reopen would
flip a new ADR to `Accepted` (or supersede this one) scoping the chosen
lever; the analysis above is preserved so it starts warm.

## Consequences

- **(A) Positive** — frees the cycle for the 3.8.x housekeeping/feature
  work; honest about the floor; no speculative complexity added.
- **(A) Negative** — the headline ≤ 10 ms number is never literally hit;
  a future consumer with a hard budget reopens from a cold start (though
  this ADR preserves the lever analysis).
- **(B) Positive** — a real shot at sub-10 ms and at unlocking
  asm-backed wins elsewhere (CLMUL-GHASH shares the same upstream gate).
- **(B) Negative** — gated on an upstream cyrius feature; asm introduces
  a portability + constant-time-audit burden on the trust boundary's
  hottest path. Larger review surface for a single-digit-ms gain.
- **Neutral** — either way, the ~10.9 ms floor and the five shipped
  levers stand; this decision only governs whether to chase the last
  ~0.9 ms.

## Alternatives considered

- **Leave the target silently open** — rejected; an undecided perf goal
  with no home rots into a "did we ever finish that?" question. Whether
  parked or pursued, it should be an explicit, signed-off disposition —
  which is what this ADR forces.

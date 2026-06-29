# Architecture Decision Records

Decisions about sigil — what we chose, the context, and the
consequences we accept. Use these when a future reader would
reasonably ask *"why did we do it this way?"*

## Conventions

- **Filename**: `NNNN-kebab-case-title.md`, zero-padded to four
  digits. **Never renumber.**
- **One decision per ADR.** If a decision supersedes a prior
  one, add a new ADR and set the old one's status to
  `Superseded by NNNN`.
- **Status lifecycle**: `Proposed` → `Accepted` → (optionally)
  `Superseded` or `Deprecated`.
- Use [`template.md`](template.md) as the starting point.

## ADR vs. architecture note vs. guide

| Kind | Lives in | Answers |
|---|---|---|
| ADR | `docs/adr/` | *Why did we choose X over Y?* |
| Architecture note | `docs/architecture/` | *What non-obvious constraint is true about the code?* |
| Guide | `docs/guides/` | *How do I do X?* |

## When to write an ADR

- Competing approaches with real trade-offs.
- Adopting or rejecting a dependency.
- Changing a public API.
- Accepting a performance or portability trade-off.
- Deliberately leaving an attractive path on the table (e.g.
  deferring a refactor to a future cycle for a documented
  reason).

If the decision could credibly have gone the other way, write
the ADR. Commit messages don't survive the long arc; ADRs do.

## Index

- [0001 — Retain `_sigil_batch_mutex` until caller-scratch lands](0001-retain-batch-mutex-until-caller-scratch.md) — why 3.3 shipped as a cleanup-only cycle and the parallel-verify mutex drop is queued for 3.5.
- [0002 — ML-DSA-65 ships behind `-D SIGIL_PQC`](0002-mldsa-cmdline-gate.md) — why PQC is opt-in instead of default-on, and what triggers the flip.
- [0003 — Per-call bump-alloc drift in `*_verify_full` orchestrators is acceptable until 3.6](0003-bump-alloc-drift-acceptable-until-3-6.md) — why the seven open LOW findings are batched into one closure rather than fixed incrementally. *(Closed: floor cleared 8→0 at 3.7.3.)*
- [0004 — Per-lane zeroization for banked crypto arrays](0004-per-lane-zeroization-for-banked-crypto-arrays.md) — why banked scratch is plain `var` + per-lane `memset`, never `secret var` (the 3.8.0 cross-lane clobber).
- [0005 — Keep Karatsuba `u256_mul_full`, retain schoolbook as the KAT oracle](0005-keep-karatsuba-u256-mul-full.md) — why a measured ~3–4% on the verify hot path is kept despite under-delivering vs. theory.
- [0006 — Disposition of the EC scalar-mult ≤ 10 ms P-256 verify target](0006-park-ec-scalarmul-10ms-target.md) — **Accepted**: closed as not-reachable-with-current-approaches (~10.9 ms floor after all portable levers); exotic levers parked to the roadmap backlog, not a current priority.
- [0007 — Auto-assigned crypto banks for concurrent TLS](0007-auto-banking-for-concurrent-tls.md) — **Accepted**: `cbank()` auto-assigns a private lane per thread on first use (atomic counter → lanes 1..63, bank 0 = serial), removing the `crypto_bank_set` cooperation that left concurrent TLS workers colliding on bank 0; `SIGIL_CRYPTO_BANKS` 8→64. The load-bearing decision behind the 3.9.6/3.9.7 thread-safety cycle.

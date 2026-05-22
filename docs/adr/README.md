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
- [0003 — Per-call bump-alloc drift in `*_verify_full` orchestrators is acceptable until 3.6](0003-bump-alloc-drift-acceptable-until-3-6.md) — why the seven open LOW findings are batched into one closure rather than fixed incrementally.

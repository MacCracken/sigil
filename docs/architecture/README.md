# Architecture Notes

Non-obvious invariants and constraints about the code — things
a future reader can't derive from reading the source alone, but
that load-bearing decisions depend on.

This is the "constraints" half of the docs. The "decisions"
half lives in [`../adr/`](../adr/) — ADRs answer
*"why did we choose X over Y?"* whereas architecture notes
answer *"what's silently true about how the code is shaped?"*.

## Conventions

- **Filename**: `NNN-kebab-case-title.md`, zero-padded to three
  digits. **Never renumber.**
- One invariant per note.
- Lead with the **What it affects** line so a reader hitting
  the affected module from grep can decide in 5 seconds
  whether the note applies.

## Module map

The end-to-end module map + data flow narrative lives in
[`overview.md`](overview.md), not in a numbered note. Overview
is the discoverable landing page; numbered notes are
deep-dives on individual invariants.

## Index

- [`001-var-array-static-semantics.md`](001-var-array-static-semantics.md) —
  **written.** quirk #1 (`var X[N]` is a static global) + the banked
  crypto-scratch pattern (`cbank()`, per-lane secret `memset`) + the 3.9.7
  corollary that `secret var` *arrays* race too. The most grep-hit invariant
  in `src/`. Cross-links ADR 0004 / 0007.

*The remaining cross-cutting constraints from CLAUDE.md "Known Cyrius Compiler
Quirks" become numbered notes the first time a reader hits one from grep
instead of from CLAUDE.md. Candidates for next extraction:*

- `002-preprocessor-output-cap.md` — quirk #8, the cap that
  motivated ADR 0002.
- `003-stdlib-thread-safety-floor.md` — quirk #7, the
  alloc/hashmap/vec thread-safety floor that motivates 3.5's
  caller-scratch architecture.
- `004-fixup-cap-and-init-block-sizes.md` — quirk #5, the
  16384-entry cap that explains the AES-GCM S-box decode-from-
  hex pattern.

When a reader hits one of these from a grep result without
CLAUDE.md context, promote it to a numbered note in this dir.

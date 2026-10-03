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

- [`002-native-asm-multiply.md`](002-native-asm-multiply.md) —
  **written.** The `asm{}` 64×64→128 multiply (`src/mul64.cyr`, 3.12.2)
  under every big-integer engine: why it has NO runtime dispatch (unlike
  SHA-NI / AES-NI), its register/clobber contract, why `_nmul64_hi`
  returns a scalar rather than writing through a pointer, and the
  toolchain dependency the test suite gates. Cross-links ADR 0008 and
  note 001.

- [`003-global-arrays-are-eight-bytes-per-element.md`](003-global-arrays-are-eight-bytes-per-element.md) —
  **written.** Every banked global costs 8x its declared size. (This index
  did not list it until 3.13.8.)

- [`004-secret-ec-scalars-run-on-ec-ct.md`](004-secret-ec-scalars-run-on-ec-ct.md) —
  **written (3.13.8).** The P-256 / P-384 verify modules are variable-time by
  construction; every secret EC scalar (ECDH, ECDSA signing,
  `pt_scalarmul_secret`) runs on the constant-time engine `src/ec_ct.cyr`, and
  how that is checked in the compiled code. Cross-links ADR 0009.

*The remaining cross-cutting constraints from CLAUDE.md "Known Cyrius Compiler
Quirks" become numbered notes the first time a reader hits one from grep
instead of from CLAUDE.md. Candidates for next extraction — they take the next
free number when written (the numbers they carried here were claimed by 003 and
004 instead):*

- `preprocessor-output-cap` — quirk #8, the cap that
  motivated ADR 0002.
- `stdlib-thread-safety-floor` — quirk #7, the
  alloc/hashmap/vec thread-safety floor that motivates 3.5's
  caller-scratch architecture.
- `fixup-cap-and-init-block-sizes` — quirk #5, the
  16384-entry cap that explains the AES-GCM S-box decode-from-
  hex pattern.

When a reader hits one of these from a grep result without
CLAUDE.md context, promote it to a numbered note in this dir.

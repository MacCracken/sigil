# cyrius: raise the 16384 fixup-table cap for large downstream
# libraries

**Filed:** 2026-04-22
**Reporter:** sigil (AGNOS trust-verification library)
**Cyrius version at time of report:** 5.5.35
**Severity:** blocker for a specific downstream 3.0 feature
**Status:** open — awaiting cyrius team review for inclusion in
remaining 5.5.x work

## Summary

When sigil pulls in `lib/thread.cyr` + the fan-out code for the
parallel `sv_verify_batch` pillar (sigil 3.0), the compilation
fails with:

```
error: fixup table full (16384)
```

The default sigil build (serial `sv_verify_batch`) builds cleanly
under 16384 fixup entries on 5.5.35, so HEAD is sitting
*immediately* below the cap. Adding ~18 additional `load64` /
`store64` operations plus the threading primitive call sites
pushes it over. This matches the cap documented in sigil's
`CLAUDE.md` § "Known Cyrius Compiler Quirks" quirk #5 ("Fixup
table cap: 16384 — up from 8192 in cc3").

## Repro

Branch: `3.0` on <https://github.com/MacCracken/sigil> at commit
containing `src/verify.cyr`'s parallel `sv_verify_batch` body,
with `src/lib.cyr` unconditionally including `lib/thread.cyr`
(before the gate added in the same landing).

```bash
cd sigil
cyrius build programs/smoke.cyr build/sigil-smoke -D SIGIL_SMOKE
# -> error: fixup table full (16384) FAIL
```

The current sigil `3.0` branch gates the parallel path behind
`-D SIGIL_BATCH_PARALLEL` as a workaround, so the default build
is green. Toggling the gate on restores the crash:

```bash
cyrius build programs/smoke.cyr build/sigil-smoke-parallel \
    -D SIGIL_SMOKE -D SIGIL_BATCH_PARALLEL
# Builds OK at time of writing — but only because we're ~30
# fixup entries under the cap. Any further feature work on
# sigil will re-breach it.
```

## Measurements

Empirical cap-probing on sigil 3.0 (5.5.35):

| code state                                    | builds? |
|-----------------------------------------------|---------|
| HEAD (serial sv_verify_batch)                 | yes     |
| HEAD + 1 trivial `var x = 0;` + `fn noop()`   | yes     |
| HEAD + sigil parallel batch (ungated)         | **no**  |
| HEAD + `include "lib/thread.cyr"` alone       | **no**  |

So the fixup budget available for new work on sigil 3.0 is on
the order of "tens of fixup-table entries". Any meaningful new
compilation unit-scoped primitive (threading, crypto, I/O) tips
the scale.

## Why this matters

Sigil is the system-wide trust boundary for AGNOS. Its surface
is intentionally large (Ed25519 / SHA-256/512 / HMAC / HKDF /
AES-256-GCM / AES-NI / ML-DSA-65 / integrity / revocation /
audit / keyring / trust chain). As consumers demand more
capabilities (parallel batch verify, HSM integration, PKCS#11,
future PQC KEM), each addition runs against the 16384 ceiling.

The parallel batch-verify pillar in sigil 3.0 is specifically
blocked on this. The sigil team's workaround is a build-time
feature gate (`-D SIGIL_BATCH_PARALLEL`, matching the existing
`-D SIGIL_PQC` gate which exists because of the separate 1 MB
preprocessor cap documented as quirk #8). Both gates add user-
visible complexity — consumers must know to opt in and configure
their build systems accordingly.

## Ask

Raise the fixup-table cap (current 16384) for cyrius 5.5.x. Two
paths, either is acceptable from sigil's perspective:

1. **Static raise** — bump the compile-time constant to, e.g.,
   32768 or 65536. Previous raise from 8192 → 16384 bought
   several years; a doubling should buy the AGNOS ecosystem
   through 2027 at current growth.
2. **Dynamic sizing** — grow the fixup table on demand rather
   than fixing a cap. Cleaner long-term story; avoids future
   "raise-the-cap" issues as more Cyrius libraries mature.

Preference: (2) if the cost is reasonable, otherwise (1).

## Downstream plan once raised

Sigil removes `-D SIGIL_BATCH_PARALLEL` as a required flag and
makes the parallel path default at `count >= threshold`. The
gate remains as a one-cycle compatibility layer so consumers on
older cyrius don't break. Documented in
`docs/development/3.0-scope.md` § Post-3.0 follow-ups.

## Related cyrius context

- Fixup cap last raised 8192 → 16384 in the cc3 → cc5 transition.
- The separate 1 MB preprocessor cap (`preprocess_out` in
  `src/frontend/lex.cyr:1436`) is already tracked in sigil's
  `CLAUDE.md` as quirk #8 — that one binds against `SIGIL_PQC`
  unconditional inclusion. A parallel ticket for the
  preprocessor cap could be worth filing if it surfaces again
  (sigil is a cap user, not currently a blocker).

## Cross-references

- `CLAUDE.md` → § "Known Cyrius Compiler Quirks" → quirk #5
  (this cap)
- `docs/development/3.0-scope.md` → "Parallel `sv_verify_batch`
  fan-out" entry
- `src/lib.cyr` → `#ifdef SIGIL_BATCH_PARALLEL` gate around
  `include "lib/thread.cyr"`
- `src/verify.cyr` → `#ifdef SIGIL_BATCH_PARALLEL` gate around
  `_batch_worker` + parallel sv_verify_batch body

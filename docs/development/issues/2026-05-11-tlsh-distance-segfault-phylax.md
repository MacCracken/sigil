# sigil: potential 3.x interaction — `tlsh_distance(h, h)` SIGSEGVs in
# phylax under cyrius 5.10.44 + sigil 3.1.1

**Filed:** 2026-05-11
**Reporter:** phylax (AGNOS threat-detection engine)
**Cyrius version at time of report:** 5.10.44 (release tarball)
**Sigil versions affected:** 3.1.1 (only version exercised post-bump; 2.9.5 was the last-known-good phylax pin pre-1.1.1)
**Sigil last-known-good (phylax-side):** 2.9.5
**Severity:** **P2** — investigation. Sigil-side fault is *one of three candidate root causes* and the least likely per the phylax-side analysis; the more likely causes are cc5 register-spill or 5.10.x stdlib-layout drift in TLSH-side code. Filed in sigil's queue so the 3.x cycle's downstream-impact tracking is complete, not because sigil is confirmed at fault.
**Status:** open — investigation. **Re-test against sigil 3.1.2
+ cyrius 6.0.1 prompted (2026-05-21).** The 3.1.2 ship-cut moves
sigil to cyrius 6.0.1, which independently resolved the sibling
P1 [`archive/2026-05-10-ed25519-verify-aarch64-accepts-wrong-pk.md`](archive/2026-05-10-ed25519-verify-aarch64-accepts-wrong-pk.md)
and silenced the sibling P1 [`2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md`](2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md)
on native x86_64. Phylax-side bisect against the new pin
(cyrius 6.0.1 + sigil 3.1.2) should now run before sigil-side
work is queued — if the segfault no longer reproduces, this
file archives with a "no sigil-side action — toolchain pass
folded it out" footer; if it persists, sigil-side investigation
goes into the 3.2.x backlog.

**3.2.0 sigil-side recheck (2026-05-21).** The 3.2.0 batch is
likewise SHA-256-surface-stable: the only sha256-related delta
is the additive `sha256_init_into(ctx)` helper (alloc-free
variant of `sha256_init`) and the `_sha_ni_self_test` gate.
Neither alters the SHA-256 / SHA-NI byte semantics — both are
verified against FIPS 180-4 §B.1 in `tests/tcyr/sha_ni.tcyr`
(13/13 green, cross-path NI vs software equality preserved).
So a phylax-side bisect against sigil 3.1.2 OR sigil 3.2.0
should see identical hash output. If the segfault persists
against either pin, the sigil-side candidate is conclusively
ruled out — the remaining candidates (cc5 register-spill,
5.10.x stdlib drift) own the bug.
**Upstream filing (phylax-side, canonical):** [phylax/docs/development/issues/2026-05-11-tlsh-distance-segfault.md](https://github.com/MacCracken/phylax/blob/main/docs/development/issues/2026-05-11-tlsh-distance-segfault.md)

## Why this is in sigil's queue (not just phylax's)

phylax's `src/hashing.cyr` implements TLSH (Trend Micro Locality Sensitive Hash); the TLSH code path internally calls into sigil for partial hashing. The crash surfaced on the 1.1.1 ship-cut when phylax bumped sigil 2.9.5 → 3.1.1 as part of a broader toolchain + dep sweep (cyrius 5.7.48 → 5.10.44, sigil + sakshi + majra + bote all moved). The sigil-bundle layout shifted by thousands of lines between 2.9.5 and 3.1.1 (PQ surface, AES-GCM, `ct_eq_bytes_lens` / `_keccak_*` / `random_bytes` additions). Listed here so that if the phylax-side bisect confirms a sigil interaction, the fix lands in this repo's history.

## Symptom

Calling `tlsh_distance(h, h)` with `h` a non-zero TLSH hash produced by `tlsh_hash(data, 256)` (phylax surface) segfaults the process (exit 139, SIGSEGV). The function never returns; no assertion message prints because the crash precedes any stdout write inside the assertion macro.

Bisected via marker `syscall(SYS_WRITE, ...)` calls in `tests/phylax.tcyr:438-442` (pre-split monolithic test file):

```
MARK8     ← last printed marker, immediately before `if (h != 0) { ... }`
[crash]   ← segfault inside `var dist = tlsh_distance(h, h);`
```

MARK9 (placed between the if-guard and the call's RHS) never fires, narrowing the crash to the `tlsh_distance` function body — not the if-guard or the RHS evaluation of `h`.

## Repro

Pin in any phylax checkout's `cyrius.cyml`:

```toml
cyrius = "5.10.44"

[deps.sigil]
git = "https://github.com/MacCracken/sigil.git"
tag = "3.1.1"
modules = ["dist/sigil.cyr"]
```

Then restore the commented block in `tests/test_tlsh.tcyr:25-29`:

```cyrius
if (h != 0) {
    var dist = tlsh_distance(h, h);
    assert_eq(dist, 0, "identical tlsh distance = 0");
}
```

Run:

```bash
$ cyrius test tests/test_tlsh.tcyr
=== tlsh ===
[exit 139]
```

Or as a standalone binary (which surfaces the real exit code that `cyrius test` masks through its pipeline):

```bash
$ cyrius build tests/test_tlsh.tcyr build/test_tlsh
$ ./build/test_tlsh
=== tlsh ===
[Segmentation fault (core dumped)]
$ echo $?
139
```

## Suspected root cause — sigil-side candidate

Of the three candidate root causes documented in the phylax-side filing, the sigil-side one is:

> **sigil 3.x SHA-256 interaction** — TLSH internally calls into the sigil bundle for partial hashing. The 2.9.5 → 3.1.1 jump pulls in the new PQ / AES-GCM transitive surface plus the `ct_eq_bytes_lens` / `_keccak_*` / `random_bytes` symbols. None of these are obviously on TLSH's hot path, but the bundle layout shifted by ~thousands of lines and the call-site offsets changed correspondingly. Listed for completeness; less likely than (1) or (2) [cc5 register-spill / 5.10.x stdlib layout drift].

For sigil-side investigation, the questions are:

1. Does TLSH's call into sigil land on `sha256_hex`, `sha256`, `sha256_init+update+finalize`, or a lower-level primitive? phylax's `src/hashing.cyr` is the file to read.
2. Is the call path crossing the SHA-NI dispatcher (`sha256_transform_ni`)? If yes, this is the same class of bug as the inline-asm `[rbp-N]` drift documented in [`2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md`](2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md) — the SHA-NI path was called out in that bisect (sigil 2.9.3 → SIGILL under cyrius 5.10.x). If the same `[rbp-N]` issue is biting the SHA-NI path inside `tlsh_distance`'s call tree, the fix is the same migration (load params into module-level globals before the asm block).
3. Does forcing the software-fallback SHA-256 path (`sha256_global_init` returning 0 on NI dispatch capability) make the crash go away? If yes, this confirms the NI-asm-drift class.

## Closeout criteria

- Phylax-side bisect across the cyrius pin (5.7.48 → 5.10.44) and the sigil pin (2.9.5 → 3.1.1) confirms which side owns the regression.
- If sigil-side: the SHA-NI or whatever inline-asm path is identified, the fix (likely the same as P1 [`2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md`](2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md)) is folded into the v3.1 ship.
- If sigil-side is cleared: this file moves to `archive/` with a "no sigil-side action — root cause was X (phylax / cc5 / stdlib)" footer pointing at the phylax-side resolution. The phylax-side filing remains canonical.

## Related

- [`2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md`](2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md) — P1, same toolchain era, same class of fault (NI inline-asm drift under cyrius 5.10.x). If the phylax bisect lands on the SHA-NI path, fold this into the same fix.
- Phylax 1.1.1 CHANGELOG `### Known issues` block — references this filing.
- Phylax's [`docs/bugs/cc5-register-spill.md`](https://github.com/MacCracken/phylax/blob/main/docs/bugs/cc5-register-spill.md) — earlier cc5 bug filing from the phylax side with similar symptom shape (silent SIGSEGV, marker-print-sensitive). One of the alternative candidate root causes.

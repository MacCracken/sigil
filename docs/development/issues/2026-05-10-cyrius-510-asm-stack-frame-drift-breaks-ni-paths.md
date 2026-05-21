# sigil: inline-asm `[rbp-N]` parameter loads SIGILL under
# cyrius 5.10.x stack frames

**Filed:** 2026-05-10
**Reporter:** majra (AGNOS distributed-queue / multiplex library)
**Cyrius version at time of report:** 5.10.34 (release tarball + source archive)
**Sigil versions affected:** 2.9.1 through 3.1.0 (inclusive)
**Sigil last-known-good:** 2.9.0
**Severity:** **P1** — blocks every downstream that pulls sigil's
crypto surface under any cyrius ≥ 5.5 toolchain. Pinning a
post-2.9.0 sigil with a modern cyrius is currently a non-starter
for downstream consumers; majra 2.4.2 had to hold sigil at 2.9.0
to ship at all.
**Status:** open — does **not** repro under cyrius 6.0.1 native
x86_64 (sigil 3.1.2 ship-cut: 24/24 `.tcyr` green including
`aes_ni.tcyr` 4/4, `aes_gcm.tcyr` 15/15, `ed25519.tcyr` 20/20),
but the **structural defect remains**: `src/aes_ni.cyr:60,88-90`
and `src/sha_ni.cyr:64,244-246` still hardcode `mov rdi,
[rbp-8]` / `mov rsi, [rbp-16]` / `mov rdx, [rbp-24]` as byte
literals. The 5.10.x prologue drift that caused SIGILL is
implicitly silenced under cyrius 6.0.x's frame layout, but a
future cyrius prologue change can re-break it identically.
Defense-in-depth structural fix is queued for **3.2.0** —
migrate the three-parameter NI dispatch sites to module-level
globals (pattern matches `_aes_ni_cache` / `_sha_ni_cache`),
producing a cyrius-stable ABI regardless of frame-layout drift.
See `docs/development/3.2-scope.md`.

## Summary

The AES-NI / SHA-NI / ed25519-NI dispatch fns in sigil 2.9.1+
hardcode parameter offsets in their inline-asm blocks (e.g.
`mov rdi, [rbp-8]`, `mov rsi, [rbp-16]`, `mov rdx, [rbp-24]`).
Those offsets matched the stack-frame layout cc5 emitted up
through cyrius ~5.4.x. cyrius 5.10.x's expanded prologue
(more locals saved by the caller-callee dance, possibly an
extra `push` per fn for the version-pinned-lib hint or for the
DCE bookkeeping) shifts the actual parameter slots, so the
hardcoded loads read garbage and the subsequent `pxor` /
`aesenc` / `pmull` instruction faults with SIGILL (typically
on a misaligned memory operand whose alignment was an invariant
when the load happened from the right slot).

## Repro

Pin sigil tag in any downstream's `cyrius.cyml`:

```toml
[deps.sigil]
git = "https://github.com/MacCracken/sigil.git"
tag = "<version>"
modules = ["dist/sigil.cyr"]
```

…with `cyrius = "5.10.34"` in the same file. Then build any
entry that exercises `aes_gcm_encrypt` / `ed25519_sign` /
`ed25519_verify`.

### Bisect (majra `tests/test_backends.tcyr`, cyrius 5.10.34, x86_64)

| sigil tag | result            | last test that printed |
|-----------|-------------------|------------------------|
| 2.9.0     | **42/42 pass**    | (clean to end)         |
| 2.9.1     | SIGILL (exit 132) | `aes_gcm_roundtrip: ok` — crashed in `test_signed_envelope` (`ed25519_*`) |
| 2.9.2     | SIGILL            | `aes_gcm_roundtrip: ok` |
| 2.9.3     | SIGILL            | `aes_gcm_roundtrip: ok` |
| 2.9.4     | SIGILL            | `aes_gcm_roundtrip: ok` |
| 2.9.5     | SIGILL            | `aes_gcm_roundtrip: ok` |
| 3.0.0     | SIGILL            | `aes_gcm_roundtrip: ok` |
| 3.0.1     | SIGILL            | `aes_gcm_roundtrip: ok` |
| 3.1.0     | SIGILL **earlier**| `encrypted_ipc: ok` — crashed in `test_aes_gcm_roundtrip` |

The 3.1.0 regression vs 3.0.x is the second data point: aes-gcm
worked under 3.0.x even with the ed25519 break, but stopped
working in 3.1.0. The 3.1.0 CHANGELOG retags 3.0.2's `ct_eq`
migration with no asm change called out, but the bundle's
aes-gcm dispatch must have been touched (or the SHA-NI hot path
added at 2.9.3 / re-encoded in 3.1.0 shifted the asm-block
neighbours' frames). Worth a `git log -p` on the 3.0.1 → 3.1.0
diff over `src/aes_gcm.cyr` / `src/sha_ni.cyr` to confirm.

### Diagnostic that confirms frame-shape

Adding diagnostic `println`s anywhere inside the calling fn
(before the asm dispatch) shifts the SIGILL window — sometimes
the test passes with the prints in place and fails with them
removed. That's the canonical signature of fragile asm-offset
arithmetic against a changing prologue, not a stale-pointer or
memory-corruption bug.

## Suggested fix angles

1. **Stop encoding parameter loads as `[rbp-N]` byte literals.**
   Use cyrius's asm-pseudo for parameter access if/when it
   exists, or emit a small non-asm thunk that captures the
   parameters into module-level globals (e.g. `_aes_ni_arg0`,
   `_aes_ni_arg1`, `_aes_ni_arg2`) and have the asm load from
   `[rip+...]` instead. Slower by a handful of cycles per
   block-encrypt, but cyrius-stable.

2. **Use call-by-global instead of call-by-frame for the
   NI dispatch surface.** All four ni fns (`aes256_encrypt_block_ni`,
   `sha256_transform_ni`, `ed25519_sign_ni`, `ed25519_verify_ni`
   if present) pass a fixed, small parameter set. A module-
   level globals-as-mailbox shape sidesteps the stack-frame
   coupling entirely. Pattern is the one sigil already uses for
   `_sha_ni_cache` / `_aes_ni_cache` and the cpuid probes.

3. **Coordinate with cyrius for a stable `asm` parameter ABI.**
   File a paired issue upstream asking for either (a) a documented,
   versioned `[rbp-N]` contract per parameter-count fn, or (b)
   inline-asm pseudo-ops (`_param0`, `_param1`, …) that resolve
   to the right offset at codegen time. The right structural
   answer, but the longest path to ship.

(1) is the lowest-risk delta; sigil's perf budget can absorb
the indirection. (2) is the cleaner shape if the NI surface is
expected to grow. (3) is the only fix that scales beyond sigil.

## Downstream impact

- **majra** — pinned at sigil 2.9.0 for 2.4.2 release (no AES-NI,
  no SHA-NI, no ed25519-NI dispatch). Documented in
  `majra/docs/development/roadmap.md` "Waiting on upstream".
- Every other consumer pulling sigil under cyrius ≥ 5.5 will hit
  the same wall the moment they try to bump sigil past 2.9.0.
  The 363× / 21–44× perf wins from the 2.9.x crypto-pillar arc
  are inaccessible until this lands.

## Suggested placement in the v3.1 work arc

The v3.1 arc is currently scoped around the alloc-free verify
hot path (`sv_verify_artifact` rewrite). That work targets a
3× speedup at 4 workers — but the parallel-batch win is moot
for downstream consumers if the *serial* NI hot paths SIGILL
under the toolchain version they're actually running.

Recommend slotting this as the **first** v3.1 work item, ahead
of the alloc-free rewrite. It unblocks every existing 2.9.x
perf win for downstream, doesn't conflict with the alloc-free
rewrite's scope (different files), and lets the 3.1 batch-verify
benchmarks actually run under cyrius 5.10.x.

> **ARCHIVED — RESOLVED (2026-06-15).** Sigil-owned. Real cause was the missing-opt-in-stdlib-include footgun (not asm drift); fixed in **3.7.8** via README opt-in-include docs + belt-and-suspenders param_load migration. Re-proven green through every pin bump to 6.2.12.
> Issue cross-walk: 3.7.15 triage + `docs/audit/2026-06-15-3.7.15-windows-entropy-audit.md`.

# sigil: NI-path inline-asm `[rbp-N]` parameter loads SIGILL again
under cyrius 6.1.20 — the predicted re-break

> **RESOLVED in 3.7.8 (2026-06-09) — no functional code defect; the fix was
> documentation.** **The reported symptom was real but the suspected cause
> was wrong, so there was nothing in sigil's logic to repair.** The SIGILL
> was NOT the asm `[rbp-N]` param-load drift — it was a **usage gap:
> bundle-consumer builds were missing the opt-in stdlib deps sigil's crypto
> surface requires.** The resolution was **cleaning up the docs to make
> consumer usage clear** (the README now spells out the required includes);
> the one source change (the NI `param_load` migration) is **behaviorally a
> no-op** — pure belt-and-suspenders hardening, not a bug fix.
>
> The SIGILL was **missing opt-in stdlib deps in bundle-consumer builds.** Since 3.6 the banked crypto hot path runs `cbank()` →
> `thread_local_*` on **every** `sha256`/`ed25519`/`aes` call, and every
> constant-time compare runs `ct_eq_bytes_lens`; ML-DSA (default-on @3.7.6)
> runs `shake256`. Cyrius stdlib is **opt-in, not auto-associated**, and
> the `dist/sigil.cyr` bundle does not carry these includes. A consumer who
> includes only `dist/sigil.cyr` leaves `thread_local_*` / `ct_*` /
> `shake256` **undefined** — cyrius 6.1.x only *warns* and compiles each
> unresolved call to a `ud2`, so the program **builds** but **SIGILLs
> (exit 132)** the instant a crypto path touches one. Software `sha1` (pure
> stdlib, auto-included) runs fine — exactly the reporter's isolation.
>
> **gdb on the bundle repro:** the fault is a cyrius-emitted `ud2` inside
> `crypto_tls_main_init` (the `thread_local_init()` call site), reached via
> `sha256` → `sha256_transform_ni` → `cbank()`. The self-test path in
> `sha_ni_available()` does *not* call `cbank()`, which is why it completes
> while the production call faults — proof it was never the asm param loads
> (which executed fine).
>
> **Fix (3.7.8):**
> 1. **Root cause — documented, not hidden.** README "Usage — stdlib
>    include order" now lists all four required opt-in includes
>    (`lib/ct.cyr`, `lib/keccak.cyr`, `lib/thread.cyr`,
>    `lib/thread_local.cyr`) before `lib/sigil.cyr`, and states plainly
>    that omission is a **runtime SIGILL, not a build error**, under cyrius
>    6.1.x. The bundle stays clean (libs are the consumer's opt-in, never
>    auto-injected).
> 2. **Belt-and-suspenders — the predicted structural NI fix landed too.**
>    The hardcoded `mov r__, [rbp-N]` param loads in `src/sha_ni.cyr` /
>    `src/aes_ni.cyr` were migrated to the prologue-drift-proof
>    `param_load(reg, idx)` pseudo (cyrius 6.0.67+) — the fix the 2026-05-10
>    issue queued. So even though the param-load drift was not *this*
>    SIGILL, the latent fragility it warned about is now closed.
> 3. Toolchain pin bumped 6.0.87 → **6.1.20**; verified green: full suite
>    1459/1459, smoke clean, and the bundle repro below now exits 0 with
>    correct digests once the four includes are present.

**Filed:** 2026-06-09
**Reporter:** cyrius-yeomans-descent (Yeoman's Descent MUD) — M6 player
persistence, Ed25519 challenge/response auth (ADR 0004).
**Cyrius version at time of report:** 6.1.20 (`cycc`), consumer pins 6.1.17.
**Sigil versions affected:** 3.6.0 (dep-cache build, pins cyrius 6.0.52)
confirmed; by inspection every published build through **3.7.7** (pins
6.0.87) carries the same unfixed inline-asm offset literals.
**Sigil last-known-good under cyrius 6.1.x:** none known.
**Severity:** **P1** — blocks every downstream that pulls sigil's
crypto surface under a cyrius 6.1.x toolchain. Yeoman's Descent cannot
ship Ed25519-backed auth (its chosen ADR 0004 identity model) and had to
escalate the milestone.
**Status:** open.

## This is the re-break foreseen in
[2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths](2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md)

That issue closed its analysis with: *"The 5.10.x prologue drift that
caused SIGILL is implicitly silenced under cyrius 6.0.x's frame layout,
but **a future cyrius prologue change can re-break it identically.**"* —
and noted the structural fix (migrate the three-parameter NI dispatch
sites to module-level globals, like `_sha_ni_cache` / `_aes_ni_cache`)
was queued for **3.2.0** (`docs/development/3.2-scope.md`).

cyrius **6.1.20** is that future prologue change. `src/sha_ni.cyr` /
`src/aes_ni.cyr` still hardcode `mov rdi, [rbp-8]` / `mov rsi, [rbp-16]`
/ `mov rdx, [rbp-24]` as byte literals; 6.1.20's frame layout shifts the
parameter slots, the hardcoded loads read garbage, and the subsequent
SHA-NI / curve instruction faults with **SIGILL**. The defense-in-depth
structural fix was either not landed or not sufficient — it must be done
now.

## Repro

Build any program against sigil 3.6.0's `dist/sigil.cyr` with cycc
6.1.20 and call any NI-accelerated primitive:

```
ed25519_keypair(seed, sk, pk)          # -> SIGILL (exit 132)
ed25519_sign(sk, msg, len, sig)        # -> SIGILL
ed25519_verify(pk, msg, len, sig)      # -> SIGILL
sha256("abc", 3, out)                  # -> SIGILL (sha256_transform_ni)
```

Minimal consumer (built via the manifest with `[deps.sigil]`):

```
fn main() {
    alloc_init();
    println("start");                  # prints
    var dg = alloc(32);
    sha256("abc", 3, dg);              # SIGILL here, exit 132
    print_num(load8(dg) & 0xFF);      # never reached
    return 0;
}
```

Observed: `start` prints, then the process dies with **exit 132**
(128 + SIGILL/4), before the digest is read. Same for the three ed25519
entry points (even the deterministic `ed25519_keypair(seed,...)`, ruling
out the RNG source).

## Isolation — it is specifically the NI / accelerated paths

On the **same** cycc 6.1.20 toolchain and the same CPU
(`/proc/cpuinfo` reports `sha_ni adx bmi2 rdrand rdseed`):

- **Software `sha1`** (cyrius stdlib `lib/sha1.cyr`, no NI variant) runs
  correctly — `sha1("abc")[0] == 0xa9`, exit 0.
- **`sha256`** (stdlib `lib/sigil.cyr`, routes through
  `sha256_transform_ni`) SIGILLs.

So the fault is not the toolchain at large and not the CPU lacking the
feature — it is exactly the hand-emitted NI dispatch's hardcoded `[rbp-N]`
parameter loads, as the 2026-05-10 issue diagnosed.

This was **not** a downstream `lib/` shadow problem: moving the
consumer's vendored `./lib/` aside to use the version-matched 6.1.20
snapshot did **not** change the SIGILL. It is sigil's bundle.

## Why it blocks the consumer

Yeoman's Descent chose Ed25519 challenge/response for player auth (no
secret on the wire over plaintext Telnet — ADR 0002 has no TLS). The
server only ever calls `ed25519_verify`, but that single call SIGILLs, so
the auth path cannot run or be tested under cycc 6.1.x. There is no
cycc-6.1.x-compatible sigil build to pin to (every cached version pins
6.0.x), so the consumer cannot work around it by version selection.

## Fix

Land the **3.2.0-scoped structural fix now**: replace the three
hardcoded `mov r__, [rbp-N]` parameter loads in `src/sha_ni.cyr`,
`src/aes_ni.cyr` (and any ed25519-NI dispatch site) with the
module-level-global handoff pattern already used for `_sha_ni_cache` /
`_aes_ni_cache`, producing a cyrius-stable ABI independent of
frame-layout drift. Then cut a sigil release whose `cyrius.cyml` pins (or
is verified against) **6.1.20**, and re-run `sha256.tcyr` / `ed25519.tcyr`
/ `aes_*.tcyr` under 6.1.20 to confirm green.

A belt-and-suspenders option worth considering: a runtime/codegen-robust
software fallback that does **not** depend on frame layout, so a future
prologue change degrades to slow-but-correct rather than SIGILL.

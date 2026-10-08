# `tests/threads.cyr`'s header says THREADS_CONCURRENT answers 0 on Windows — stale from cyrius 6.6.16

**Filed:** 2026-10-05 (recorded by cyrius 6.6.16, lane net-4 / N7) · **Severity:** LOW (comment only) ·
**Status:** resolved (3.13.11)

**Where:** `tests/threads.cyr` lines 5-8, the header of `test_threads_concurrent` (sigil 3.13.9):

> It answers 0 on x86 macOS and agnos, which do run bodies inline — and ALSO on Windows, where thread_create
> is CreateThread and the threads are real (measured on cass under cyrius 6.6.14).

From cyrius 6.6.16 `THREADS_CONCURRENT` answers **1** on Windows (`lib/thread_win.cyr`), so the "ALSO on
Windows" clause is stale. The code is unaffected: `test_threads_concurrent` short-circuits on 1 and measures
only on 0, so on Windows it now takes the fast path and returns the same 1 its probe measured.

**Suggested text:** "It answers 0 on x86 macOS and agnos, which do run bodies inline (and on Windows before
cyrius 6.6.16, whose CreateThread threads were always real). So a 0 is measured here, not trusted …".
Keep the measurement fallback while sigil supports a cyrius pin below 6.6.16.

(Also from cyrius 6.6.16, for information: every thread peer exports `CHAN_BLOCKING` — 1 on Linux, arm64 macOS
and Windows, 0 on x86 macOS, agnos and cx — and arm64 macOS / Windows channels now block like Linux's.)

## Resolution (3.13.11)

The header now names Linux, Windows (since cyrius 6.6.16) and both macOS arches (x86 since 6.6.19) as
answering 1, agnos as the one target that answers 0 because it runs bodies inline, and the two earlier pins
that answered 0 for real threads — which is why the measurement fallback stays. The cyrius 6.6.19 note in the
roadmap about `_crypto_needs_block`'s "macOS keep it process-global" reasoning was fixed in the same release:
the comment in `src/crypto_scratch.cyr` now describes the per-thread blocks macOS workers have, and the code is
unchanged (no non-Linux thread can lack a block, so nothing there can fault).

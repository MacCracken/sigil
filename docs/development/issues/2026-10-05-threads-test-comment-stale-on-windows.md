# `tests/threads.cyr`'s header says THREADS_CONCURRENT answers 0 on Windows — stale from cyrius 6.6.16

**Filed:** 2026-10-05 (recorded by cyrius 6.6.16, lane net-4 / N7) · **Severity:** LOW (comment only) ·
**Status:** open — for sigil's next release

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

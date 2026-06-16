# 0004 — Per-lane zeroization for banked crypto arrays

**Status**: Accepted
**Date**: 2026-06-16

## Context

Function-scope `var X[N]` arrays are static globals in Cyrius, not
stack locals (CLAUDE.md quirk #1). To make a crypto primitive safe on a
concurrent path, sigil banks the array across `SIGIL_CRYPTO_BANKS` lanes
and indexes by `cbank()` (`src/crypto_scratch.cyr`, since 3.6.0):
`var X[N*SIGIL_CRYPTO_BANKS]; var Xb = &X + cbank()*N;`. Each worker
owns one lane, so concurrent workers never alias the same scratch.

3.8.0 extended this scheme from the verify primitives to ChaCha20
(`chacha20_block`'s `st`/`ws`, `chacha20_xor`'s `ks`) and X25519
(`x25519`'s `W`/`ub`, `x25519_base`'s `base`) ahead of any concurrent
AEAD or TLS-handshake consumer. These arrays hold **secret** state —
x25519's `W` carries the clamped scalar `k`; chacha20's buffers carry
key-derived keystream — so the original (serial) code declared them
`secret var`, getting compiler-guaranteed zeroization on scope exit.

That is exactly the trap. `secret var X[N*BANKS]` zeroizes the **whole**
array on exit. When worker A returns, it wipes all 8 lanes — including
worker B's in-flight lane. The new `tests/tcyr/banking_concurrent.tcyr`
race-detector (4 workers on distinct non-zero banks vs. a serial
bank-0 reference) caught this immediately as intermittent 1–2
byte-mismatches per run — the classic data-race signature a serial KAT
at bank 0 alone cannot surface (offset 0 hides a wrong lane stride).

## Decision

**Banked crypto arrays are plain `var`, with an explicit per-lane
`memset` of the worker's own lane before return — never `secret var`.**

`memset(Xb, 0, N)` wipes only `[cbank()*N, cbank()*N + N)`, preserving
per-call secret zeroization without ever touching a sibling's lane.
This matches the proven `fp_mul` / `fp_inv` field banking, which has
always been plain `var`. The rule is now CLAUDE.md quirk #9 and is
enforced by review + the race-detector.

Scope: every banked array that holds secret or key-derived state. Banked
arrays holding only public values may skip the wipe (but still must not
be `secret var`).

## Consequences

- **Positive** — eliminates a real, shipped-if-uncaught cross-lane
  corruption while keeping the secret-zeroization intent. The per-lane
  wipe is *stronger* than `fp_*` banking (which does no zeroization at
  all, a deliberate transient-scratch trade-off).
- **Positive** — `banking_concurrent.tcyr` is now a permanent regression
  guard for the whole bank scheme, not just these four functions.
- **Negative** — `secret var`'s compiler guarantee is forfeited for
  banked arrays; correctness now depends on the author remembering the
  per-lane `memset`. Mitigated by the quirk-#9 documentation, the
  CONTRIBUTING code-style rule, and the race-detector.
- **Neutral** — if Cyrius ever gains a true thread-local *array*
  qualifier, the whole bank scheme (and this rule) collapses back to a
  plain `secret var X[N]` (roadmap "retire bank-indexing" item, still
  gated — 6.0.62 added per-thread TLS *slots*, not arrays).

## Alternatives considered

- **Keep `secret var`, serialize the banked functions behind a mutex** —
  rejected; reintroduces the `_sigil_batch_mutex` that 3.6.0 deleted, and
  throws away the per-worker-bank parallelism for no benefit.
- **Keep `secret var`, give each worker a fully separate array (not
  lanes of one)** — rejected; that is what banking already is at the
  storage level, but the `secret var` qualifier zeroizes by *declared
  array*, not by lane, so the whole-array wipe persists regardless.
- **Drop zeroization entirely (match `fp_*`)** — rejected; x25519's `W`
  and chacha20's keystream are genuinely secret, unlike the transient
  field products. Per-lane wipe keeps the hygiene at no race cost.

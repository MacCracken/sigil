# 0007 — Auto-assigned crypto banks for concurrent TLS

**Status**: Accepted
**Date**: 2026-06-29

## Context

Since 3.6.0 sigil makes a crypto primitive concurrency-safe by *banking*
its function-scope scratch: a `var X[N]` (a static global, CLAUDE.md
quirk #1) is widened to `var X[N*SIGIL_CRYPTO_BANKS]` and each thread
operates on its own lane `&X + cbank()*N` (`src/crypto_scratch.cyr`,
ADR 0001/0004). The lane index came from a thread-local slot that
**only the batch-verify path ever set** — `crypto_bank_set(1..workers)`
at worker entry. Every other thread read the unset slot as **0**.

That was fine while batch-verify was the only concurrent consumer. It
broke the moment cyrius `tls_native` / sandhi pointed concurrent TLS
handshakes at sigil: no TLS worker calls `crypto_bank_set`, so **every
concurrent handshake collided on bank 0**, racing the banked scratch.
The `yeo-cy-test` probe (2026-06-28) reproduced a server SIGSEGV /
ECONNRESET on the second simultaneous `TLS_AES_256_GCM_SHA384`
handshake. Worse, a 21-agent root-cause pass found the handshake-
critical primitives the TLS key schedule actually drives — HKDF, HMAC,
`ed25519_sign`, the one-shot SHA-2 hashes, and **both** AEAD suites —
were not banked at all (or `fl_alloc`'d their scratch, and `fl_alloc`
is not thread-safe, quirk #7).

A fix has to make concurrent crypto safe **without** requiring the
consumer to thread a per-worker call through every spawn — the protocol
layer lives in cyrius, and "TLS protocol stays in cyrius" is a standing
constraint. The bank index has to appear by itself.

## Decision

**`cbank()` auto-assigns a private lane to each thread on first use,
and `SIGIL_CRYPTO_BANKS` is raised 8 → 64.**

On a thread whose thread-local slot is still unassigned, the first
`cbank()` call atomically claims the next lane from a process-global
counter (`atomic_fetch_add(&_crypto_next_bank, 1)`, mapped into
`1..BANKS-1` so bank 0 stays the exclusive main/serial lane) and pins it
in the slot for the life of the thread. No `crypto_bank_set` call is
required by any consumer; the slot encoding changed to `(bank+1)` so a
fresh slot reads 0 = "unassigned". `crypto_bank_set` is retained for the
batch path's deterministic fan-out and back-compat.

64 lanes covers a 63-worker TLS-termination pool (one worker per core on
any realistic host) plus the main thread. Every banked array was widened
×8 accordingly.

In the same cycle, the previously-unbanked handshake + record primitives
were banked under this scheme (plain `var` + per-lane wipe, ADR 0004):
HKDF / HKDF-SHA384 (rewritten allocation-free, streaming the HMAC input
so the process-global `fl_alloc` concat scratch is gone), HMAC /
HMAC-SHA384, `ed25519_sign` + `sc_muladd`, the one-shot SHA-256/384/512
(now banked `_into` contexts — no `fl_alloc`), `sha384_finalize`, and the
full AES-GCM AEAD path (GHASH/CTR/encrypt/decrypt scratch + a banked
round-key schedule replacing the `fl_alloc`). The NI self-test probes
(`aes_ni_available` / `sha_ni_available`) got a CAS guard so two threads
can't race the one-time self-test scratch.

A multi-threaded consumer should still call `crypto_tls_main_init()` once
on the main thread at startup (installs main's TLS block; in practice any
main-thread crypto call — e.g. parsing the server cert/key — triggers it
via the lazy backstop before workers spawn). This is a one-time process
init, not a per-worker contract.

**Out of scope (deferred to 3.9.7, tracked on the roadmap, not buried):**
ChaCha20-Poly1305's `_cp_tag` `fl_alloc` mac_data buffer (needs a
streaming Poly1305); ECDSA P-256/P-384 sign+verify scratch (~100
pointer-globals/curve, latent — `tls_native` rejects RSA and the probe
cert is Ed25519); the bignum modexp/Montgomery and tls12_prf statics
(RSA / TLS 1.2 — off the TLS 1.3 server path).

## Consequences

- **Positive** — concurrent TLS handshakes/records are race-free with
  **zero per-worker consumer cooperation**; the fix lives entirely in
  sigil, honoring the crypto-boundary ownership. Validated by the new
  `tests/tcyr/concurrent_tls_handshake.tcyr` (16 auto-banked workers,
  >8 lanes, byte-for-byte vs. serial across sign + both HKDFs +
  transcript + both AEAD suites; stable 30/30).
- **Positive** — making the one-shot SHA-2 hashes and HKDF/HMAC
  allocation-free removes `fl_alloc` from the whole hot key-schedule
  path, not just the racing call sites.
- **Negative** — 64 lanes ×8 widening grows static (`.bss`) scratch
  (~404 KB → ~1.24 MB in the smoke build). Acceptable for a server-side
  trust library; flagged as the cost of the 64-lane ceiling.
- **Negative** — auto-assignment is bounded: more than 63 simultaneously-
  live crypto threads alias lanes (counter wraps mod BANKS-1). 63 worker
  cores is well beyond realistic TLS pools, but the ceiling is now a
  documented invariant rather than an implicit "batch workers only".
- **Neutral** — `_cp_tag` / ECDSA / bignum / tls12_prf remain unbanked
  until 3.9.7; concurrent callers on those specific paths (ChaCha-suite
  AEAD tag, ECDSA-cert servers, TLS 1.2) stay at-risk until then.

## Alternatives considered

- **Require consumers to call `crypto_bank_set` per worker** — rejected;
  pushes the fix into cyrius `tls_native` / sandhi (cross-repo) and
  cannot fix the crash from sigil alone, against the crypto-boundary
  ownership rule.
- **Documented "not concurrency-safe, serialize" contract only** — the
  issue's interim option; rejected as a non-fix that leaves multi-core
  TLS termination blocked.
- **A true per-thread arena (thread-local *array*)** — Cyrius offers
  per-thread TLS *slots* (6.0.52), not arrays, and the scratch is far
  larger than a TLS block; banking remains the only mechanism. If a
  thread-local array qualifier ever lands, the whole bank scheme (and
  this ADR) collapses to plain `secret var X[N]`.
- **Keep banks at 8** — rejected; 8 cannot cover a per-core TLS pool, and
  an auto-assigned thread could otherwise alias a live lane at low
  worker counts.

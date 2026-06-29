# 001 — `var X[N]` static semantics & banked crypto scratch

**The single most grep-hit invariant in `src/`.** Everything about sigil's
per-thread crypto-scratch banking follows from one Cyrius fact.

## The invariant (CLAUDE.md quirk #1)

A function-scope `var X[N]` **array** is a STATIC function-scope GLOBAL, not a
per-call stack array — confirmed by cyrius `src/frontend/parse_fn.cyr` and
`tests/tcyr/var_array_semantics.tcyr` (still true under cycc 6.x). Two
consequences:

- **Same-function reuse across sequential calls** works *iff* each call fully
  writes the buffer before reading it.
- **Concurrent threads share the array** — so any `var X[N]` reached on more
  than one thread at once is a data race.

Scalar `var x = …` locals ARE per-call. **Only arrays are static.**

## The banking pattern (the fix)

A racing `var X[N]` is widened to `var X[N * SIGIL_CRYPTO_BANKS]` and each call
operates on its own *lane*:

```cyrius
var bk = cbank();                 // this thread's lane index
var X[N * SIGIL_CRYPTO_BANKS];    // SIGIL_CRYPTO_BANKS = 64
var Xb = &X + bk * N;             // lane base — operate on Xb, not X
```

`cbank()` (`src/crypto_scratch.cyr`) returns the calling thread's lane. **Since
3.9.6 it AUTO-ASSIGNS** a private lane per thread on first use (an atomic
counter cycles new threads into lanes `1..63`; bank 0 is the main/serial lane),
so concurrent callers — notably cyrius `tls_native` / sandhi TLS workers — get
disjoint lanes with **no `crypto_bank_set` cooperation** (ADR 0007). The same
shape lane-slices `alloc`'d process-global scratch (ECDSA's ~150 buffers, bignum
/ RSA): `_X = alloc(SZ * SIGIL_CRYPTO_BANKS)` + `_X + cbank()*SZ`.

## Secret handling — plain `var` + per-lane `memset`, NEVER `secret var`

A banked array that holds secret state must be a **plain `var`** zeroized by an
explicit per-lane `memset(Xb, 0, N)` before return — **never `secret var`**. The
compiler's `secret var` whole-array zeroize-on-exit wipes *all 64 lanes*,
clobbering a sibling worker's live lane (the 3.8.0 ChaCha20/X25519 corruption,
caught by `tests/tcyr/banking_concurrent.tcyr`). See ADR 0004.

## The 3.9.7 corollary — `secret var` ARRAYS race even unbanked

The array-vs-scalar split applies to `secret var` too: a function-scope
`secret var X[N]` **array** is itself a static global that races concurrent
callers — only scalar `secret var x` locals are per-call. **Proven by a
2-thread probe under pin 6.3.5.** This bit the ECDSA DER wrappers
(`ecdsa_p256_sign_der` / `ecdsa_p384_sign_der` / `ecdsa_p256_verify_der`): their
`secret var sig` / `raw_sig` were assumed stack-local (a misread "cyrius
v6.2.25 arena fix" — that only removed a per-call bump-heap *leak*, not the
static/shared semantics) and raced the concurrent TLS CertificateVerify path.
Fixed in 3.9.7 by banking them.

**Rule of thumb when hardening a module for concurrency:** `grep 'secret var
[a-z_]\+\['` and bank every array on a reachable concurrent path; leave scalars
and genuinely main-thread-only (keygen-at-startup) arrays as-is.

## See also

- CLAUDE.md quirk #1 (var-array static), quirk #9 (banked secret scratch).
- [ADR 0004](../adr/0004-per-lane-zeroization-for-banked-crypto-arrays.md) — per-lane zeroization.
- [ADR 0007](../adr/0007-auto-banking-for-concurrent-tls.md) — auto-assigned lanes.
- `src/crypto_scratch.cyr` — `cbank()` + `SIGIL_CRYPTO_BANKS`.
- Audits `2026-06-16-3.8.0-…`, `2026-06-29-3.9.6-…`, `2026-06-29-3.9.7-…`.

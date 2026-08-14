# 003 — A module-level `var X[N]` costs 8N bytes, not N

**Status:** current (verified under cycc 6.5.21, 2026-08-14)
**Applies to:** every file-scope `var X[N]` in `src/`
**Found by:** 3.12.9's RSA/bignum de-banking, when the measured `.bss` saving
came in at exactly 8× the arithmetic.

## The rule

| Declaration site | `var X[N]` allocates |
|---|---|
| **Function-local** | **N bytes** — CLAUDE.md quirk #3, unchanged |
| **Module-level (file scope)** | **8N bytes** — N eight-byte slots |

Quirk #3 ("`var buf[N]` is N bytes, not N elements") is correct, but it
describes the **local** case only. It has been read as a whole-language rule,
and at file scope it is wrong by a factor of eight.

## How it was established

Two independent confirmations, because one ratio is a coincidence and two are a
rule.

**1. Direct probe.** A file whose only global is `var G[20000]`, built with
`cyrius build`, reports `large static data (160000 bytes)` — 20000 × 8.

**2. The codebase.** 3.12.9 deleted 40 file-scope array globals from
`src/rsa.cyr` and `src/bignum.cyr` whose declared sizes sum to **1,249,280**.
A/B-building `programs/smoke.cyr` with only those files swapped moved static
data **10,779,648 → 785,408 bytes**, a reduction of **9,994,240**.

```
1,249,280 × 8 = 9,994,240      exact, to the byte
```

## Why it mattered

Sigil's banked scratch is declared as `var X[N * SIGIL_CRYPTO_BANKS]` with a
comment stating the intended footprint — e.g.:

```
var _bn_mont_r2src[66560];  # 1040 * SIGIL_CRYPTO_BANKS  (2^(128*limbs) src)
```

That buffer did not occupy 66,560 bytes. It occupied **532,480**. Every such
comment in the tree understates its global by 8×, which is how the library
accumulated **9.53 MiB** of `.bss` that nobody had costed. The 3.9.6 decision to
widen `SIGIL_CRYPTO_BANKS` from 8 to 64 was recorded as growing static scratch
"~14 MB (lazy zero-pages; informational)" — that figure was right, but it was
right for a reason nobody had identified.

## What to do about it

- **When sizing a global array, multiply by 8.** The declared number is slots,
  not bytes.
- **Prefer a function-local.** Since cyrius 6.3.15 an array local inside the
  122,880 B per-fn budget is a per-thread stack slot (see
  [001](001-var-array-static-semantics.md)), so it is both correct under
  concurrency *and* eight times cheaper per declared unit. 3.12.9 took this
  route for all of `rsa.cyr` and `bignum.cyr`.
- **Do not "fix" this by dividing the declared size by 8.** The index
  arithmetic in banked code (`&X + cbank() * N`) is written in bytes and is
  correct as it stands; shrinking the declaration would produce out-of-bounds
  lanes. Either leave the global sized as it is, or localise it.

## Remaining exposure

The symmetric and EC scratch (`sha256`, `sha512`, `hmac`, `hkdf`, `aes_gcm`,
`chacha20`, `poly1305`, `ecdsa_p256`, `ecdsa_p384`, `ed25519`, `x25519`,
`argon2`, `blake2b`, `tls12_prf`) is still banked and therefore still paying
the 8× multiplier. That is the bulk of the 785,408 bytes that remain, and
localising it is the natural follow-on to 3.12.9 — tracked in the roadmap.

## See also

- [001 — `var X[N]` static semantics + banked crypto scratch](001-var-array-static-semantics.md)
- CLAUDE.md quirks #1 (array locals are per-thread since 6.3.15) and #3
- `docs/development/issues/archive/2026-08-08-rsa-verify-shared-lane-accepts-forged-signature.md`
- CHANGELOG `[3.12.9]`

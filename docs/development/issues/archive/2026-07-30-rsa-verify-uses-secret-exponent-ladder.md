# RSA public-key verify runs the secret-exponent ladder — ~235× slower than OpenSSL, ~2.3× of it free

**Filed:** 2026-07-30
**Reporter:** agnosai (Rust → Cyrius port), while porting `server/auth.rs`'s
RS256 JWT validation onto `rsa_pkcs1v15_verify_sha256`.
**Version:** sigil 3.12.1 (measured against the tagged bundle resolved into
agnosai's `lib/sigil.cyr`; line numbers below are **sigil's own `src/`**).
**Severity:** Performance, on an unauthenticated request path. Not a
correctness or security defect — every result is right, and nothing here is a
side-channel report. Filing it because the cost lands on a DoS-relevant path and
because a chunk of it is recoverable without touching the arithmetic.

**Not a release blocker for us.** agnosai ships the current behaviour and has
documented the consequence; this is a "when convenient" report with the
measurements already done.

---

## RESOLVED — sigil 3.12.2 (2026-07-30). Both pieces.

**Piece 1 — `bn_mont_modexp_pub`** (`src/bignum.cyr`). Exactly the transplant
suggested below: the same CIOS Montgomery core with `bn_modexp`'s high-bit
scan and a conditional multiply. For e = 65537 the mont_mul count went
**51 → 20** — slightly better than the 22 estimated here, because seeding the
accumulator with the base at the high bit (rather than starting from
Montgomery 1 and squaring it) saves the leading square+multiply pair. Three
call sites converted, not one: `_rsa_recover_em` as suggested, **plus** the
sign path's blinding `r^e` (`rsa.cyr:593`) and its verify-after-sign `s^e`
(`rsa.cyr:610`), which are also public-exponent operations. The
secret-exponent ladder is untouched, and the "public exponents only" rule is
recorded in [ADR 0008](../../adr/0008-native-asm-multiply-and-public-modexp.md).

**Piece 2 — the lead was right.** `_mul64`'s memory round-trip *was* where the
rest lived. sigil now has `src/mul64.cyr`: an x86-64 `MUL r/m64` in an `asm{}`
block, replacing **four** separate copies of the portable 32-bit-halves
decomposition (bayan's `_mul64` under `bignum.cyr`, `_p384_mul64`, and two
inlined into `bigint_ext.cyr`). `_bn_mont_mul` at 32 limbs went **42 µs →
20.264 µs**. Cyrius can express what was needed — a leaf `asm{}` block with
`param_load`, the same pattern `sha_ni.cyr` / `aes_ni.cyr` have used since
2.9.x — so no compiler work was required.

### Measured, same host, both sides at pin 6.5.3

| | Filed | 3.12.2 | |
|---|---|---|---|
| `rsa_pkcs1v15_verify_sha256`, RSA-2048 | 3.29 ms | **1.178 ms** | 2.78× |
| `_bn_mont_mul`, 32 limbs | 42 µs | **20.264 µs** | 2.07× |
| RSA-2048 CRT sign (bonus — Piece 1 hit it too) | 70.132 ms | **41.276 ms** | 1.70× |

**~235× vs OpenSSL → ~84×.** Still portable code against hand-tuned assembly
with ADX/MULX, as the report predicted, but the recoverable part was
recovered. **agnosai's ~300 verifies/second/core becomes ~860.**

Two notes back to the reporter:

- The report's framing was accurate on every point, including that this was
  neither a correctness nor a side-channel finding. Worth adding: replacing
  the portable multiply is a **side-channel improvement** — the code it
  replaced carries two *value-dependent* branches per product, where `MUL r64`
  is data-independent. So RSA *signing*, which does branch on nothing but
  must not leak, got quietly safer as well as 1.70× faster.
- The suggested `bn_mont_modexp_pub` name and no-API-break shape were both
  adopted as filed.

Remaining, if a consumer ever needs it: a full `asm{}` CIOS *inner loop*
(rather than an asm leaf multiply) would remove the per-product call overhead
and the `_bn_m64` round-trip entirely. Not scoped — the leaf multiply captured
most of the win at a fraction of the audit surface.

---

## Summary

`rsa_pkcs1v15_verify_sha256` — a **public**-key operation on **public** operands
— routes through `bn_mont_modexp`, which `src/bignum.cyr:626-628` documents as:

> Constant-time in the exponent (square+multiply every bit over the full width).
> Modulus MUST be odd. **Safe for the secret exponent.**

That is the right primitive for signing and the wrong one for verifying. Its
sibling `bn_modexp` (`src/bignum.cyr:347`) *does* locate the exponent's high bit
first (`:359-368`) and multiply conditionally, but it is schoolbook rather than
Montgomery, so the verify path reasonably prefers Montgomery — and there is no
Montgomery variant for a public exponent. The call site knows this and says so
(`src/rsa.cyr:124-125`):

> operands are public — Montgomery is used purely for speed, not for
> the side-channel posture

…and then calls the constant-time ladder anyway (`src/rsa.cyr:126`), because it
is the only Montgomery modexp available.

## Measurements

x86_64 Linux, cyrius 6.5.3, sigil 3.12.1, 2048-bit key (the standard e=65537).

| What | Time |
|---|---|
| `rsa_pkcs1v15_verify_sha256`, RSA-2048 | **3.29 ms** |
| `openssl speed rsa2048` verify, same box | **14 µs** (70,445/s) |
| `_bn_mont_mul`, 32 limbs, in isolation | **42 µs** |

**~235× slower than OpenSSL.** Some of that gap is inherent — a portable bignum
against hand-tuned assembly with ADX/MULX will never be close — but it decomposes
into two independent pieces, and one is cheap to close.

### Piece 1 — the ladder does 2.3× more work than a public exponent needs

`bn_mont_modexp`'s loop (`src/bignum.cyr:652`) starts at `exp_blen * 8 - 1` and
walks **every bit of the exponent's byte width**, with an unconditional multiply
plus a `_bn_ct_select` per bit:

```
var i = exp_blen * 8 - 1;
while (i >= 0) {
    _bn_mont_mul(res, res, res, modulus, n0inv, limbs);      # square
    _bn_mont_mul(tmp, res, basem, modulus, n0inv, limbs);    # ALWAYS multiply
    _bn_ct_select(res, tmp, res, _bn_exp_bit(exp, exp_blen, i), limbs);
    i = i - 1;
}
```

For RSA verification the exponent is 65537, which `rsa_pubkey_from_der` hands
back as **3 bytes** (`01 00 01`). So:

| | mont_muls |
|---|---|
| Current: 24 iterations × 2, plus 3 setup/teardown | **51** |
| A public ladder: high bit at 16 → 17 squarings + 2 multiplies, plus 3 | **22** |

**51 → 22 is 2.3×**, and 51 × 42 µs ≈ 2.1 ms of the measured 3.29 ms, so the
arithmetic accounts for essentially all of it.

Suggested shape: a `bn_mont_modexp_pub` that reuses the same CIOS core but takes
`bn_modexp`'s high-bit scan (`:359-366`) and a conditional multiply. `bn_modexp`
already contains both halves; this is mostly a transplant, and it leaves the
secret-exponent ladder untouched for signing. `_rsa_recover_em`
(`src/rsa.cyr:94`) would be the only caller to switch.

### Piece 2 — `_bn_mont_mul` at 42 µs is where the rest lives

That is ~20 ns per inner `_mul64` round (2s² = 2048 of them at s=32), which is
where the remaining ~30× against OpenSSL sits. The CIOS structure
(`src/bignum.cyr:513`) is textbook and I am not suggesting the algorithm is
wrong. One observation, offered as a lead rather than a diagnosis since I do not
know cyrius's codegen well enough to be sure it is the cause: every partial
product round-trips through memory —

```
_mul64(load64(a + j * 8), bi, m64, m64 + 8);
...
C = load64(m64 + 8) + c1 + c2;
```

`_mul64` writes lo/hi through pointers into the per-lane `_bn_m64` slot, so each
of the 2048 inner steps stores two words and reloads them. If cyrius can express
a 64×64→128 multiply that yields both halves as values, keeping the product in
registers would remove two stores and two loads per step.

## Reproduction

Verify timing (needs a 2048-bit key + a signed message; agnosai's suite has
both):

```
rsa_pkcs1v15_verify_sha256(n_be, n_len, e_be, e_len, msg, msg_len, sig, sig_len)
```

Isolated `_bn_mont_mul`, which needs nothing but an odd 32-limb modulus:

```
var limbs = 32;
var n[256]; var a[256]; var b[256]; var o[256];
for (var k = 0; k < limbs; k = k + 1) {
    store64(&n + k * 8, 0xFFFFFFFF00000001 + k);
    store64(&a + k * 8, 0x0123456789ABCDEF + k);
    store64(&b + k * 8, 0x76543210FEDCBA98 + k);
}
store64(&n, load64(&n) | 1);
var n0inv = _bn_mont_n0inv(load64(&n));
# ... bench_batch over _bn_mont_mul(&o, &a, &b, &n, n0inv, limbs)
```

Baseline for comparison: `openssl speed -seconds 2 rsa2048`.

## Why it matters downstream

agnosai serves RS256 JWTs on its HTTP API. At 3.29 ms a core sustains ~300
verifies/second, and the verify runs **before** the request is authenticated —
so it is reachable by anyone who can reach the endpoint. agnosai has accepted
that and answers it with rate limiting rather than by reordering checks (moving
the cheap `alg` check ahead of the signature meant parsing attacker-controlled
JSON pre-authentication, which was a worse failure). Piece 1 alone would take
~300/s to ~700/s for a transplant of code that already exists in the same file.

Nothing in agnosai is blocked on this.

## What is explicitly NOT being reported

- **Not a side-channel finding.** The verify path handles only public values;
  running a constant-time ladder there is over-provisioning, not a defect, and
  the sign path should keep it.
- **Not a correctness finding.** Every signature verified correctly across
  agnosai's suite, including tampered-signature, tampered-payload, wrong-key and
  algorithm-confusion vectors.
- **No API break requested.** A new `bn_mont_modexp_pub` alongside the existing
  entry point leaves every current caller working.

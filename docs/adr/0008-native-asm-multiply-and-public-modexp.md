# 0008 — A native asm multiply, and a deliberately non-constant-time modexp

**Status**: Accepted
**Date**: 2026-07-30

> Decided 2026-07-30 (Robert), during the 3.12.2 cycle, in response to the
> agnosai consumer report
> [`2026-07-30-rsa-verify-uses-secret-exponent-ladder`](../development/issues/archive/2026-07-30-rsa-verify-uses-secret-exponent-ladder.md).

## Context

agnosai filed a performance report against RSA verification: at 3.29 ms per
RSA-2048 verify on an unauthenticated HTTP request path, a core sustains ~300
verifies/second. The report decomposed the cost into two independent pieces
and — usefully — did the measurements.

**Piece 1.** `rsa_pkcs1v15_verify_sha256`, a *public*-key operation on
*public* operands, routed through `bn_mont_modexp`, which `src/bignum.cyr`
documents as constant-time in the exponent and "safe for the secret
exponent". That is the right primitive for signing and the wrong one for
verifying: it walks every bit of the exponent's byte width with an
unconditional multiply. For `e = 65537`, handed back by `rsa_pubkey_from_der`
as the three bytes `01 00 01`, that is 51 Montgomery multiplies where a
public schedule needs 20. The call site already knew — its comment said
"operands are public — Montgomery is used purely for speed, not for the
side-channel posture" — and then called the constant-time ladder anyway,
because it was the only Montgomery modexp available.

**Piece 2.** `_bn_mont_mul` at 42 µs for 32 limbs. It runs 2·s² = 2048
64×64→128 products, each going through bayan's portable `_mul64`: four 32×32
multiplies, a shifted middle-term recombination, and two comparison-based
carry fixups, with the result round-tripping through memory.

Two things made this more than a local optimisation.

First, sigil had **four** separate copies of that portable multiply —
bayan's `_mul64` under `bignum.cyr`, `_p384_mul64` under `ecdsa_p384.cyr`,
and two inlined into `bigint_ext.cyr` — so the same fix applied to the RSA,
Ed25519, ECDSA P-256 and ECDSA P-384 paths at once.

Second, [ADR 0006](0006-park-ec-scalarmul-10ms-target.md) had parked the
`ecdsa_p256_verify` ≤ 10 ms target as "not reachable with current
approaches", naming as one of three unavailable exotic levers "*a
hand-written asm multiply (MULX/ADCX/ADOX) — needs the cyrius `asm`-block
global-symbol pseudo*". That premise turned out to be **too pessimistic**: a
leaf function needs no global-symbol pseudo at all. `param_load` plus raw
opcode bytes — the pattern `sha_ni.cyr` and `aes_ni.cyr` have used since
2.9.x — is sufficient, and a plain `MUL r/m64` needs neither MULX nor ADX.

## Decision

**Three decisions, taken together.**

**1. Own the 64×64→128 multiply.** `src/mul64.cyr` provides `_nmul64` and
`_nmul64_hi`, an x86-64 `MUL r/m64` inside an `asm{}` block with a portable
aarch64 fallback, and every big-integer engine in sigil routes through it.
Unlike the SHA-NI / AES-NI dispatchers there is **no CPUID probe and no
runtime feature detection**: `MUL r/m64` is baseline x86-64, not an extension.
CLAUDE.md's "runtime feature detection over compile-time gating" rule is about
*optional* ISA features and does not reach the base ISA. Mechanics and
register discipline: [architecture note 002](../architecture/002-native-asm-multiply.md).

**2. Ship a deliberately non-constant-time modexp, with a stated rule for
who may call it.** `bn_mont_modexp_pub` reuses the CIOS Montgomery core but
takes `bn_modexp`'s public schedule: locate the exponent's high bit, seed with
the base, then square every iteration and multiply *only* on a set bit. Its
control flow depends on the exponent, so:

> **The rule: `bn_mont_modexp_pub` may be called only where the exponent is
> public. RSA `d` / `dp` / `dq` keep `bn_mont_modexp`.** Both entry points
> carry that rule in their header comments, and the three converted call
> sites (`_rsa_recover_em`; the sign path's blinding `r^e` and its
> verify-after-sign `s^e`) each carry a one-line justification.

Recording this as an ADR because sigil IS the trust boundary, and a future
reader who finds a non-constant-time modexp in a crypto library will
reasonably ask why. The answer is that over-provisioning a public operation
is not free, and 2.5× is the price.

**3. Reopen ADR 0006's ≤ 10 ms question — but do not silently close it.**
`ecdsa_p256_verify` measured **9.808 ms** after this work, against 10.539 ms
on the same host at the same toolchain pin. That is below the parked target.
ADR 0006 is **not** superseded by this ADR: its disposition was Robert's
call, the crossing is narrow (7 %) and single-host, and "the target is met"
deserves its own deliberate decision rather than being inherited from a
performance side-effect. What this ADR records is that **the premise changed**
— the asm-multiply lever is now demonstrably available and no longer gated on
upstream cyrius work. The roadmap backlog item is updated to say so.

## Consequences

- **Positive** — RSA-2048 verify 3.276 → **1.158 ms** (2.83×); RSA-2048 CRT
  sign 70.1 → **40.5 ms** (1.73×); `ed25519_verify` 6.425 → **5.189 ms**;
  `ecdsa_p256_verify` 10.539 → **9.808 ms**. agnosai's JWT endpoint goes from
  ~300 to ~860 verifies/second/core on the same hardware.
- **Positive, and easy to miss** — this is a **side-channel improvement**, not
  a trade. The portable multiply it replaces carries two *value-dependent*
  branches per product; `MUL r64` is data-independent. On RSA's secret-exponent
  ladder and ECDSA P-384's signing nonce, the native path removes two
  data-dependent branches per limb product.
- **Negative** — sigil now owns hand-written machine code on the hottest path
  in the library, and a third `asm{}` site to maintain. `_nmul64_hi` returns
  through `rax` by falling through its asm block with no trailing `return`,
  which is a real dependency on cyrius codegen. It is gated by a differential
  KAT in `tests/tcyr/bignum.tcyr` that fails loudly at build time if a future
  toolchain breaks it, but the dependency exists.
- **Negative** — a non-constant-time modexp now exists in the API surface.
  Mitigated by naming (`_pub`), by header comments on both entry points, and
  by justifications at every call site — but a careless future caller could
  reach for it with a secret exponent.
- **Neutral** — the aarch64 path keeps the portable multiply, so its
  performance and its branchy timing posture are both unchanged from 3.12.1.
- **Neutral** — ADR 0006's roadmap item now needs a decision it did not need
  before.

## Alternatives considered

- **Piece 1 only (`bn_mont_modexp_pub`, no asm).** This is what the issue
  actually asked for, and it is genuinely cheap — the transplant is ~40 lines
  of code that already existed in the same file. It delivers 3.276 → 1.687 ms.
  Rejected as the *whole* answer because it leaves the 30× against OpenSSL
  entirely untouched and leaves four copies of a slow multiply in place.
  Shipped as one half of the work rather than instead of it.
- **A full asm CIOS inner loop**, rather than an asm leaf multiply. Larger
  win — it would also remove the per-product call overhead and the `_bn_m64`
  memory round-trip the issue flagged. Rejected for this cycle: it is a
  substantially bigger audit surface on the single most correctness-critical
  loop in the library, and the leaf multiply captures most of the benefit
  (42 → 20.2 µs) at a fraction of the risk. Left explicitly available.
- **BMI2 `MULX` instead of `MUL`.** `MULX` avoids the implicit `RDX:RAX`
  operands and would compose better with ADCX/ADOX in a future full-loop
  version. Rejected because it *is* an optional ISA extension, so it would
  reintroduce exactly the CPUID probe + dispatch + self-test machinery that
  plain `MUL` lets us skip — for no measurable gain on a leaf function.
- **Leaving the EC paths alone and shipping bignum only.** Rejected: the
  identical primitive sat under three more engines, the change is mechanical,
  and skipping them would have left the ADR 0006 premise untested.
- **Retrying `bn_modexp` (schoolbook, already public-scheduled) for verify.**
  Rejected on measurement: it is 10.38 ms against the Montgomery core's
  1.15 ms. Montgomery is the right core; only its *schedule* was wrong.

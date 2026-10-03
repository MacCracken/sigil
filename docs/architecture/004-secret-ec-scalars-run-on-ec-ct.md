# 004 — secret EC scalars run on `src/ec_ct.cyr`, never on the verify arithmetic

**What it affects:** anything that multiplies a P-256 / P-384 point by a secret scalar or
does arithmetic mod n on a secret — `src/ecdh.cyr`, `src/ecdsa_sign.cyr`,
`pt_scalarmul_secret` / `pt384_scalarmul_secret` — and anyone tempted to call
`fp_p256_*`, `fn_p256_*`, `u256_*`, `pt_add`, `pt_scalarmul`, `p256_scalarmul_base`,
`p256_scalarmul_var` (or the P-384 names) with a key, a nonce or a value derived from one.

Landed 3.13.8. Decision record: [ADR 0009](../adr/0009-constant-time-ec-engine-for-secret-scalars.md).

## The invariant

`src/ecdsa_p256.cyr` and `src/ecdsa_p384.cyr` are **variable-time by construction**. Their
field arithmetic branches on operand values (conditional final subtracts, carry fix-ups
written as `if`, early-exit compares and zero tests, Karatsuba corrections); their point
formulas branch on the point at infinity and on P == ±Q; their comb and window tables are
indexed by scalar nibbles. That is correct for verification, whose inputs are all public, and
it is why verify is fast.

Every secret goes through `src/ec_ct.cyr` instead: Montgomery arithmetic with branch-free
carries and selects, complete projective formulas, a fixed 4-bit window over every window of
the scalar with a full-table masked lookup, Fermat inversion with public exponents. The
engine's contract is written at the top of the file; the short form is *no branch and no
memory address depends on a secret*.

## How it is checked

- **Structurally, in the compiled code.** Build any program that includes the engine with
  `CYRIUS_SYMS=<file>` and disassemble each `_ect_*` function: every conditional jump
  (`jcc` on x86_64; `b.cond` / `cbz` / `tbz` on aarch64) corresponds to a loop bound (limb
  count, window count, byte count, exponent length), the public exponent bit in `_ect_pow`,
  the pointer comparison in `_ect_reduce_once`, or a public verdict in a caller. The 3.13.8
  audit lists the counts per function for both architectures; a new branch in that list is
  the thing to explain.
- **By timing, as a smoke check.** `tests/tcyr/ecdh.tcyr` and
  `tests/tcyr/ecdsa_sign_timing.tcyr` compare medians for scalars of very different weight
  and length; the 3.13.0 ladder ran k = 1 in under 1% of the k = n - 1 time, the engine
  within ~1%.

## Things that are easy to get wrong

- **A comparison is not a select.** `if (x < y)` is a branch. Carries and borrows in the engine
  are the majority-of-MSB forms (`((x & y) | ((x | y) & ~s)) >> 63`); keep it that way even
  where cyrius currently lowers a comparison to `setcc`, because that is codegen, not contract.
- **`_nmul64_hi_sw` is on the secret path on aarch64.** It became branch-free at 3.13.8; the
  32-bit-halves form it replaced had two value-dependent carry fix-ups.
- **Wipe from the outermost frame.** `_ect_burn_stack(n)` clears the n bytes directly below its
  caller, which is where the dead frames of the field and point operations lie (the stack grows
  down, so that is the HIGH end of its pad). Call it from the public entry point after the
  worker returns; a worker that calls it on itself leaves its own scalar spill slots behind
  (`tests/tcyr/ecdh.tcyr` "zeroisation" finds them).
- **A public point is still validated.** ECDH refuses a peer key that is not exactly
  `0x04 || X || Y` with X, Y < p on the curve; the comparison of X and Y against p must not be
  done modulo p (the x = p encoding of the point with x = 0 is a test case).

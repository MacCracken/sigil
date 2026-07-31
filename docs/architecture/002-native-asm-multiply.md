# 002 — the native `asm{}` 64×64→128 multiply

**What it affects:** `src/mul64.cyr` (the primitive), and every big-integer
engine that consumes it — `src/bignum.cyr` (RSA), `src/bigint_ext.cyr`
(Ed25519, ECDSA P-256), `src/ecdsa_p384.cyr` (ECDSA P-384). If you are
touching a limb loop, or adding a fourth big-integer engine, read this first.

Landed 3.12.2. It is the **third** `asm{}` site in `src/`, after
`sha_ni.cyr` and `aes_ni.cyr`, and the first one on a path with no runtime
feature detection.

## Why a hand-written multiply exists at all

Every big-integer operation in sigil bottoms out in one primitive: multiply
two 64-bit limbs and keep all 128 bits. Through 3.12.1 sigil had **four
separate portable implementations** of it — bayan's `_mul64`, `_p384_mul64`,
and two copies inlined into `bigint_ext.cyr` — all the same 32-bit-halves
decomposition: four 32×32 multiplies, a shifted middle-term recombination,
and two comparison-based carry fixups.

x86-64 has done the whole thing in one instruction since 2003. `MUL r/m64`
puts the 128-bit product in `RDX:RAX`.

## The thing that is easy to get wrong: no dispatch

`sha_ni.cyr` and `aes_ni.cyr` both carry a CPUID probe, a cached availability
sentinel, a self-test gate, and a software fallback selected at runtime.
**`mul64.cyr` deliberately has none of that**, and that asymmetry is the point
of this note:

`MUL r/m64` is **baseline x86-64**, not an ISA extension. There is no CPUID
bit to test, because there is no CPU that runs sigil's x86 build and lacks it.
So the gate is a compile-time `#ifdef CYRIUS_ARCH_X86` with a portable
fallback for aarch64 — *not* the runtime detection CLAUDE.md mandates for
AES-NI / SHA-NI. That rule exists to avoid compile-time gating on
*optional* features; it does not apply to the base ISA.

Do not "fix" this by adding a probe.

## Two entry points, and why the second one exists

```cyrius
fn _nmul64(a, b, out_lo, out_hi): i64   // both halves, through pointers
fn _nmul64_hi(a, b): i64                // high half only, returned in rax
```

`_nmul64` suits `bignum.cyr`, whose CIOS loop already owns a banked 16-byte
`lo||hi` slot (`_bn_m64`).

`_nmul64_hi` exists because of **note 001**. `u256_mul_full` /
`_u256_mul_full_schoolbook` (`bigint_ext.cyr`) and `u384_mul_full`'s callers
run on the **Ed25519 parallel batch-verify path**, and are documented
thread-safe by having *no static scratch at all*. Receiving a pointer-form
result would need a `var lo[8]` — which is a function-scope STATIC GLOBAL
(note 001), reintroducing exactly the race 3.9.7 spent a cycle removing.
Returning a scalar sidesteps it: scalar `var x = …` locals ARE per-call.

Its callers pair it with a plain `a * b` for the low half. That is exact, not
an approximation: cyrius's `*` on `i64` is a wrapping multiply, and the low
64 bits of a product are identical for signed and unsigned operands in two's
complement.

## The toolchain dependency, and the gate on it

`_nmul64_hi` has **no trailing `return`**. The asm block leaves the value in
`rax` and the function falls through to its epilogue — a `return 0;` would
clobber it. That is a real dependency on cyrius codegen, verified against
pin 6.5.3 by direct probe.

It is not left to trust. `tests/tcyr/bignum.tcyr` cross-checks `_nmul64_hi`
against bayan's portable `_mul64` over 17 adversarial operand pairs. **A
toolchain that ever zeroes or reuses `rax` in the epilogue fails the suite at
build time** rather than silently corrupting every ECDSA and Ed25519
signature. If you change that function, keep the gate.

## Register discipline

```
rax = a   (MUL's implicit multiplicand; the LOW half on exit)
rcx = b   (the explicit operand)
rdx       (clobbered by MUL; receives the HIGH half)
rsi/rdi = out_lo / out_hi   (_nmul64 only)
```

All five are **caller-saved** in SysV x86-64. Nothing callee-saved (`rbx`,
`rbp`, `r12`–`r15`) is touched, so — unlike the CPUID probes in `sha_ni.cyr` /
`aes_ni.cyr`, which must `push rbx` — no push/pop is needed. Both blocks are
straight-line with no calls.

In `_nmul64`, **both pointer parameters are loaded before the `MUL`**, so the
`rdx` clobber cannot eat one. That ordering is load-bearing; do not reorder
the `param_load`s below the multiply.

Two compiler facts make this safe, both read from cyrius `6.5.3` source
rather than assumed:

- Any function containing an `asm` token is **force-excluded from register
  allocation** (`src/frontend/parse_fn.cyr`), so the compiler holds nothing
  live across the block.
- `param_load(reg, idx)` resolves each parameter's spill slot **at emit time**
  (`src/backend/x86/emit.cyr`, `ASM_PARAM_LOAD`) using the same formula the
  prologue spills with. Hardcoded `[rbp-N]` literals are what caused the
  6.1.20 SIGILL re-break documented in `sha_ni.cyr`'s header. Never hand-roll
  the parameter loads.

## Constant-time posture — this is an improvement, not a trade

The portable code being replaced carries **two value-dependent branches** per
product (the `mid_carry` / `lo_carry` fixups). `MUL r64` is data-independent
on every x86-64 microarchitecture sigil targets.

So on the secret-operand paths — RSA's secret-exponent ladder, ECDSA P-384's
signing nonce — the native path both removes two data-dependent branches and
runs faster. There is no side-channel cost to weigh against the speed-up.

The aarch64 fallback (`_nmul64_hi_sw`) keeps the old branchy shape; on that
target the posture is unchanged from 3.12.1, not worsened.

## Measured effect (3.12.2, x86-64)

| Unit | 3.12.1 | 3.12.2 |
|---|---|---|
| `_bn_mont_mul`, 32 limbs (2048 products) | 42 µs | **20.2 µs** |
| `fp_mul` (Curve25519 field) | 900 ns | **731 ns** |
| `ed25519_verify` | 6.425 ms | **5.189 ms** |
| `ecdsa_p256_verify` | 10.539 ms | **9.808 ms** |

The `ecdsa_p256_verify` row crosses **below 10 ms**, which is the target
[ADR 0006](../adr/0006-park-ec-scalarmul-10ms-target.md) parked as "not
reachable with current approaches". See
[ADR 0008](../adr/0008-native-asm-multiply-and-public-modexp.md) for what that
means for ADR 0006.

## Related

- [`001-var-array-static-semantics.md`](001-var-array-static-semantics.md) —
  why `_nmul64_hi` returns a scalar instead of writing through a pointer.
- [ADR 0008](../adr/0008-native-asm-multiply-and-public-modexp.md) — the
  decision record for this primitive and the public-exponent modexp.
- `docs/development/issues/archive/2026-07-30-rsa-verify-uses-secret-exponent-ladder.md`
  — the consumer report that prompted it ("Piece 2").

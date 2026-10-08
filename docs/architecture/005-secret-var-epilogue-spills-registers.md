# 005 — a `secret var` function's epilogue writes live registers into dead stack after its wipe

> **LIFTED at 3.13.11 (pin cyrius 6.7.5).** cyrius 6.6.15 fixed this — `EDEFER_RESTORE` now
> zeroes the save area before releasing it (cyrius CHANGELOG [6.6.15], "the secret-var epilogue
> spill gap") — and `tests/tcyr/secret_epilogue.tcyr` proves it under sigil's pin: markers in
> every saved register, a `secret var` function returning with them, and a window over the
> released frames finds none (7 of 8 under cyrius 6.6.14, 0 under 6.7.5; x86_64 and aarch64),
> with an anti-vacuous control that leaves all eight one frame down. The text below is the
> record of the defect. What changed for the rules is in "After the lift" at the end.

**What it affects:** every function that holds a `secret var` and returns while a register still
holds a secret or secret-derived value, and every public entry point that relies on
`_ect_burn_stack` to clear what its callees left (`src/ecdsa_sign.cyr`, `src/ecdh.cyr`,
`src/ec_ct.cyr`); the `asm {}` blocks that leave state in vector registers (`src/sha_ni.cyr`,
`src/aes_ni.cyr`).

Found 3.13.8 under cyrius 6.6.9; still true of the cyrius 6.6.15 development compiler. Filed for
cyrius by the 3.13.8 lane (draft for the 6.6.15 integrator).

## The invariant

cyrius compiles a `secret var` wipe as a `defer` block, and every function holding a `defer`
runs the defer walker on each return (cyrius `src/frontend/parse.cyr` `_defer_emit_walk`). The
walker saves the whole return convention into a 64-byte area just below the stack pointer —
**x86_64: rax, rdx, r8, the entry rsp, xmm0, xmm1; aarch64: x0–x3, q0, q1** — runs the blocks
(the wipe among them), reloads the registers and pops the area **without clearing it** (cyrius
`EDEFER_SAVE` / `EDEFER_RESTORE`, x86 `src/backend/x86/float.cyr`, aarch64
`src/backend/aarch64/emit.cyr`, both CHANGELOG [6.6.7]). So whatever those registers hold at the
return is written into dead stack *after* the wipe.

A plain function (no `secret var`, no `defer`) does not do this. A standalone probe — a
`secret var` function that loads markers into xmm1 and rdx and returns — leaves both in the dead
stack; the same function without `secret` leaves neither.

## What it cost

After `ecdsa_p256_sign` returned in the first 3.13.8 draft, words 0–3 of the RFC 6979 nonce k sat
212–224 bytes below the caller, directly above the signer's 8 KB stack burn. The signer held its
`secret var` block in the same function that called the burn, so the epilogue ran after the burn
and saved xmm1 — which still held the SHA-NI state of the HMAC_DRBG's last round, i.e. k. With k
and one signature, d = r^-1(s·k − e).

## Rules

- **Burn from a plain wrapper.** A public entry point that ends with `_ect_burn_stack` holds no
  `secret var` (and no `defer`); the secret block lives in a callee (`_ecs_sign_p256`,
  `_ecdh_shared`, …), whose epilogue spill then lands inside the region the wrapper burns.
- **Clear vector registers at the end of an `asm {}` block that put secret state in them.**
  `_sha_ni_compress_one` clears xmm0–xmm7 (and its scratch and edx); the AES-NI block functions
  clear xmm0. A register outlives the block and the function, and a later spill — anyone's
  `secret var` epilogue, in sigil or in the caller — writes it to memory where no burn reaches.
- **Test with a spill.** The "zeroisation" groups of `tests/tcyr/ecdsa_sign.tcyr` and
  `tests/tcyr/ecdh.tcyr` call a `secret var` function right after the entry point returns, so a
  register that still holds a secret is written into the region they scan. Without the SHA-NI
  clear the signing group finds 4 words of k even with the full burn.

## Scope

sigil's other `secret var` functions (Ed25519, X25519, HKDF, the PEM/key parsers, …) are not
restructured: if one returns with a secret in rax / rdx / r8 / xmm0 / xmm1 (x86_64) or x0–x3 /
q0 / q1 (aarch64), the epilogue writes it below its frame. The cyrius fix (zero the area in
`EDEFER_RESTORE`) closes that for all of them; until then the two rules above are how a sigil
entry point makes its own guarantee.

## After the lift (3.13.11)

- **Burn from a plain wrapper** — kept. The signers and ECDH entry points still hold their
  `secret var` block in a callee and burn from a plain wrapper; that remains correct and costs
  nothing, and the burn still clears what the callees left in their frames.
- **Clear vector registers at the end of a secret `asm {}` block** — kept, and independent of
  this defect: a register outlives the block and the function, and anything that later spills it
  writes it to memory.
- **Test with a spill** — the mechanism changed. Under cyrius ≥ 6.6.15 a `secret var` call no
  longer spills anything, so the zeroisation groups had silently stopped seeing registers
  (measured at 3.13.11: with the SHA-NI register clear deleted, `ecdsa_sign.tcyr` still passed).
  They now call `regdump_spill()` (`tests/regdump.cyr`), which stores xmm0–xmm15 and the scratch
  GPRs (aarch64 q0–q7, x1–x16) into the dead stack they scan; with the same mutant the signing
  group finds 12 words of k again.

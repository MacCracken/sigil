# RSA verify's banked lane accepted forged signatures — v1.5 fixed in 3.12.3, PSS and sign residuals open

**Status:** 🟡 **PARTIALLY RESOLVED in 3.12.3.** The PKCS#1 v1.5 verify bypass is
closed. Two residuals remain banked and still carry the 63-lane ceiling — PSS
verify and the two sign digest wrappers — because localising them regressed
tests for reasons not yet understood (see *Residuals*).
**Placement:** 3.12.3 for the v1.5 half. Residuals unpinned — 3.x line, security.
**Discovered:** 2026-08-08 by agnosai, chasing a *different* (benign) compiler
note during its Rust→Cyrius port.
**Severity:** **Critical** — authentication bypass for any consumer verifying
RSA signatures from more than 63 lifetime threads.
**Affects:** 3.9.7 (when banking landed) through 3.12.2. Fixed for v1.5 in 3.12.3.

## Summary

`rsa_pkcs1v15_verify_sha256` could **return 1 for an invalid signature**. Not a
corrupted-scratch DoS — a genuine accept.

`_rsa_pkcs1v15_check` ended with both operands of its decision in the same
lane-indexed **file-scope** global:

```
var bk   = cbank();
var rem  = &_rsa_em + bk * 512;          # recovered EM, from the caller's signature
var rexp = &_rsa_expected + bk * 512;    # expected EM, from the caller's digest
...
return ct_eq_bytes(rem, rexp, n_len);
```

A colliding thread that left a *consistent* valid pair there made the next
thread's compare succeed on bytes that were never its own. Nothing downstream
caught it: `ct_eq_bytes` (`lib/ct.cyr`) is a plain OR-accumulating XOR with no
structural gate, and `_rsa_recover_em` performs **no** PKCS#1 structural
validation — no `00 01` header, no `FF` padding run, no `00` separator. That one
comparison was the entire decision.

## Why collisions are structural, not a load threshold

`crypto_scratch.cyr`'s `cbank()`:

```
var n = atomic_fetch_add(&_crypto_next_bank, 1);
var bank = (n % (SIGIL_CRYPTO_BANKS - 1)) + 1;   # 63 lanes
```

`_crypto_next_bank` has **no decrement anywhere** — a lane is claimed on a
thread's first `cbank()` and held for the thread's life. The bound is therefore
**63 lifetime crypto-touching threads**, not 63 concurrent ones. A server that
creates and retires threads crosses it while never running more than a handful
of verifications at once.

## Reproduction

Reported from agnosai, whose sandhi pool is 100 OS workers over 63 lanes.
RSA-2048, `openssl`-generated key and signature (`openssl dgst -sha256 -verify`
→ `Verified OK`). Forged signature = the valid one with **one byte flipped**, so
the digest — and therefore `_rsa_expected` — is byte-identical, leaving
`_rsa_em` the only discriminator. 100 threads, natural `cbank()` assignment,
8000 iterations each:

```
sanity valid=1   sanity forged=0        (single-threaded)
false_accepts (forged -> 1) = 888     of 400,000    <-- ~1 in 450
false_rejects (valid  -> 0) = 281,965 of 400,000    <-- 70% of legitimate auth
```

Per-thread `cbank()` values printed showed the wrap directly: bank 1 at thread
index 0 **and** 64. Reproduced independently three times by reviewers each
trying to *refute* it: **888 / 1674 / 314**.

### ⚠ Trap for anyone re-testing

Pinning **every** thread to one lane shows `false_accepts = 0` with near-total
false rejects, which reads as fail-closed. It is not — extreme contention
corrupts the lane so continuously that no clean snapshot survives to match
against. The bypass lives in the **low-multiplicity** regime that a real pool
produces.

## Root cause: quirk #1 is stale

Banking existed because `CLAUDE.md` quirk #1 states *"function-scope `var X[N]`
arrays are static globals"*. **That was verified under cyrius pin 6.3.5 and is
false under 6.5.11** for any array inside the per-fn stack budget:

- Non-tail recursion yields four distinct frames **576 B apart**.
- Two threads land **~2 MB apart** — one thread stack.
- The budget is **122,880 bytes** per function, counted cumulatively
  (`cyrius/src/frontend/parse_decl.cyr:89`). Exceeding it makes the compiler
  emit `note: oversized array local kept in shared global (not per-thread)` —
  which is the signal that a local really did become shared.

⚠ A first probe of this was **invalid**: `return nest(depth-1)` is a tail call
and the frame is reused, so every depth reported the same address. Use non-tail
recursion.

**Every other use of quirk #1 in this tree should be re-checked against 6.5.11.**

## Fix (3.12.3)

Moved the v1.5 verify workspace to function-scope locals — per-call, therefore
per-thread, with no lane arithmetic, no wrap, and no ceiling on concurrent
callers:

| function | buffers | cost | % of budget |
|---|---|---|---|
| `_rsa_recover_em` | n / s / m | 1,536 B | 1.3% |
| `_rsa_pkcs1v15_check` | em / expected | 1,024 B | 0.8% |
| `rsa_pkcs1v15_verify_sha256/384` | digest + DigestInfo | 88 B | 0.07% |

`_rsa_n`, `_rsa_s`, `_rsa_m`, `_rsa_expected` are deleted.

**Why this closes the bypass even with residuals still banked:** the accept
required **both** compare operands to be shared. Both are now private, so a
foreign write can no longer plant a *matching* pair; corrupting anything else
yields a mismatch — fail-closed.

64/64 suites pass, `rsa.tcyr` 38/38 (baseline confirmed 38/38 before the change,
so the regressions below were genuinely introduced and genuinely backed out).

## Residuals — still banked, still 63-lane-capped

Both were attempted and **reverted**, because they regressed tests for reasons
not yet understood, and a half-understood change to a crypto path is worse than
a documented one:

1. **`_rsa_em` in `_rsa_pss_verify`.** Localising `rem` exactly as
   `_rsa_pkcs1v15_check`'s was localised fails **all four** PSS tests (valid PSS
   SHA-256/384 rejected, both roundtrips) with the surrounding logic unchanged
   and the v1.5 path green. Ruled out: zero-initialisation (memset makes no
   difference), `cbank()` call ordering, and callee-clobbers-caller (a probe
   passing a caller's 512 B array into a callee holding 1,536 B of its own
   showed zero corruption). **PSS therefore still carries the ceiling** — and
   `tls_native_hs13.cyr` routes TLS 1.3 CertificateVerify through it.
2. **`_rsa_hash` / `_rsa_di` in the two sign wrappers.** Localising all four
   digest wrappers broke the sign KATs (`SHA-256/384 signature matches Python
   KAT`, both roundtrips). Localising only the two **verify** wrappers is green
   and is what shipped.

Both are worth a proper diagnosis; neither is a bypass on its own.

### ⚠ 3. The bignum engine — measured, and it is why the consumer workaround stays

**Verified end to end against 3.12.3**, by staging the new `dist/sigil.cyr` into
agnosai and removing its mutex, two threads pinned to one lane, 2,000
verifications each:

| | result |
|---|---|
| forged signatures accepted | **0** ✅ the bypass is closed |
| valid signatures verified | **1 of 2,000** ❌ |
| valid signatures rejected | **1,999 of 2,000** |

So 3.12.3 converts a **fail-open auth bypass** into a **fail-closed denial of
service** — a real improvement in kind, and not yet a fix.

The cause is not in `rsa.cyr` at all: `_rsa_recover_em` calls
`bn_mont_modexp_pub`, and the bignum engine's scratch (`_bn_mont_t/_r2/_r2src/
_base/_res/_tmp/_one`, `_bn_exp_*`, `_bn_inv_*`) is **still file-scope and
lane-banked**. Two threads sharing a lane corrupt each other's modexp, so the
recovered EM is wrong and the compare rightly rejects.

**Consequence for consumers: localising the RSA workspace is necessary but not
sufficient.** agnosai therefore keeps its serialising mutex, and this issue
stays open until the bignum engine is per-thread too. That is the larger piece
of work — the engine is shared by every asymmetric primitive in the library, so
fixing it there fixes RSA, PSS, ECDSA and Ed25519 at once, and is very likely
the right place to fix it rather than module by module.

### 4. `bn_mod` — measured against 3.12.4, still shared

3.12.4 localised `_bn_mont_*` and asked consumers to re-run the agnosai staging
before dropping their mutex. Re-run, same harness, two threads pinned to lane 1
with `crypto_bank_set(1)`, 2,000 verifications each:

| sigil | valid verified (of 2,000) | forged accepted |
|---|---|---|
| 3.12.2 | 1 | **888** |
| 3.12.3 | 1 | 0 |
| **3.12.4** | **712** | 0 |

Substantial progress — 99.95% failure down to 64% — but **not closed**, so
**agnosai's mutex stays**.

The remaining shared state is `bn_mod` (`src/bignum.cyr:313-317`):

```
fn bn_mod(rem, x, x_limbs, modulus, m_limbs): i64 {
    var bk = cbank();
    var modrem = &_bn_modrem + bk * 520;   # this thread's lane (PUBLIC)
    var modn1  = &_bn_modn1  + bk * 520;
```

`bn_mont_modexp_pub` calls `bn_mod` at `:661` and `:740` for the R² setup, so
the public verify path still reaches a banked lane. Both buffers are 520 B —
1,040 B against the 122,880 B frame budget, so localising them is the same
one-line change as the rest.

⚠ **One caveat that makes this more than a copy-paste.** `bn_mod` is also called
on **secret** operands by the CRT sign path (`rsa.cyr:538`, `:539`, `:547`), and
`rsa.cyr:601` currently scrubs the shared lane with
`memset(&_bn_modrem + bk * 520, 0, 520)`. Moving the buffers to stack locals
makes that scrub a no-op on a dead global and leaves the secret residue
unscrubbed on the stack. The local must therefore zero itself before returning —
which is strictly better, since it scrubs only this call's data rather than a
whole lane — and `rsa.cyr:601` should then be deleted rather than left pointing
at nothing.

**On the harness.** 3.12.4 records that three attempts failed to create a
collision because the workers landed on lanes 0 and 1. Forcing it is the trick:
have *both* threads call `cbank()` and then `crypto_bank_set(1)` as their first
act, which puts them on one lane deterministically instead of waiting for the
counter to wrap. `agnosai/tests/server_auth_lane_race.tcyr` does exactly that
and is mutation-verified.

## Wider scope, not addressed here

A brace-depth scan finds **62 file-scope banked globals**. Beyond RSA verify:

- **The bignum engine is shared** — `_bn_mont_*`, `_bn_exp_*`, `_bn_inv_*`. Two
  aliased threads corrupt each other even running *different* primitives.
- **PSS / ECDSA / Ed25519** — `_pss_*`, `_mgf_*`. `tls_native_hs13.cyr` routes
  TLS 1.3 peer authentication through these.
- **Sign / blind / CRT** — `_rsa_sign_*`, `_rsa_blind_*`, `_rsa_crt_*`. Inferred
  from reading, not probed: `_rsa_scrub_sign_lanes` wipes the shared lane on
  return, which would zero an aliased thread's in-flight secret residue
  mid-sign; and the Bellcore verify-after-sign guard compares `schk` to `sm`
  with both operands in the same shared lane — the same "both operands in one
  shared object" shape as the bug above.

**At minimum, `cbank()` should fail closed** rather than silently aliasing past
lane 63: a consumer cannot currently detect that it has crossed the line.

## Consumer-side workaround (agnosai, to be removed)

agnosai serialised its verify call behind a process-global mutex
(`_agnosai_auth_rsa_verify_locked`, `src/server/auth.cyr`), pinned by
`tests/server_auth_lane_race.tcyr` — mutation-verified: without the lock a valid
signature verifies 0 of 2000. Cost ~0.85 ms/verify under contention. It is
deleted once agnosai vendors 3.12.3.

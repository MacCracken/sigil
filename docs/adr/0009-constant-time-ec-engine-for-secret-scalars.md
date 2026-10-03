# 0009 — A separate constant-time engine for every secret EC scalar

**Status**: Accepted
**Date**: 2026-10-02

> Decided in the 3.13.8 cycle. The user decided on 2026-10-02 that sigil gains
> constant-time ECDH on P-256 / P-384 after cyrius 6.6.14 ships, for the cyrius
> 6.6.15 refold (native TLS 1.2 ECDHE on secp256r1 / secp384r1). The premise check
> for that work found that ECDSA signing ran its secret nonce through variable-time
> arithmetic, so the same engine fixes signing.

## Context

cyrius's native TLS client did ECDHE on X25519 only. Since cyrius 6.6.14 lists a
P-256 / P-384 client certificate's curve in `supported_groups` (OpenSSL requires it),
a TLS 1.2 server that ranks that curve first fails the handshake, and an OpenSSL 1.2
server with an ECDSA P-256 / P-384 certificate answers "no shared cipher". Real ECDHE
on those curves needs a scalar multiplication that is constant-time in the private
scalar.

sigil had none. `ecdsa_p256.cyr` / `ecdsa_p384.cyr` are verify modules: their field
arithmetic (`fp_p256_*`, `fn_p256_*`, `u256_*` / `u384_*`, the Solinas and long-division
reductions, the Karatsuba multiply) branches on operand values — conditional final
subtracts, carry fix-ups written as `if`, early-exit compares and zero tests — and
`pt_add` / `pt_double` branch on the point at infinity and on P == ±Q. The ECDSA signer
ran its nonce k through that arithmetic (a fixed-length scalar since 3.13.0 and a
blinded ladder input since 3.13.1 removed the coarse leaks, not the arithmetic ones),
and computed k^-1 and r·d on the variable-time mod-n code. The 3.7.0 and 3.7.17 audits
recorded this as an accepted INFO residual; a 400-sample fixed-vs-random Welch t-test
on the 3.13.7 entry measures |t| = 6.3 (CHANGELOG [3.13.8]).

## Decision

**Every operation on a secret elliptic-curve scalar runs on one constant-time engine,
`src/ec_ct.cyr`; the verify modules stay variable-time and are documented as public-
input only.** The engine is generic over the limb count, so one implementation serves
the P-256 and P-384 fields and both scalar fields:

- Montgomery arithmetic (CIOS multiply, branch-free add / sub / conditional subtract),
  carries and borrows as bit arithmetic on the operands' top bits, never a comparison;
- homogeneous projective points with the complete Renes–Costello–Batina (2016)
  formulas for a = -3 (Algorithms 4 and 6) — one formula for every input, so no
  operand-dependent special case exists to branch on;
- a fixed 4-bit window over every window of the scalar with a full-table masked
  lookup, for both fixed-base (k·G, d·G) and variable-base (d·Q) multiplication;
- Fermat inversion with the public exponents p - 2 and n - 2.

ECDH (`src/ecdh.cyr`) and ECDSA signing (`_ecs_sign_core` in `src/ecdsa_sign.cyr`) are
its consumers; `pt_scalarmul_secret` / `pt384_scalarmul_secret` keep their names and
signatures but now run on it (moved into `src/ec_ct.cyr`). The fixed-length k_hat
(3.13.0) and the blinded ladder input (3.13.1) are removed with the ladder they
mitigated. Key generation takes caller-supplied randomness and reduces len(n) + 64
bits (FIPS 186-5 A.2.1), so it has no rejection loop and no branch on the random value.

## Consequences

- **Positive** — ECDH exists for the TLS refold, and signing is constant-time end to
  end. The engine is also faster than the variable-time path it replaced for secrets:
  ECDSA P-256 sign 13.3 → 2.7 ms, P-384 30.1 → 7.9 ms (x86_64, same host, A/B; `benches/history.csv`). Its
  constant-time property is checked mechanically: every conditional branch in the
  compiled engine (x86_64 and aarch64) maps to a loop bound, a public exponent bit or a
  public verdict.
- **Negative** — two field implementations per curve now exist, and a change to curve
  handling has to consider both. Nothing on the verify path may be handed a secret;
  `docs/architecture/004-secret-ec-scalars-run-on-ec-ct.md` is the rule.
- **Neutral** — keygen and signing pay a full variable-base cost for k·G / d·G (the
  table of 15 multiples of G is rebuilt per call). A precomputed constant-time comb for
  G would cut them roughly 4x at the cost of ~98 KB (P-256) + ~221 KB (P-384) of
  lazily-built tables; left for the maintainer (roadmap).

## Alternatives considered

- **Make the verify arithmetic constant-time.** One implementation, but every verify
  pays for constant-time reductions it does not need, and the verify path's comb and
  window tables index by the (public) scalar — the code would still need a separate
  secret path for the scalar multiplication. Rejected: slower verify for no benefit.
- **Keep the Montgomery ladder, make only its field operations constant-time.** The
  ladder still needed k_hat to dodge the point at infinity, and `pt_add` still branches
  on P == ±Q. Complete formulas remove that class of case analysis outright.
- **Solinas reduction instead of Montgomery.** Faster per multiply in principle, but a
  separate branch-free reduction per prime (and none for the scalar fields, whose
  orders are not Solinas primes); generic Montgomery covers all four moduli with one
  audited routine and already runs 3x faster than the verify-side `fp_p256_mul`.
- **Rejection sampling for keygen (FIPS 186-5 A.2.2).** Needs a retry with fresh
  randomness, which a caller-supplied buffer cannot provide, and branches on the
  candidate. The extra-bits method has neither and a bias below 2^-64.

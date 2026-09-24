# ECDSA signing: one-bit ladder timing residual, and unbanked `k_hat` scratch

**Filed:** 2026-09-23 (3.13.0) · **Severity:** MEDIUM · **Status:** open

**Where:** `src/ecdsa_p256.cyr` (~1246, `t2` ~1295, `kh` ~1338), `src/ecdsa_p384.cyr` (`t2` ~1110,
`kh` ~1153). Left after the 3.13.0 fixed-length-ladder fix.

1. **One-bit timing leak (LadderLeak class).** G enters the ladder with Z = 1, so iteration 2's work
   depends on bit 255 (P-384: 383) of k_hat — `pt_add(2G, G) + pt_double(2G)` vs
   `pt_add(G, 2G) + pt_double(G)`, and field ops on Z = 1 are cheaper. Measured ~260 ns
   (32.8 vs 33.07 µs per add + double, stable over 5 rounds) against a ~10 ms ladder. For
   k ≥ 2^256 − n that bit tracks MSB(k); LadderLeak (Aranha et al. 2020) recovered keys from under
   one leaked nonce bit. Direction: randomise G's projective coordinates (X·λ², Y·λ³, Z·λ) before
   the ladder, or at least use a fixed non-unit Z.
2. **`kh[40]` / `t2[40]` (P-384: `[56]`) are the only unbanked secret arrays on the concurrent sign
   path.** Correct today (array locals are per-thread stack under the 6.6.6 pin), but
   `CYRIUS_STACK_ARRAYS=0` makes them shared `.bss`, and with RFC 6979 a race-corrupted R plus a
   correct signature on the same message recovers d. Direction: bank them like the rest of the sign
   path, or record the choice.

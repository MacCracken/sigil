# Sigil Roadmap

Forward-looking work only. For completed items and version history, see
[CHANGELOG.md](../../CHANGELOG.md).

## 2.3.0 — Fixed-base signing performance

- [ ] **Precomputed base-point table for `_ed_B`**. Fixed-base
      scalarmult via 4-bit windowed comb: 64 additions, no
      doublings. Target: `ed25519_keypair` / `ed25519_sign`
      ≈ 5.7ms → ~1.0ms. Binary cost: ~16KB of precomputed point
      data. Must remain constant-time: use `ge_cmov` across all 16
      window entries so memory-access pattern does not depend on
      the window value.
- [ ] Separate `ge_scalarmult_base` fast path from the generic
      `ge_scalarmult`; `ge_scalarmult` (variable base, used by
      `ed25519_verify`) retains the CT loop from 2.2.1.
- [ ] Unit tests for `ge_cmov` bit-select cases (currently covered
      only transitively by RFC 8032 vector 1).

## 2.4.0 — Coverage & correctness

- [ ] Ed25519 RFC 8032 test vectors 2–5 (currently only vector 1).
- [ ] `fp_inv` regression tests — direct `fp_inv(a) * a ≡ 1 (mod p)`
      check on a spread of inputs (the addition chain is currently
      validated only through `ge_to_bytes`).
- [ ] Decision on the stubbed `SigilVerifier` cache fields
      (`sv_set_cache_enabled`, `sv_clear_cache`) — wire up or remove.
      Flagged as breaking in 2.1.2 CHANGELOG.
- [ ] Expanded fuzz corpus / longer fuzz runs in CI.

## 2.5.0 — AGNOS integration

- [ ] Replace TPM seal/unseal stubs with real `agnosys` TPM syscalls
      when those land.
- [ ] IMA measurement integration via `agnosys`.
- [ ] Secure-boot state detection at startup.
- [ ] Trust-store JSON load (currently save-only).
- [ ] Audit-log JSON-lines load (currently write-only).

## Future

- **PQC**: ML-DSA-65 signing when Cyrius implementations mature.
- **Hybrid Ed25519 + ML-DSA-65 dual signatures** for transitional
  trust chains.
- **Certificate pinning** integration via `agnosys certpin`.
- **Parallel batch verification** when Cyrius threading matures.
- **Lookup-resistant table access** for the fixed-base comb (scatter
  across all rows) if cache-timing becomes a documented concern.

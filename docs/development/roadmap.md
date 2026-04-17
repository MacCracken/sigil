# Sigil Roadmap

Forward-looking work only. For completed items and version history, see
[CHANGELOG.md](../../CHANGELOG.md).

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
- **Scatter-store for the fixed-base comb**: distribute the 128-byte
  point entries across cache lines so a cache-timing attacker on the
  same host cannot recover the nibble selected per window. Not needed
  for AGNOS's single-tenant role; document as a hardening option if
  the threat model changes.

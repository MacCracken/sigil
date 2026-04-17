# Sigil Roadmap

Forward-looking work only. For completed items and version history, see
[CHANGELOG.md](../../CHANGELOG.md).

## 2.7.0 — Load paths for trust-store / audit-log

- [ ] **Trust-store JSON load** — symmetrical to the existing
      `sv_save_trust_store`. Parse the persisted JSON back into a
      `SigilVerifier`'s trust-store map, restoring artifact metadata
      and signatures.
- [ ] **Audit-log JSON-lines load** — symmetrical to the existing
      JSON-lines writer. Stream a rotated log file back into an
      `AuditLog` for forensic replay.
- [ ] Round-trip tests for both paths (write → load → deep-equal).

## 2.8.0 — Certificate pinning via agnosys

- [ ] Wrap `certpin_verify_pin`, `certpin_compute_spki_pin`,
      `certpin_find_entry` into a sigil-facing API.
- [ ] Add a `sigil_cert_pin_check(host, actual_pin, pin_set)` entry
      point. Integrates with the SigilVerifier key-pin machinery.
- [ ] Fixture pin sets for tests (no network required).

## Future

- **PQC**: ML-DSA-65 signing when Cyrius implementations mature.
- **Hybrid Ed25519 + ML-DSA-65 dual signatures** for transitional
  trust chains.
- **Parallel batch verification** when Cyrius threading matures.
- **Scatter-store for the fixed-base comb**: distribute the 128-byte
  point entries across cache lines so a cache-timing attacker on the
  same host cannot recover the nibble selected per window. Not needed
  for AGNOS's single-tenant role; document as a hardening option if
  the threat model changes.

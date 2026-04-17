# Sigil Roadmap

Forward-looking work only. For completed items and version history, see
[CHANGELOG.md](../../CHANGELOG.md).

## 2.6.0 — Tier 2 dead-field cleanup (breaking)

Accessors still shipping for `TrustedArtifact` / `IntegrityPolicy` /
`IntegrityMeasurement` / `IntegrityReport` / `IntegritySnapshot` /
`TrustedArtifact` fields that have **no read path**: the field is
present in the struct, a getter/setter exists, nothing uses either.
Removing the field shrinks the struct — a breaking layout change —
so this is batched into a dedicated minor rather than sneaked into
2.5.0's cleanup.

- [ ] Drop `artifact_signature_len`, `artifact_sig_alg`/`set_`,
      `artifact_verified_at`/`set_`, `artifact_metadata`/`set_`
      and their backing fields (`TrustedArtifact` shrinks 80 → 40
      bytes — nearly halves). Keep the ones that still have
      callers (`artifact_set_verified_at` has one, at
      `sv_sign_artifact`).
- [ ] Drop `ireport_checked_at`, `ireport_summary`,
      `isnap_exported_at`, `meas_at`, `meas_error`, `meas_actual`,
      `ipolicy_count`, `ipolicy_measurements`, `pcr_index`,
      `attest_passed`, `attest_quote_sig`/`set_`,
      `vresult_verified_at`, `key_id_from_public_hex`.
- [ ] Consumer-repo audit pass (`daimon`, `kavach`, `ark`,
      `aegis`, `phylax`, `mela`) before each removal, same as the
      2.4.0 / 2.5.0 cache-stub precedent.

## 2.5.1 — Load paths for trust-store / audit-log

- [ ] **Trust-store JSON load** — symmetrical to the existing
      `sv_save_trust_store`. Parse the persisted JSON back into a
      `SigilVerifier`'s trust-store map, restoring artifact metadata
      and signatures.
- [ ] **Audit-log JSON-lines load** — symmetrical to the existing
      JSON-lines writer. Stream a rotated log file back into an
      `AuditLog` for forensic replay.
- [ ] Round-trip tests for both paths (write → load → deep-equal).

## 2.6.0 — Certificate pinning via agnosys

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

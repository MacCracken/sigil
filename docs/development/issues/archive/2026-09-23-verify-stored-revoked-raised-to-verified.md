# `sv_verify_artifact` lets a valid signature lift a stored `TRUST_REVOKED` entry to Verified

**Filed:** 2026-09-23 (3.13.0) · **Severity:** MEDIUM · **Status:** resolved (3.13.1)

**Where:** `src/verify.cyr`, `sv_verify_artifact_into` (~470).

An artifact whose trust-store entry is `TRUST_REVOKED` — with no revocation-list entry — still
passes `sv_verify_artifact` when it carries a valid signature: the signature branch raises the rank
from Revoked (0) to Verified (3). 3.13.0 closed this only for the boot chain (an explicit
stored-Revoked check in `_sv_boot_component`).

**Fix direction (not applied):** never raise a Revoked entry in `sv_verify_artifact_into`. It
changes `sv_verify_artifact` semantics, which is why it was left open.

## Resolution (3.13.1)

`sv_verify_artifact_into` never lifts a stored Revoked entry: a valid signature leaves it
Revoked, the revocation check fails with "Revoked in trust store", and the key-pin /
allowed-type downgrades no longer raise Revoked to Unverified. Test group in
`tests/tcyr/verify_hardening.tcyr`.

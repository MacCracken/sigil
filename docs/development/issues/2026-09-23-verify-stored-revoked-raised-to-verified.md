# `sv_verify_artifact` lets a valid signature lift a stored `TRUST_REVOKED` entry to Verified

**Filed:** 2026-09-23 (3.13.0) · **Severity:** MEDIUM · **Status:** open

**Where:** `src/verify.cyr`, `sv_verify_artifact_into` (~470).

An artifact whose trust-store entry is `TRUST_REVOKED` — with no revocation-list entry — still
passes `sv_verify_artifact` when it carries a valid signature: the signature branch raises the rank
from Revoked (0) to Verified (3). 3.13.0 closed this only for the boot chain (an explicit
stored-Revoked check in `_sv_boot_component`).

**Fix direction (not applied):** never raise a Revoked entry in `sv_verify_artifact_into`. It
changes `sv_verify_artifact` semantics, which is why it was left open.

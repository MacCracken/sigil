# LOW findings recorded during the 3.13.0 work (not fixed)

**Filed:** 2026-09-23 (3.13.0) · **Severity:** LOW · **Status:** resolved (3.13.1)

Line numbers are approximate; re-locate by content.

## TEE (sgx/tdx/sev_snp)
- L1 TDX P-384 AK binding: comment (tdx.cyr ~29-33) says the 64-byte report_data slot cannot hold a 48-byte SHA-384 digest (it can); att_key_type 3 compares only the first 32 bytes of SHA-384 and requires 32..63 zero. Only a synthesized P-384 fixture exists. Needs checking against Intel's TDX DCAP quote spec. QUESTION, not a code change.
- L2 SEV-SNP parser accepts only report VERSION 2; later AMD firmware may emit newer versions (unverified).
- L3 SEV-SNP TCB values are raw u64 bit patterns in an i64: a byte >= 0x80 makes the value negative, so a signed TCB comparison in a consumer is wrong.
- L4 TDX/SGX verify on an allocated-but-never-parsed struct dereferences near-null pointers (SNP returns 0 safely).
- L5 TDX/SGX parsers accept trailing bytes after the signature section (they reject slack inside it).
- L6 TEE *_alloc fns do not check alloc's return before memset.
- L7 TDX has no accessors for TEE_TCB_SVN / SEAMATTRIBUTES / MROWNERCONFIG (offsets defined); TEE_TCB_SVN is what a TCB policy check needs.

## verify / audit / trust / policy
- L8 sv_stats / sv_compliance_report / sv_trust_level_for read stored trust levels only; the revocation list is not reflected. Verify-path lookups ignore revoked_after (stricter outcome).
- L9 alog_save, sv_save_trust_store and keyring_save ignore file_write results — a failed or short write still returns success.
- L10 audit_revocation_added drops the `reason` sv_add_revocation passes.
- L11 sv_load_trust_store restores trust levels (SystemCore included) as-is from an unsigned file; the store file itself is not integrity-protected.
- L12 key rotation: keyring_rotate_key builds the new version with defaults (role Publisher, all artifact types, no publisher/issuer info), so a type-restricted key becomes unrestricted unless re-set; the verifier uses only keyring_get_current, so artifacts signed by the old version fail during the overlap window.
- L13 _rj_parse_string (policy.cyr) reads one byte past `end` when a string ends in a backslash as the last input byte.
- L14 rl_merge treats entries as duplicates by key_id + content_hash only, ignoring revoked_after — an unconditional revocation can be skipped when a conditional one exists (affects only the _at queries).
- L15 The JSON parsers in policy.cyr share module globals (not safe for concurrent callers).

## EC / Ed25519 / hashes / AEAD / seal
- L16 ECDSA sign: the lane-wipe routines skip the field-inverse / reduction scratch (_p256fi_*, _p384_inv_*, _p256_sol_t, _p384_sol_t) as "verify-only", but signing runs through them (k·G to affine, every field multiply) — secret-derived residue left behind.
- L17 ecdsa_p256_verify_der accepts non-canonical DER (INTEGERs bounded by buffer not SEQUENCE length, trailing bytes, redundant leading zeros, high-bit INTEGERs) — signature malleability; the verify result itself is correct.
- L18 sc_muladd drops a carry from the low 256 bits into limbs 5-7: when limb 4 is all ones (~2^-67 per signature) S is wrong by 2^320 — an invalid signature that verify rejects, not a key leak.
- L19 one-shot sha512() does not wipe its context: when ed25519_keypair / ed25519_sign hash the seed with it, the seed block and expanded secret key (and sha512_transform's W) stay in scratch.
- L20 seal.cyr `_seal_info` is one module-level alloc'd buffer shared by every call, with a non-atomic init flag — concurrent key derivations race (comment calls it stack-allocated).
- L21 Lazy table init for AES, BLAKE2b, SHA-512, Ed25519 is a plain flag; only sv_verify_batch pre-warms (Ed25519/SHA-256/SHA-512) — a first-call race can read a half-filled table. (AES S-box table lookups are cache-timing-visible; accepted at 3.5.7.)
- L22 integrity.cyr: the verifier callback is stored but never invoked; policy `enforce` / `check_interval` are never acted on; iv_verify_all writes VERIFIED back to the policy's measurement but never MISMATCH / FILE_NOT_FOUND (a tampered file can still read VERIFIED in meas_status); ipolicy_remove leaks the removed entry.

## trust-stack / platform
- L23 ima_core policy_loaded is "the policy file exists"; on default kernel configs the kernel removes that file after a policy loads, so the flag may read backwards (needs confirming on an IMA host).
- L24 tpm_seal's staged plaintext is unlinked but never overwritten, so on a non-tmpfs output_dir the secret can persist in freed blocks.
- L25 luks_open does not detach its loop device when `cryptsetup open` fails (luks_format does).
- L26 On Windows (PE) a CREATE_NEW with O_EXCL|O_NOFOLLOW resolves a final reparse point rather than refusing it (cyrius 6.6.6 notes), so luks_write_keyfile's symlink refusal is weaker there; LUKS itself is unreachable on Windows (no cryptsetup / fork+exec).
- L27 src/sysinfo.cyr's `uname_release` duplicates lib/sys.cyr's (6.6.6 warns "duplicate fn ... last definition wins"); same semantics. Tracked by the existing "Retire the interim src/sysinfo.cyr" backlog item.
- L28 The stdlib's full-write loop `_io_write_full` is module-private, so sigil carries its own `agnosys_write_all`; a public fd-level write-all in lib/io.cyr would let it go.

## Resolution (3.13.1)

- **Fixed:** L4, L5, L6, L7 (TEE parse / verify / alloc / accessors), L8, L9 (`alog_save`,
  `sv_save_trust_store`, `keyring_save`), L10, L11 (group- / world-writable store refused),
  L12, L13, L14, L15 (parser state moved to a per-call context), L16, L17, L18, L19, L20,
  L21, L22, L24, L25, L27.
- **Documented as intended:** L1 (the type-3 AK binding layout, as the code applies it),
  L2 (report versions other than 2 fail closed until checked against AMD's ABI), L3 (compare
  TCB components per byte, unsigned), L26 (Windows reparse-point semantics; LUKS has no
  Windows path).
- **Not a defect:** L28 — `agnosys_write_all` stays; the stdlib's `_io_write_full` is private.
- **Still open:** L23 → `docs/development/issues/2026-09-23-ima-policy-loaded-needs-ima-host.md`.

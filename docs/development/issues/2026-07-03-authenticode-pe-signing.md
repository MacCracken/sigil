# Native UEFI Authenticode PE signing — PKCS#7/CMS SignedData + EFI signature-list generation

**Filed:** 2026-07-03
**Driver:** gnoboot (sovereign UEFI bootloader) needs its `BOOTX64.EFI`
Authenticode-signed to run under UEFI Secure Boot; the sovereign install chain
(agnova) should provision AGNOS-owned PK/KEK/db. Pairs with the cyrius toolchain
proposal `cyrius/docs/development/proposals/2026-07-03-uefi-secure-boot-signing.md`
(the `cyrius sign-efi` driver surface) — **sigil is the crypto home that proposal
depends on.**
**Severity:** Sovereignty gap. sigil already has the *primitives*, but the only
"secure boot signing" it exposes today (`secureboot_sign_module`) **shells out to
external Linux tooling** and signs the wrong artifact class — so a sovereign UEFI
boot binary can only be signed by non-sovereign external tools (`sbsign`).
**Not a release blocker:** Secure Boot is post-v1.0 in gnoboot's roadmap.

**Status (2026-07-03): P1 + P2 RESOLVED in sigil 3.10.0.** `src/authenticode.cyr`
lands the DER encoder + `authenticode_pe_hash` (P1) and `authenticode_pkcs7_sign` +
`authenticode_pe_sign` (P2). Validated end-to-end against openssl on a real gnoboot
`BOOTX64.EFI` (`openssl pkcs7 -print_certs` / `asn1parse` / `dgst -sha256 -verify` →
`Verified OK`); regression-locked by `tests/tcyr/authenticode.tcyr`. The remaining
firmware-interop gate (boot the signed EFI under OVMF Secure Boot with AGNOS-owned
PK/KEK/db enrolled) needs key-enrollment tooling not present on this host. **P3**
(`.esl`/`.auth` enrollment) and **P4** (`authenticode_pe_verify`) are still open.

## What sigil ALREADY has (reuse, do NOT rebuild)

This issue is deliberately scoped *narrow* because sigil is already a deep crypto
library — the mistake to avoid is re-requesting what exists:

- **`rsa.cyr`** — native RSA PKCS#1 v1.5 **sign** over SHA-256/384
  (`rsa_pkcs1v15_sign_sha256`, shipped 3.6.4, blinded + CRT) **and** verify, plus
  PSS, plus `rsa_privkey_from_der` / `rsa_pubkey_from_der`. **RSA signing is done.**
- **`x509.cyr`** — X.509 cert struct + DER walk/skip (`der_walk`, `der_skip`,
  `x509_cert_*`). X.509 parse + the DER substrate exist (`der_` across 14 modules).
- **`sha256.cyr`** (+ SHA-NI bank), **`pem.cyr`**, **`bignum.cyr`/`bigint_ext.cyr`**,
  **`ecdsa_p256.cyr`**, even **`mldsa.cyr`** (ML-DSA post-quantum). Rich.

## What's MISSING (the actual gap)

None of these exist anywhere in `src/` (grep: 0 files for pkcs7 / cms / authenticode
/ SpcIndirect / EFI_SIGNATURE_LIST):

1. **PKCS#7 / CMS `SignedData`** construction — the container UEFI Secure Boot
   requires around the signature. (DER-encode a `ContentInfo` → `SignedData` with
   one `SignerInfo`; reuse the existing DER + RSA-sign.)
2. **Authenticode** — the `SpcIndirectDataContent` content type + the **PE
   Authenticode hash** (SHA-256 over the image **skipping** the optional-header
   `CheckSum`, the Certificate-Table data-directory entry, and the attribute-cert
   data), then embedding the PKCS#7 blob in the PE **Attribute Certificate Table**
   (`WIN_CERTIFICATE`, `WIN_CERT_TYPE_PKCS_SIGNED_DATA`) and fixing the Security
   data-directory + PE size. This is the exact job `sbsign` does; it's the headline
   deliverable.
3. **EFI signature-list generation** — `EFI_SIGNATURE_LIST` (`.esl`) +
   `EFI_VARIABLE_AUTHENTICATION_2`-wrapped `.auth` for `PK` / `KEK` / `db`, so the
   sovereign installer can **enroll AGNOS-owned keys** on a machine (the job of
   efitools' `cert-to-efi-sig-list` + `sign-efi-sig-list`).

## Why the existing `secureboot*` modules don't cover it

`secureboot.cyr` is documented as *"a thin wrapper over agnosys secureboot_*
functions"*, and `secureboot_core.cyr::secureboot_sign_module` **execs `kmodsign` /
`sign-file`** (line ~411) — i.e. it signs **Linux kernel MODULES** via external
tools, a different artifact class from a **UEFI EFI application**, and it is
non-sovereign (shells to external binaries). `secureboot_detect_state` similarly
wraps `mokutil`. Useful for their purpose (module signing + SB-state policy on a
Linux host), but they are **not** UEFI Authenticode PE signing and cannot become
the sovereign boot-signing path.

## Proposed work (build on the existing primitives)

New module(s) — suggested `src/authenticode.cyr` (+ `src/pkcs7.cyr` if the CMS
surface warrants its own file), sitting on `rsa.cyr` + `x509.cyr` + `der_*` +
`sha256.cyr`:

- `pkcs7_signeddata_build(...)` — DER `SignedData` from (digest, signer cert, RSA key).
- `authenticode_pe_hash(pe, len, out32)` — the spec-correct PE hash.
- `authenticode_pe_sign(pe, len, key, cert, out_pe, out_len)` — hash → PKCS#7 →
  embed in the attribute-cert table → fixed-up signed PE. **(headline)**
- `authenticode_pe_verify(pe, len, trusted_certs)` — the inverse (also lets gnoboot
  verify the *kernel* it loads — the other trust half; RSA-verify already exists).
- `efi_sig_list_from_cert(cert, type)` + `efi_auth2_wrap(esl, key)` — enrollment.

## Phasing

- **P1 ✅ (sigil 3.10.0)** — DER encoder + `authenticode_pkcs7_sign` (SignedData) +
  `authenticode_pe_hash`. (Shipped as `authenticode_pkcs7_sign`, not the placeholder
  name `pkcs7_signeddata_build`.)
- **P2 ✅ (sigil 3.10.0)** — `authenticode_pe_sign` (attribute-cert-table embed).
  **Unblocks gnoboot** — openssl-validated; OVMF Secure Boot firmware-interop still
  pending key-enrollment tooling.
- **P3** — `efi_sig_list_*` enrollment artifacts (agnova self-provisioning).
- **P4 (optional)** — `authenticode_pe_verify` (gnoboot-verifies-kernel) + ECDSA-P256
  signer variant (sigil has `ecdsa_p256.cyr` already) for firmware that prefers it.

## Open decisions

- Module layout: fold into `secureboot*` (co-locate SB surface) or a fresh
  `authenticode`/`pki` module (keeps the Linux-module-signing wrapper separate from
  the native UEFI path). Recommend **separate** — different artifact class, native
  vs wrapper.
- RSA-2048 default vs ECDSA-P256 option (firmware support varies; RSA-2048 universal).
- Do P4 (verify) in the same arc? The RSA-verify + PE-hash code is shared with sign,
  so it's cheap to include and closes the full firmware→gnoboot→kernel chain.

## Non-goals

- No new signature *scheme* — UEFI firmware mandates X.509/RSA/PKCS#7/Authenticode.
- Not the Microsoft 3rd-party UEFI CA — self-managed AGNOS keys only.
- Production key *ownership* (who holds PK/KEK/db) is an AGNOS policy call, not sigil's.

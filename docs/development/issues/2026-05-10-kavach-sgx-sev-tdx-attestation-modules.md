# Sigil: kavach SGX / SEV / TDX backends need attestation + sealing surface

**Filed:** 2026-05-10
**Reporter:** kavach (AGNOS sandbox-execution framework, v3.1.1)
**Sigil version at time of report:** 2.9.0 (kavach's pinned tag; see
[`kavach/cyrius.cyml`](https://github.com/MacCracken/kavach/blob/main/cyrius.cyml))
**Severity:** **P1** — see "Severity rationale" below; the rating is
the reporter's ask. A sigil maintainer prioritising the 3.1 alloc-free
verify rewrite may legitimately re-rate to **P3** (enhancement, no
current forcing function — kavach SGX/SEV/TDX backends ship without
this surface today).
**Status:** open.

## Summary

Kavach's v3.0 port shipped three TEE-backed sandbox backends:

| Backend | Implementation today | Attestation today |
|---|---|---|
| `backend_sgx.cyr` | `gramine-sgx` shell-out + auto-generated Gramine manifest. Requires `/dev/sgx_enclave`. | **None.** Kavach builds the manifest and spawns the runtime; the enclave's resulting attestation report is never fetched or verified. `src/attestation.cyr` stores the report shape (`SgxAttestationReport`) but the verify path doesn't exist. |
| `backend_sev.cyr` | `qemu-system-x86_64` + SEV-SNP confidential-guest object. Requires `/dev/sev`. | **None.** |
| `backend_tdx.cyr` | `qemu-system-x86_64` + tdx-guest object. Requires `/dev/tdx_guest`. | **None.** |

Closing the attestation gap requires three pieces of sigil-side surface
that the 2.9.0 crypto pillar (`sha256`, `hmac`, `ed25519`, `aes_gcm`,
`verify`, `ct`) doesn't cover today:

1. **SGX quote-structure parser + IAS / DCAP cert-chain verifier**
   (Intel EPID-attested via Intel Attestation Service; or DCAP-attested
   via PCK certificate chains for newer SGX deployments). The quote
   format is the EAR (Enclave Attestation Result) shape — an emerging
   RATS standard wrapping a CBOR/COSE-signed quote with MRENCLAVE,
   MRSIGNER, ISVPRODID, ISVSVN, ATTRIBUTES, report data.
2. **SEV-SNP guest attestation parser** — VCEK / VLEK leaf cert chain,
   guest measurement, report data, IDBLOCK / IDAUTH info.
3. **TDX TD-quote parser** — TD report (MRTD, RTMR0..3, TD attributes)
   wrapped in a quote signed under the SGX quoting enclave (same chain
   as SGX from there on).

Sigil's existing `verify.cyr` / `ed25519.cyr` / `ct.cyr` / `sha256.cyr`
all compose into a verifier once the quote-shape parsers and the
Intel/AMD cert-chain primitives land. Suggested module shape (pick
whichever fits the 3.0 module-layout conventions):

```
sigil/src/sgx.cyr       — SgxQuote + ias_verify_cert_chain + sgx_quote_parse + sgx_quote_verify
sigil/src/sev_snp.cyr   — SevSnpReport + vcek_verify_cert_chain + snp_report_parse + snp_report_verify
sigil/src/tdx.cyr       — TdxQuote + tdx_td_report_parse + tdx_quote_verify (shares the SGX cert chain)
sigil/src/seal.cyr      — sgx_seal_key / sgx_unseal_key (key derivation against MRSIGNER + ISVSVN for SGX sealing)
```

## Severity rationale

The reporter (kavach) rates this **P1** because attestation is the
load-bearing primitive that turns kavach's TEE-tier scoring claim
("fortress" — base score 80+) from "trusts the runtime started" into
"verifies the guest's identity." Today the score is a claim about
the runtime's intent, not the runtime's identity.

The honest counter-case: **kavach ships fine without this today.**
The SGX/SEV/TDX backends start the runtime and execute through it;
the score reflects the runtime's capability tier; the attestation
gap is a tier-claim-vs-reality drift that downstream consumers can
work around by demanding attestation at their own layer. Plus sigil's
3.1 arc is currently scoped around alloc-free `sv_verify_artifact`
rewrite ([`sigil/docs/development/roadmap.md`](../roadmap.md) § "Road
to v3.1"), which is a real perf win for every downstream and shouldn't
be displaced. A sigil maintainer can legitimately re-rate to **P3**
(enhancement, defer to 3.2 or later) — the rating reflects
"kavach would like this", not "kavach cannot ship without it".

## What's structurally already present in sigil 2.9.0

The crypto primitives are all in place — only the format-specific
parsers and cert-chain helpers are missing:

| Primitive | Module | Used for |
|---|---|---|
| SHA-256 / SHA-512 | `src/sha256.cyr` / `src/sha512.cyr` | Quote body hash |
| HMAC-SHA256 | `src/hmac.cyr` | DICE / sealing key derivation |
| Ed25519 sign + verify | `src/ed25519.cyr` | (Not used for SGX/SEV/TDX directly — those use ECDSA P-256) |
| Constant-time compare | `src/ct.cyr` | Cert-chain comparisons |
| HKDF-SHA256 | `src/hkdf.cyr` (from the 2.9.x crypto pillar) | Sealed-key derivation |
| TPM / IMA / secureboot / integrity | `src/tpm.cyr` / `src/ima.cyr` / `src/secureboot.cyr` / `src/integrity.cyr` | Host-side attestation; SGX/SEV/TDX is the guest-side counterpart |

**Missing for SGX/SEV/TDX:** ECDSA P-256 verify (or P-384 for some
TDX paths), X.509 cert-chain parsing (Intel IAS root + intermediates;
AMD ARK/ASK/VCEK chain), the quote-format CBOR/COSE parsers. These
are the bulk of the new module surface; the crypto kernel is already
in tree.

## Downstream impact

- **kavach** — three "fortress"-tier backends ship without their
  defining property (identity verification of the guest). Today the
  hardening pass (ADR-005) addresses the runtime-host boundary;
  this issue addresses the runtime-guest boundary.
- **Future first-party consumers of TEE runtimes** — daimon (when
  orchestrating across TEE-attested nodes), AgnosAI (when running
  agent crews under attested confidential compute), shakti (when
  enforcing TEE-presence as a privilege-escalation guard) — all
  inherit the same gap.

## Suggested placement

Not v3.1 — that arc is the alloc-free verify rewrite and shouldn't be
displaced (real perf win for every downstream).

A reasonable v3.2-or-later scoping would be a dedicated **sigil 3.2
attestation-module sub-arc** that lands the three quote-format parsers
and the Intel/AMD cert-chain primitives in order:

1. **ECDSA P-256 verify** (and P-384 if needed for some TDX paths).
   Reuses the existing constant-time discipline from `ct.cyr`.
2. **X.509 cert-chain primitives.** Minimal — just enough to walk
   IAS root → intermediate → leaf, and ARK → ASK → VCEK. No general
   PKIX library needed.
3. **`sgx.cyr`** — quote parser + verifier composed against (1) + (2)
   + the existing sha256.
4. **`sev_snp.cyr`** — same composition pattern as SGX.
5. **`tdx.cyr`** — shares the cert chain with SGX (TDX quotes are
   ultimately signed by the SGX quoting enclave); smaller delta once
   SGX lands.
6. **`seal.cyr`** — SGX sealing primitives (key derivation against
   MRSIGNER + ISVSVN). Probably last; sealing is rarely the gating
   feature for downstream — quote verify is.

Each step is independently shippable; each unblocks part of kavach's
TEE-backend roadmap and is also useful to any other first-party
consumer that needs to assert "this code is running inside an attested
enclave."

## What kavach is doing in the meantime

Nothing scheduled. The v3.2 "Blocked — actually awaiting upstream"
row for SGX/SEV/TDX attestation is parked and reflects the wait. The
`src/attestation.cyr` types in kavach are accurate placeholder shapes
that the verifier will populate when sigil ships the quote parsers.

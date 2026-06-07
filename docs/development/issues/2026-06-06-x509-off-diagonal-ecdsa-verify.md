# x509: off-diagonal ECDSA chain-link verification (hash ≠ curve)

- **Filed**: 2026-06-06 (sigil 3.7.4)
- **Priority**: **P1** (roadmap: "x509 — cert verification")
- **Reporter**: cyrius native-TLS **Mini-arc E** real-peer dev-check (verifying the live
  `one.one.one.one:443` Cloudflare chain through a real OS trust store).
- **Affects**: `src/x509.cyr` → `_x509_verify_link` (and the ECDSA verify primitives it calls).
- **Status**: follow-up to the **3.7.4** fix, which addressed the *parse* side only.

## Background — what 3.7.4 fixed (parse side)

`x509_parse` derived the ECDSA signature field width `ec_fw` from the signature **hash**
(SHA-256 → 32, SHA-384 → 48). But the r,s width is the **issuer key's curve**, not the hash.
A P-384 key signing with `ecdsa-with-SHA256` (e.g. the **SSL.com Root ECC**, and ~12 of 121
OS-trust-store roots) has 48-byte r,s, which overflowed `ec_fw=32` → `x509_parse` returned 0
→ the root was silently dropped from the trust store → chains rooting at it failed.

3.7.4 widens `ec_fw` to 48 when the cert's own key curve is P-384, so self-signed P-384
**anchors** parse. Verified: the full live Cloudflare → SSL.com chain now validates.

## The remaining gap — verify side (this issue)

`_x509_verify_link(child, issuer)` hardcodes the **hash↔curve diagonal**:

| `child` sig algo | required issuer curve | sig_len | primitive |
|---|---|---|---|
| `X509_SIG_ECDSA_SHA256` | P-256 only | 64 | `ecdsa_p256_verify` (hashes SHA-256) |
| `X509_SIG_ECDSA_SHA384` | P-384 only | 96 | `ecdsa_p384_verify` (hashes SHA-384) |

Real-world certs decouple the hash from the curve. sigil **cannot verify a chain LINK** that
is off-diagonal:

- a **P-384 issuer signing a child with SHA-256** (`ECDSA_SHA256` + P-384 issuer), or
- a **P-256 issuer signing a child with SHA-384** (`ECDSA_SHA384` + P-256 issuer).

`_x509_verify_link` rejects both (`x509_cert_curve(issuer) != X509_CURVE_P256/384` guard, and
the `sig_len` check). The fix is *not* exercised by cloudflare-class chains — there the only
off-diagonal cert is the **trust anchor**, which is never link-verified — which is why this is
**P1, not P0**. But it is required for full real-world chain coverage.

## Fix sketch

1. **Decouple hash from curve in `_x509_verify_link`.** Pick the **hash** from the child's sig
   algorithm OID (SHA-256 vs SHA-384) and the **curve / verify primitive** from the issuer's
   `x509_cert_curve` — independently. Drop the "ECDSA_SHA256 ⟹ P-256 issuer" coupling.
2. **Provide all four ECDSA verify primitives** `{P-256, P-384} × {SHA-256, SHA-384}`. Today only
   the two diagonal ones exist (`ecdsa_p256_verify` hashes SHA-256 internally; `ecdsa_p384_verify`
   hashes SHA-384). Add the off-diagonal two — ideally by factoring the hash out of the verify
   primitive (pass the digest, or a hash selector) rather than four copies.
3. **Signature width on store** (`x509_parse_into`, `ec_fw`): once the verify side is curve-aware,
   revisit storing r,s at the issuer's curve width rather than the hash-derived proxy + the 3.7.4
   P-384 widening — so the stored `sig_len` is unambiguous for the off-diagonal link cases too.
4. **Tests**: add a real-cert corpus exercising each of the four combos as a verified chain link
   (not just the anchor). The cyrius `tests/tcyr/tls_native_scaffold.tcyr` real-peer path is the
   downstream integration check once the cyrius Mini-arc E Release B real-peer smoke lands.

## Downstream

cyrius native-TLS Mini-arc E (Release B real-peer smoke + sandhi HTTPS) consumes this via the
re-folded `lib/sigil.cyr`. Cloudflare-class chains work after 3.7.4; broader real-world coverage
(off-diagonal *links*) needs this issue.

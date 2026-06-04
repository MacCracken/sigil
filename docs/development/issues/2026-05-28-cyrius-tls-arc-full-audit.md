# Sigil: comprehensive audit of gaps for the cyrius TLS 1.2 + 1.3 native arc

**Filed:** 2026-05-28
**Reporter:** cyrius (native TLS arc, v6.0.14 mini-arc A.5 entry +
forward plan through .37)
**Sigil version at time of report:** 3.5.6 (cyrius's pinned tag,
bumped from 3.5.5 earlier this session at the HKDF-SHA384 ship)
**Severity:** **P1** for the cyrius TLS arc (cumulative — every gap
below either holds a future cyrius slot or forces a 2-of-3 / 4-of-6
incomplete-ciphersuite ship). Sigil maintainers can re-rate any
individual line item; the issue exists as ONE filing to avoid the
piecemeal-per-cyrius-slot pattern.
**Status:** **substantially RESOLVED** (2026-06-03). All five line
items shipped; the cycle was **renumbered from 3.5.x to 3.6.x** when
3.6.0 opened the 3.6 line early (parallel verify). AES-128-GCM (3.5.7),
EC+Ed25519 key parsers (3.5.8), ECDSA sign (3.5.9), TLS 1.2 PRF (3.6.1),
and the full RSA PKCS#1 v1.5 surface — verify + key parsing + sign with
blinding/CRT (3.6.2–3.6.4) — are all in. **Remaining tail (3.6.5+):**
RSA-**PSS** (the only un-shipped part of line item 2) and the
cycle Closeout Pass. See `docs/development/roadmap.md` § "v3.6.x" and
CHANGELOG for per-tag detail.

## Triage — scheduled into sigil 3.5.x (2026-05-28)

Accepted in full and scheduled as five separate, ordered 3.5.x bites
(forcing-function + internal-dependency order; private-key parsers
land before the sign paths that consume their handles). The cycle-wide
Closeout Pass is held as the **last** 3.5.x tag, after every line item
ships. Cyrius bumps its sigil pin and resumes the held slot at each
tag. Tracking: [`docs/development/roadmap.md`](../roadmap.md) §
"Planned — v3.5.7 → v3.5.12 (cyrius native-TLS arc support)".

Final disposition (tags as actually shipped; the cycle renumbered
3.5.x → 3.6.x mid-flight):

| Issue line item | Sigil tag (shipped) | Cyrius forcing slot |
|---|---|---|
| 1. AES-128-GCM | **3.5.7** | v6.0.14 |
| 4. Private-key parsers — EC + Ed25519 | **3.5.8** | v6.0.15 / .23 |
| 3. ECDSA P-256/P-384 sign | **3.5.9** | v6.0.17 / .25 |
| 2. RSA PKCS#1 v1.5 verify + bignum engine | **3.6.2** | v6.0.17 / .25 |
| 2/4. RSA key parsing + PKCS#1 v1.5 sign | **3.6.3** | v6.0.17 / .25 |
| 2. RSA sign hardening (blinding + CRT) | **3.6.4** | v6.0.17 / .25 |
| 5. TLS 1.2 PRF | **3.6.1** (decision: SHIP) | v6.0.29–.34 |
| 2. RSA-PSS (remaining) | **3.6.5+** (pending) | v6.0.29–.34 |
| — Closeout Pass | **3.6.5+** (pending) | — |

> **Line-item-4 split (2026-05-28):** the RSA private-key parser moved
> from 3.5.8 to 3.5.10. RSA keys have no representation in sigil until
> the bignum/key type lands with the engine in 3.5.10, so the parser
> bundles there (where it can parse into a real type and be tested
> against sign/verify). 3.5.8 ships the EC + Ed25519 parsers, whose key
> types already exist and are end-to-end testable today.

**Notes carried into the roadmap:**
- Line 2 (RSA) is the one item that is **not** existing-shape:
  sigil has no general bignum modexp engine (`src/bigint_ext.cyr` is
  Curve25519 field arithmetic mod 2²⁵⁵−19 only). 3.5.10 is sized
  Large and may split into a modexp-engine + PKCS#1-v1.5-verify bite
  followed by PSS/MGF1 + sign bites.
- Line 5 (TLS 1.2 PRF) — sigil will make the ship-or-decline call at
  3.5.11 and flag the choice to cyrius either way; default lean is to
  keep protocol-shaped helpers in cyrius per the
  crypto-primitives-only boundary, but it ships for HKDF symmetry if
  preferred.
- Toolchain pin bumped 6.0.12 → **6.0.14** at triage.

Sigil maintainers may still re-rate or re-order any individual line
item; the schedule above is the current plan, not a contract.

## Why this is one issue instead of N

Prior pattern (the HKDF-SHA384 issue closed earlier today, 2026-05-28)
filed ONE missing primitive at the moment it became a forcing function
for cyrius v6.0.13. That was the correct shape for a single
primitive — but the cyrius native TLS arc has at least 4 more
upstream-sigil gaps that will surface one by one across cyrius
v6.0.14 through .34. Filing each at its forcing slot creates exactly
the per-slot-piecemeal pattern that's unhelpful for sigil's planning
(sigil can't see the dependency graph until each gap surfaces) and
for cyrius's planning (each surface point is a hold or a scope
compromise).

This issue is the comprehensive cross-walk. Sigil can plan around it
holistically and ship in whichever order fits the sigil cycle; cyrius
will scope around it (some gaps allow cyrius to ship a partial
ciphersuite list and add the missing one later; others are blockers).

## Sigil 3.5.6 has — usable as-is

| Surface | Sigil fn(s) | Cyrius uses for |
|---|---|---|
| SHA-256 family | `sha256_*`, `hmac_sha256`, `hkdf_*` | TLS 1.3 transcript + key schedule (SHA-256 ciphersuites) |
| SHA-384 family | `sha384_*`, `hmac_sha384`, `hkdf_*_sha384` | TLS 1.3 transcript + key schedule (SHA-384 ciphersuite) — shipped this session |
| SHA-512 | `sha512_*` | not directly used by TLS but needed by some peer extensions |
| ChaCha20 + Poly1305 | `chacha20poly1305_encrypt`/`decrypt` | `TLS_CHACHA20_POLY1305_SHA256` (1.3) + `TLS_*_WITH_CHACHA20_POLY1305_SHA256` (1.2) |
| AES-256-GCM | `aes256_key_expand`, `aes_gcm_encrypt`/`decrypt` | `TLS_AES_256_GCM_SHA384` (1.3) + `TLS_*_WITH_AES_256_GCM_SHA384` (1.2) |
| X25519 ECDH | `x25519`, `x25519_base` | TLS 1.3 + 1.2 key_share extension (group `x25519`) |
| ECDSA P-256 verify | `ecdsa_p256_verify` + `_der` | Verify peer's CertificateVerify (P-256 leaf) |
| ECDSA P-384 verify | `ecdsa_p384_verify` | Verify peer's CertificateVerify (P-384 leaf) |
| Ed25519 sign + verify | `ed25519_sign`, `ed25519_verify` | Verify peer + sign as server (Ed25519 leaf) |
| X.509 cert parse + chain | `x509_parse`, `x509_verify_chain` | RFC 8446 §4.4.2 certificate chain verification |
| PEM cert decode | `pem_decode_certs` | Load peer trust bundle + server cert chain |
| DER helpers | `der_walk`, `der_skip` | Re-parse cert subject / SAN for hostname verification |
| Constant-time bytes compare | `ct_eq_bytes` (via `lib/ct.cyr`) | MAC + tag verification side-channel safety |

## Sigil 3.5.6 missing — needed for cyrius TLS arc

The five line items below are **independent of each other** —
sigil can ship them in any order across one or more 3.5.x patches.
Each line item is small (existing-shape additive); the total is
modest. The cumulative impact on cyrius is: lifts all 6 TLS 1.3
ciphersuite gaps + every server-side cert-signing path + all 4
common TLS 1.2 ECDHE ciphersuites.

### 1. AES-128-GCM (3 fns)

**Why**: `TLS_AES_128_GCM_SHA256` (0x1301) is the RFC 8446 §9.1
**mandatory** TLS 1.3 ciphersuite. Without it, cyrius ships
non-compliant for interop floor (modern peers in practice accept any
of the 3 suites, but the RFC text is unambiguous about which is the
must-implement). It also unblocks 4 TLS 1.2 ciphersuites
(`TLS_*_WITH_AES_128_GCM_SHA256`).

**API ask** (mirrors the existing AES-256-GCM surface byte-for-byte):

```cyrius
fn aes_128_key_expand(key, round_keys): i64;          # 16-byte key → 176 bytes (11 round keys)
fn aes_128_gcm_encrypt(key, iv, aad, aad_len,
                       pt, pt_len, ct_out, tag_out): i64;
fn aes_128_gcm_decrypt(key, iv, aad, aad_len,
                       ct, ct_len, tag, pt_out): i64;
```

**Implementation note**: AES-128 differs from AES-256 only in the
key schedule (10 rounds + 176-byte round-key table vs 14 rounds +
240 bytes). The encrypt/decrypt block fns ARE the same — they walk
the round-key table by count rather than knowing the cipher
strength. If sigil prefers a single `aes_gcm_encrypt(key, key_len,
iv, aad, aad_len, pt, pt_len, ct_out, tag_out)` (9 args, key_len
arg switches the round count), that ALSO works for cyrius; just
flag the choice so cyrius's wrapper knows which path.

**Block-size gotcha for whoever picks up**: 16-byte block in both
variants; only the key schedule differs.

### 2. RSA signature surface (PKCS#1 v1.5 + PSS, sign + verify)

**Why**: TLS 1.3 server certs are still overwhelmingly RSA in the
wild (Let's Encrypt issues RSA by default until requested
otherwise; enterprise CAs ditto). Without RSA, cyrius's TLS 1.3
client cannot verify any RSA-signed CertificateVerify (so cannot
talk to most https://*.com servers); cyrius's TLS 1.3 server
cannot present an RSA cert (so cannot operate as a host for any
consumer's existing RSA-cert deployment). Also blocks all 1.2
RSA ciphersuites.

**API ask** (4 sign + 4 verify, or pack as 2 dispatched fns):

```cyrius
# PKCS#1 v1.5 (legacy 1.2 + still legal for 1.3 CertificateVerify)
fn rsa_pkcs1_sign_sha256(privkey, msg, msg_len, sig_out, sig_len): i64;
fn rsa_pkcs1_sign_sha384(privkey, msg, msg_len, sig_out, sig_len): i64;
fn rsa_pkcs1_verify_sha256(pubkey, msg, msg_len, sig, sig_len): i64;
fn rsa_pkcs1_verify_sha384(pubkey, msg, msg_len, sig, sig_len): i64;
# PSS (RFC 8446 §4.2.3 `rsa_pss_rsae_*`)
fn rsa_pss_sign_sha256(privkey, msg, msg_len, sig_out, sig_len): i64;
fn rsa_pss_sign_sha384(privkey, msg, msg_len, sig_out, sig_len): i64;
fn rsa_pss_verify_sha256(pubkey, msg, msg_len, sig, sig_len): i64;
fn rsa_pss_verify_sha384(pubkey, msg, msg_len, sig, sig_len): i64;
```

`privkey` / `pubkey` are opaque handles from sigil's RSA key parser
(see line item 4). Returns 0 / non-zero per sigil convention.

**Scope note**: SHA-256 + SHA-384 hashes match the TLS 1.3
`signature_algorithms` extension's `rsa_*_sha256` / `rsa_*_sha384`
values. SHA-512 RSA is rare in 1.3 deployments — not blocking
cyrius today; can stay backlog.

### 3. ECDSA P-256 + P-384 sign

**Why**: cyrius can VERIFY peer ECDSA signatures today
(`ecdsa_p256_verify`, `ecdsa_p384_verify`). But to act as a TLS
server with an ECDSA cert (or as a TLS 1.3 client with a client
cert), cyrius needs to SIGN. RFC 6979 deterministic-k is the
preferred construction for side-channel hygiene; RFC 4754 random-k
is the alternative.

**API ask**:

```cyrius
# Deterministic-k (RFC 6979); preferred for side-channel safety
fn ecdsa_p256_sign(privkey, msg, msg_len, sig_out): i64;       # 64-byte raw sig (r||s)
fn ecdsa_p256_sign_der(privkey, msg, msg_len, sig_der_out, max): i64;  # DER-encoded
fn ecdsa_p384_sign(privkey, msg, msg_len, sig_out): i64;       # 96-byte raw sig
fn ecdsa_p384_sign_der(privkey, msg, msg_len, sig_der_out, max): i64;
```

TLS 1.3 CertificateVerify uses the DER-encoded form (RFC 8446 §4.2.3
`ecdsa_secp256r1_sha256` value is `ASN.1 DER`). Cyrius will hash the
transcript with sigil's `sha256` / `sha384` before calling sign.

### 4. Private-key parsers (PEM + DER for RSA, ECDSA, Ed25519)

**Why**: `tls_native_new_server(cert_chain, cert_len, key, key_len)`
takes the server's private key as DER (PEM via caller's choice of
decoder). Without a private-key parser, the server cannot bring its
key online. Also needed for ECDH/ECDHE ephemeral-key path in some
1.2 flows (less load-bearing — sigil's `x25519_base` already
handles random→public-key for the EC side).

**API ask**:

```cyrius
# DER parsers — produce opaque private-key handles that
# rsa_*_sign / ecdsa_*_sign accept.
fn rsa_privkey_from_der(der, der_len): i64;          # PKCS#1 or PKCS#8
fn ecdsa_p256_privkey_from_der(der, der_len): i64;   # SEC1 or PKCS#8
fn ecdsa_p384_privkey_from_der(der, der_len): i64;
fn ed25519_privkey_from_der(der, der_len): i64;       # PKCS#8 (RFC 8410)

# PEM decoder — strip PEM headers, call the DER parser above.
# Returns handle or 0 on parse fail.
fn pem_decode_privkey(pem, pem_len): i64;            # auto-detect algo from header
```

Both keys-from-DER and keys-from-PEM are needed because real-world
consumers ship PEM (Let's Encrypt + most CA tools) and embedded
deployments ship raw DER.

### 5. TLS 1.2 PRF (optional — cyrius can build inline)

**Why**: TLS 1.2's key schedule uses
`P_hash(secret, label || seed)` = HKDF-Expand-like but with `A(i+1)
= HMAC_hash(secret, A(i))`. Cyrius can build this from sigil's
`hmac_sha256` / `hmac_sha384` directly — only 15-20 LoC inside
`tls_native.cyr`. If sigil prefers to ship it (for symmetry with
HKDF), that's fine; if not, cyrius will keep it inline. **Not
blocking** — flagging for completeness.

```cyrius
# Optional. If sigil does not ship, cyrius implements inline.
fn tls12_prf_sha256(secret, secret_len, label, label_len,
                    seed, seed_len, out, out_len): i64;
fn tls12_prf_sha384(secret, secret_len, label, label_len,
                    seed, seed_len, out, out_len): i64;
```

## Cyrius-side impact map

| Cyrius slot | Sigil dep | Status |
|---|---|---|
| v6.0.14 (Mini-arc A.5, ciphersuite negotiation) | line 1 (AES-128) | ships 2/3 ciphersuites without it; AES-128 lands when sigil ships |
| v6.0.15 (Mini-arc B.1, ClientHello) | line 4 (private key parsers — for client cert) | optional first cut, client cert is rare |
| v6.0.17 (Mini-arc B.3, CertificateVerify path) | lines 2 + 3 (RSA + ECDSA sign) | NEEDED for server auth verification per RFC 8446 §4.4.3 — wait, that's verify only, which we have. Sign path needed for server (line 3 mini-arc C) and client cert (line 4) |
| v6.0.19 (Mini-arc B.5, X.509 chain) | none | sigil's x509_verify_chain unblocks today |
| v6.0.23 (Mini-arc C.1, server state machine) | line 4 (private key parsers) | NEEDED to load server cert + key |
| v6.0.25 (Mini-arc C.3, ServerHello + key share) | lines 2 + 3 (sign for CertificateVerify) | NEEDED |
| v6.0.29–.34 (Mini-arc D, TLS 1.2 backport) | lines 1 + 2 (AES-128 + RSA) + optional 5 | the 4 ECDHE_RSA suites + ECDHE_ECDSA_AES_128 paths gate here |

**Net impact if sigil ships nothing more**: cyrius lands at v6.0.34
with a working TLS 1.3 client + server for the 2 ChaCha20-Poly1305
and 1 AES-256-GCM ciphersuites + Ed25519/ECDSA-verify-only auth + no
TLS 1.2. That's ~70% of the modern TLS surface; the missing 30%
is the load-bearing part for real-world interop floor (AES-128 +
RSA).

## What would close this issue

Any 3.5.x patch tag that ships at least lines 1 + 2 + 3 + 4 (in any
combination across one or more patches). Line 5 is optional. Each
line item lifts a specific cyrius hold; sigil can ship in whichever
order fits the sigil cycle.

Cyrius will update its sigil pin and resume held slots at each tag.

## Not asking for in this issue

- TLS 1.0 / 1.1 (deprecated by RFC 8996; cyrius doesn't support).
- SHA-512 RSA (rare; backlog).
- AES-CBC (legacy; modern peers don't need it).
- DH (non-EC); only EC variants in 1.3.
- DTLS (datagram TLS; not in cyrius scope).
- QUIC (separate stack; not in this arc).

---

## Cyrius arc reference

- Cyrius native TLS arc: `cyrius/docs/development/roadmap.md` § "Native TLS arc — v6.0.x .10 → .37".
- Cyrius memory pin: `project_native_tls_arc_v6_2_x`.
- TLS 1.3 spec: RFC 8446 §4–§7, §9.1 (mandatory ciphersuite).
- TLS 1.2 spec: RFC 5246 §5 (PRF), §6 (record layer), §7 (handshake).
- RFC 8017 (PKCS#1 v2.2 — RSA-PKCS1 + RSA-PSS).
- RFC 6979 (deterministic ECDSA).
- RFC 8446 §4.2.3 (signature algorithms).
- RFC 5208 / 5958 / 8410 (PKCS#8 private key formats).

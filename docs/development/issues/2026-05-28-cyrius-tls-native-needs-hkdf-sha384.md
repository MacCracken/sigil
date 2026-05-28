# Sigil: HMAC-SHA384 + HKDF-SHA384 needed for cyrius TLS 1.3 native stack

**Filed:** 2026-05-28
**Reporter:** cyrius (native TLS arc, v6.0.13 mini-arc A.4 entry; arc
spans cyrius v6.0.9–.37, currently HELD at .13 pending this work)
**Sigil version at time of report:** 3.5.5 (cyrius's pinned tag; see
[`cyrius/cyrius.cyml`](https://github.com/MacCracken/cyrius/blob/main/cyrius.cyml))
**Severity:** **P1** for the cyrius TLS arc (a forcing function — the
arc cannot progress past Mini-arc A.4 / v6.0.13 without it). Sigil
maintainers may legitimately re-rate to **P2** if other 3.5.x work is
in flight — this is a pure additive surface with no removal pressure
and no security-incident driver.
**Status:** **RESOLVED** in sigil **3.5.6** (2026-05-28). See the
Resolution section at the foot of this file.

## Summary

Cyrius is mid-arc on a native, pure-Cyrius TLS 1.3 + 1.2 stack
(`lib/tls_native.cyr`) that replaces the existing libssl/fdlopen
wrapper (`lib/tls.cyr`). The arc charter explicitly puts the **crypto
primitives in sigil** and keeps `tls_native.cyr` as a **protocol
layer only** (handshake state machine + record layer + ciphersuite
negotiation + key schedule wiring + X.509 chain-verify wiring).
Adding HMAC / HKDF inline to `tls_native.cyr` would violate that
discipline; cyrius held v6.0.13 instead so this can come from sigil.

The TLS 1.3 key schedule (RFC 8446 §7.1) uses HKDF based on the
negotiated ciphersuite's hash:

| Ciphersuite (IANA, RFC 8446 §B.4) | Hash | Available in sigil 3.5.5? |
|---|---|---|
| `TLS_AES_128_GCM_SHA256` (0x1301) | SHA-256 | ✓ (existing `hmac_sha256` / `hkdf_extract` / `hkdf_expand`) |
| `TLS_CHACHA20_POLY1305_SHA256` (0x1303) | SHA-256 | ✓ (same as above) |
| `TLS_AES_256_GCM_SHA384` (0x1302) | SHA-384 | ✗ — only sigil-side gap blocking cyrius v6.0.13 |

Sigil 3.4.x already ships `sha384_init` / `sha384_update` /
`sha384_finalize` (verified at cyrius v6.0.12 transcript-hash work,
which used both `sha256_*` and `sha384_*` from sigil 3.5.5
successfully). What's missing is the HMAC-over-SHA384 primitive +
the HKDF construction over it.

## What we'd like sigil to ship

Three new public fns (and optionally a fourth combined helper, for
parity with the existing `hkdf` helper that combines extract +
expand):

```cyrius
# HMAC-SHA384 per FIPS 198-1 + RFC 4231 §3.
# `key` is the input keying material; `key_len` may be ≥ 128
# (the SHA-384 block size — keys longer than that are first
# hashed). Output is 48 bytes written to `out48`.
# Returns 0 on success, non-zero on validation failure.
fn hmac_sha384(key, key_len, msg, msg_len, out48): i64;

# HKDF-Extract over HMAC-SHA384 per RFC 5869 §2.2.
# `salt` may be empty/null (treated as HashLen=48 zero bytes per RFC).
# `prk_out48` receives the 48-byte pseudo-random key.
# Returns 0 on success.
fn hkdf_extract_sha384(salt, salt_len, ikm, ikm_len, prk_out48): i64;

# HKDF-Expand over HMAC-SHA384 per RFC 5869 §2.3.
# Max OKM = 255 * 48 = 12240 bytes (RFC bound).
# Returns 0 on success, -2 if out_len > 255*48.
fn hkdf_expand_sha384(prk, prk_len, info, info_len, out, out_len): i64;

# Optional convenience — combined extract+expand, mirrors the
# existing `hkdf(salt,...,out,out_len)` helper.
fn hkdf_sha384(salt, salt_len, ikm, ikm_len, info, info_len,
               out, out_len): i64;
```

Naming follows sigil's existing convention (`hmac_sha256`,
`hkdf_extract`, `hkdf_expand`, `hkdf`) with the algorithm suffix
disambiguated.

## Implementation outline (for reference)

- **HMAC-SHA384** is the standard `H((K ⊕ opad) || H((K ⊕ ipad) ||
  message))` construction, with SHA-384's **128-byte block size**
  (NOT 64 like SHA-256 — this is the one wrinkle worth flagging
  for whoever picks this up; copying `hmac_sha256.cyr` byte-for-byte
  and only flipping the hash will produce wrong output). Keys longer
  than 128 bytes are first replaced by their SHA-384 hash (48
  bytes) and zero-padded to 128.
- **HKDF-Extract-SHA384** is `hmac_sha384(salt, salt_len, ikm,
  ikm_len, prk_out)` directly. If `salt` is null/empty, substitute
  48 zero bytes (RFC 5869 §2.2).
- **HKDF-Expand-SHA384** is RFC 5869 §2.3's iterative HMAC loop. T(0)
  = empty; T(i) = HMAC-SHA384(PRK, T(i-1) || info || i). Concatenate
  T(1) || T(2) || … up to `out_len` bytes (max 255 iterations).

Sigil's existing `src/hmac.cyr` + `src/hkdf.cyr` are the reference
shape. The 48-byte / 128-byte sizings cascade from the SHA-384
block + digest sizes — easy mistake to make is reusing the 64 / 32
constants from the SHA-256 variant.

## Test vectors

The standard known-answer vectors are in **RFC 4231 §4** (HMAC-SHA384)
and **RFC 5869's HKDF test cases** are SHA-256 only; the
sha2-crypt-style SHA-384 HKDF vectors come from elsewhere. The
practical TLS 1.3 vector source is **RFC 8448 §4 "Resumed 0-RTT
Handshake"** which uses TLS_AES_256_GCM_SHA384 end-to-end — every
intermediate secret is published byte-for-byte. Cyrius will verify
against RFC 8448 §4 once sigil ships these primitives.

For sigil's own regression: at minimum the RFC 4231 §4 HMAC-SHA384
vectors (Test Cases 1–7), and a couple of HKDF-SHA384 vectors
synthesized from those (Extract+Expand with known inputs, output
re-verified by an external tool — Python's `cryptography.hazmat`
HKDFExpand or `openssl kdf` work). Cyrius can supply the HKDF-SHA384
vectors against an external reference if helpful for sigil's
regression — let me know.

## Cyrius-side context (why this is P1 for cyrius but not sigil)

The native TLS arc (cyrius v6.0.9–.37) replaces a libssl/fdlopen
wrapper that the in-flight bare-metal AGNOS kernel cannot use
structurally (libssl needs ld.so + glibc TCB; the kernel has
neither). The arc pulled forward from its original v6.2.x placement
to v6.0.x tail at the user's direction 2026-05-28 so sandhi + other
projects-waiting-on-TLS unblock immediately. With cyrius .13 held,
the arc serialises behind sigil — Mini-arcs B (1.3 client, .14–.21),
C (1.3 server, .22–.28), D (1.2 backport, .29–.34), and E (sandhi
rewire + closeout, .35–.37) all queue here.

That serialisation is the cyrius-side P1. Sigil's own roadmap may
have other 3.5.x work in flight (the 3.5.4 backlog had X.509 path
validation + a TEE pillar; not sure where 3.5.6+ landed). Sigil
maintainers see the full picture — please re-rate as makes sense for
the sigil cycle. Cyrius will resume v6.0.13 at the next sigil tag
that exposes these fns.

## What would close it

A sigil 3.5.x patch tag that exports `hmac_sha384` +
`hkdf_extract_sha384` + `hkdf_expand_sha384` (and optionally the
combined `hkdf_sha384`), with RFC 4231 §4 HMAC test vectors covered
in sigil's regression suite. Public-API additive; no breakage; no
removal pressure. Cyrius bumps its sigil pin in `cyrius.cyml` and
resumes the held v6.0.13 key-schedule work.

## Not asking for in this issue

- SHA-512 HKDF (no TLS 1.3 ciphersuite uses it; would only be needed
  if a future TLS extension or non-TLS consumer surfaces).
- HKDF over keyed-hash MACs other than HMAC (e.g. KMAC) — same
  reasoning.
- Any change to the existing `hkdf` / `hmac_sha256` surface.

---

## Cyrius arc reference

- Cyrius native TLS arc: `cyrius/docs/development/roadmap.md` §
  "Native TLS arc — v6.0.x .10 → .37".
- Cyrius held slot: v6.0.13 (Mini-arc A.4 — TLS 1.3 key schedule).
- Cyrius memory pin: `project_native_tls_arc_v6_2_x` (cyrius agent
  memory; mirrors this issue's status).
- TLS 1.3 spec: RFC 8446 §7.1 (Key Schedule), §B.4 (ciphersuites).
- RFC 4231 (HMAC-SHA-2 test vectors).
- RFC 5869 (HKDF spec).
- RFC 8448 §4 (TLS 1.3 1-RTT handshake using AES-256-GCM-SHA384;
  every intermediate secret published).

---

## Resolution — sigil 3.5.6 (2026-05-28)

Shipped exactly the requested surface, additive, no breakage:

| Fn | Module | Notes |
|---|---|---|
| `hmac_sha384(key, key_len, msg, msg_len, out48)` | `src/hmac_sha384.cyr` | FIPS 198-1 / RFC 4231 §3. 128-byte block, 48-byte digest. Keys > 128 B SHA-384-hashed first. K′/ipad/opad are `secret var`. |
| `hkdf_extract_sha384(salt, salt_len, ikm, ikm_len, prk_out48)` | `src/hkdf_sha384.cyr` | RFC 5869 §2.2. Empty salt → 48 zero bytes. |
| `hkdf_expand_sha384(prk, prk_len, info, info_len, out, out_len)` | `src/hkdf_sha384.cyr` | RFC 5869 §2.3. Returns `-2` if `out_len > 255*48 = 12240`. |
| `hkdf_sha384(salt, salt_len, ikm, ikm_len, info, info_len, out, out_len)` | `src/hkdf_sha384.cyr` | Combined one-shot (the optional fourth helper). PRK is `secret var`, zeroized. |

The SHA-384 **128-byte block / 48-byte digest** wrinkle the issue
flagged was honored — the implementation does NOT reuse the 64/32
SHA-256 constants.

**Module placement.** `src/sha384.cyr` is included *after*
`src/hmac.cyr` / `src/hkdf.cyr` in sigil's dependency order
(`src/lib.cyr`), so the SHA-384 MAC/KDF could not be appended to the
existing SHA-256 modules — they went into two new modules placed
after `sha384.cyr` in the include chain, the `[lib].modules` list,
and `scripts/regen-dist.sh`.

**Test vectors** (`tests/tcyr/hkdf_sha384.tcyr`, +19 assertions):
- HMAC-SHA384: **RFC 4231 §4** Test Cases 1–4, 6, 7 (TC5 truncation
  omitted — sigil emits the full 48-byte tag). TC6/TC7 use a
  131-byte key, exercising the >128-byte key-hash path.
- HKDF-SHA384: three synthesized vectors (RFC 5869 TC1 inputs over
  SHA-384; empty-salt/empty-info single block; two-round 96-byte
  OKM), each **cross-verified against Python `hmac`/`hashlib` AND
  `openssl kdf -kdfopt digest:SHA384 … HKDF`** — two independent
  references agree byte-for-byte.
- Edges: `out_len > 12240` → `-2`; `out_len == 0` → `0`.

These fns are in the `dist/sigil.cyr` bundle (regenerated;
`cyrius doc --check`: 0 undocumented), so cyrius gets them by
bumping its sigil pin — no `src/verify.cyr` wrapper needed (HKDF is
called directly from the bundle, same as the SHA-256 variants).

**For cyrius:** bump the sigil pin in `cyrius/cyrius.cyml` to
`3.5.6` and resume the held v6.0.13 key-schedule work. RFC 8448 §4
end-to-end verification can now proceed.

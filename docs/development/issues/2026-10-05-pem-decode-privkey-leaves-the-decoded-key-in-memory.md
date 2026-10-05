# `pem_decode_privkey` leaves the decoded private key in memory, and never checks its scratch allocation

**Filed:** 2026-10-05 (recorded by cyrius 6.6.16, from the thr-2 lane's review of the native TLS server's
key load) · **Severity:** MEDIUM (a secret left in memory; plus a NULL write on allocation failure) ·
**Status:** open

⛔ Nothing in cyrius 6.6.16 depends on this; fix it in sigil, release, and cyrius refolds `lib/sigil.cyr`.

**Where:** `src/privkey.cyr`, `pem_decode_privkey` (:389; folded into cyrius as `lib/sigil.cyr` ~20410,
the allocation at ~20456). Checked against sigil **3.13.9** (`7d7a880`).

## 1. The decoded key DER is never zeroed — a secret left in memory

`pem_decode_privkey` base64-decodes the PEM body into `var pool = alloc(pem_len);` (:435) and hands `pool` to
the typed parser (`ecdsa_p256_privkey_from_der`, `ecdsa_p384_privkey_from_der`, `ed25519_privkey_from_der`,
`rsa_privkey_from_der`). That buffer IS the private key in DER form — the EC scalar / Ed25519 seed, or the
whole RSA key (d, p, q, dP, dQ, qInv). **No return path wipes it**: not the success returns (32 / 48 /
`RSAK_SIZE`), not the RSA sentinel (`0 - SIG_PRIVKEY_RSA`, which leaves a fully decoded RSA key behind and
returns to a caller that will retry and decode it a SECOND time), and not the `-1` failure returns after the
decode. Because the scratch comes from the bump allocator, which never frees or reuses, the plaintext key
stays in the process heap for the life of the process — readable by anything that later discloses heap
memory (a core dump, a swapped page, an over-read elsewhere in the process).

The header comment frames the scratch only as "allocator hygiene" (`:384-387`, "Long-running consumers
wanting allocator hygiene should decode DER themselves"). It is a key-material problem, not a hygiene one, and
the caller cannot fix it: `pool` is internal and never returned.

**Reach.** Every native TLS server that loads a PEM key (cyrius `lib/tls_native_hs13.cyr`, `_tn_load_privkey`
→ `pem_decode_privkey`). Through cyrius 6.6.15 that ran on EVERY accept, so a long-running server left one
copy of its private key per handshake on the heap (sandhi measured 120 B/request with an Ed25519 key). cyrius
6.6.16 decodes once per distinct key text and caches the answer, so it is now one leaked copy per key per
process — fewer, but still a plaintext key in never-freed memory. Any other caller of `pem_decode_privkey`
(sigil's own tests and tools, consumers loading signing keys) leaves one copy per call.

## 2. `alloc(pem_len)` is never checked for 0

`var pool = alloc(pem_len);` is used without a check. On a refused allocation (`alloc` returns 0 — address-space
exhaustion, an over-large `pem_len`, or a capped arena) `_pem_b64_decode(pem, body_start, end_off, pool, pem_len)`
writes the decoded bytes through address 0 instead of returning `-1`. `pem_decode_certs` has the same unchecked
`alloc(pem_len)` (`src/pem.cyr:359`, passed straight to `pem_decode_certs_into`; the fold's ~19894) and should get the same check.

## Suggested fix (sigil's call)

- Check `pool == 0` → `return 0 - 1;` (and the same in `pem_decode_certs`).
- Wipe `pool` for `pem_len` bytes (a non-elidable wipe, the shape `_mldsa_wipe` already uses) on **every**
  return after the decode — success, the RSA sentinel and each failure path — e.g. by routing all of them
  through one `_privkey_scratch_done(pool, pem_len, ret)` exit. If sigil prefers, decode into a caller-supplied
  arena (`*_a` variant) so a server can also reclaim it, but the wipe is the part that matters.
- Consider zeroing on the RSA sentinel path *before* returning, or not decoding the body at all until
  `key_max >= RSAK_SIZE` is known to hold for RSA.
- Update the `:384-387` comment: the scratch holds the key and is wiped.

## Acceptance

A test that decodes a PEM key of each kind (SEC1 P-256, PKCS#8 Ed25519, PKCS#1 RSA with `key_max <
RSAK_SIZE` and with it ≥) and asserts the scratch region holds no non-zero byte afterwards (capture `alloc`'s
next pointer before the call, scan `pem_len` bytes after); and a row that forces the allocation to refuse
(an arena/limit-capped allocator) and expects `-1`, not a fault.

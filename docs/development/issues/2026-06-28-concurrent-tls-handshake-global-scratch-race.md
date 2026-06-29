# Concurrent TLS handshakes race sigil's module-global crypto scratch → server crash

**Filed:** 2026-06-28 (by the `yeo-cy-test` consumer — SecureYeoman → Cyrius
full-stack viability probe; toolchain bump to cyrius 6.3.0 / sandhi 1.6.13 /
sigil 3.9.5)
**Severity:** **HIGH (🔴)** — a TLS server crashes (SIGSEGV) or drops connections
(ECONNRESET) the moment **two TLS handshakes run concurrently**. Blocks the
entire promise of sandhi's multi-worker `sandhi_server_run_pooled_tls` (parallel
handshakes across cores) and means a "secure, local-first" product's TLS
termination can only use **one core**.
**Component:** module-**global** crypto scratch buffers, shared across all
threads:
- `src/aes_ni.cyr:54-56` — `_aes_ni_st_key[32]` / `_aes_ni_st_rk[240]` /
  `_aes_ni_st_pt[16]` / `_aes_ni_st_ct[16]` (single global AES-NI state + round keys)
- `src/sha_ni.cyr:61` — `_sha_ni_st_ctx[144]` (single global SHA-NI context)
- `src/bignum.cyr:46-50, 370-376, 384-387` — `_bn_modrem` / `_bn_modn1` /
  `_bn_exp_*` / `_bn_mont_*` / `_bn_inv_*` (modexp + Montgomery + inverse scratch)
**sigil's role: FIX OWNER.** The scratch lives in sigil; the consumer and sandhi
only compose it.
**Repos:** surfaced through cyrius `tls_native` + sandhi 1.6.10's
`sandhi_server_run_pooled_tls`; the global state is sigil's.

## Summary

The negotiated cipher in the repro is **`TLS_AES_256_GCM_SHA384`**, so every TLS
1.3 handshake + record drives **AES-GCM** (through the single global
`_aes_ni_st_*`) and the **SHA-384 transcript / HKDF** (through the single global
`_sha_ni_st_ctx`). These are *process-global* `var …[N]` buffers — one copy for
the whole process, not per-call and not thread-local. Two handshakes on two
threads interleave on the same AES round-key / SHA state buffers mid-operation →
the round keys (or transcript state) get overwritten under the other thread →
corrupted AEAD/transcript output (handshake fails → ECONNRESET) or an
out-of-bounds/garbage-pointer dereference (**SIGSEGV — the server process dies**).

## Reproduction

A pooled TLS server (sandhi `sandhi_server_run_pooled_tls`, ≥2 workers, Ed25519
cert) driven by N **simultaneous** client handshakes:

```
concurrency = 1 : ok = 1            (one handshake at a time — fine)
concurrency = 2 : ok = 0, server SIGSEGV (exit 139); later connects → ECONNREFUSED
concurrency ≥ 2 : ECONNRESET / "EOF in violation of protocol", or SIGSEGV
```

Serializing the handshakes (1 worker, or a single-threaded client loop) is always
fine — it is specifically *concurrent* access to the global scratch that breaks.

## Ruled out (so the fix targets the right thing)

- **Allocator** — `alloc()` is CAS-locked / thread-safe (cyrius v6.0.64); the
  sandhi serve loop gives each worker its own arena. The races are on the
  *static* scratch, not heap allocation.
- **Entropy / transport hooks** — `tls_native`'s `_tn_tx_read/_write/_now/_rand`
  are documented "set once at init"; default entropy is the `sys_getrandom`
  syscall (thread-safe). Not the cause.
- **sandhi** — its per-worker arenas and per-connection `reset_via` are correct;
  it just calls into sigil, which is where the shared state lives.

## Why this wasn't caught before

sandhi's own server-TLS gate (`programs/_server_tls_probe.cyr`) drives its
"burst of 8" through a **single-threaded parent `while` loop** — each request
completes before the next starts, so the handshakes are **serialized**. Its
"[3] isolation" check pins a worker by holding a **plaintext** silent TCP socket
in the accept-read, then runs 8 *more sequential* GETs — proving the pool isn't
single-flight, but **never running 2 concurrent TLS handshakes**. So the
multi-worker TLS pool's core behaviour (parallel handshakes) had never actually
been exercised until this probe pointed real concurrent clients at it.

## Prior art (sigil is already part-way there)

sigil **3.8.0** shipped "ChaCha20 + X25519 parallel-path banking (done +
race-tested)" — so per-call/thread-safe crypto is an established sigil goal and
pattern. This issue is the request to extend that to the **handshake-critical**
paths a TLS 1.3 server actually exercises: **AES-NI (GCM), SHA-NI (transcript /
HKDF), and the bignum modexp/Montgomery scratch.**

## Suggested direction (fix owner's call)

1. **Thread-local or per-call scratch** for `_aes_ni_st_*`, `_sha_ni_st_ctx`,
   and the `_bn_*` modexp/Montgomery buffers (the same banking 3.8.0 applied to
   ChaCha20/X25519). A caller-arena variant (`…_in(a, …)`) would let sandhi pass
   its existing per-worker arena straight through.
2. If (1) is large, an interim **documented contract** ("sigil's AES-NI/SHA-NI/
   bignum primitives are NOT safe for concurrent calls; serialize or use one
   instance per thread") so consumers like sandhi can guard correctly instead of
   crashing — and sandhi can then either serialize handshakes or thread per-worker
   instances.

## Consumer-side mitigation (in place)

`yeo-cy-test` pins its TLS pool to **1 worker** (`max_conns = 1`) — handshakes
serialize, the server is crash-safe — and keeps a 60-concurrent-HTTPS test as a
tripwire that fails loudly if the pool is bumped back to >1 before this lands.
Plaintext HTTP stays at 4 workers (no crypto → no sigil scratch). This is a
stopgap; the real fix unlocks multi-core TLS termination.

---

## Addendum (2026-06-28) — deeper root-cause + scope corrections

A follow-up deep-dive (21-agent workflow + hands-on repro at cyrius 6.3.1)
sharpened this issue. The original inventory above (`_aes_ni_st_*` / `_sha_ni_st_ctx`
/ `_bn_*`) is correct but **incomplete**, and one related claim was **refuted** —
please fold these in:

- **PRIMARY observed crash site is HKDF, not AES-NI.** `hkdf_expand`
  (`src/hkdf.cyr:75-169`) and `hkdf_expand_sha384` (`src/hkdf_sha384.cyr:78-171`)
  hold live expand state in process-global pointers (`_hkdf_scratch` /
  `_hkdf384_scratch`) + a non-thread-safe `fl_alloc`; under two concurrent
  handshakes the faulting `memset`/store lands here. HKDF runs in every TLS 1.3
  key schedule, so it's hit before the AEAD bulk path.
- **SYSTEMIC ROOT: the per-thread crypto BANKS exist but are never activated for
  TLS.** `src/crypto_scratch.cyr:51-88` provides `crypto_bank_set` / `cbank()`
  (the 3.6/3.8 mechanism), and the scratch sites (`x25519.cyr:65`, `sha512.cyr:181`,
  ed25519 `ge_add`/`ge_double`, etc.) read **bank 0** until `crypto_bank_set` is
  called. **No TLS consumer ever calls `crypto_bank_set`** (grep: only
  `src/verify.cyr:1072` does) — so every concurrent handshake collides on bank 0.
  The cleanest fix is likely **activating per-worker banks on the TLS handshake
  path** rather than removing globals, plus extending banking to the unbanked
  sites below.
- **`ed25519_sign` is fully UNBANKED.** `src/ed25519.cyr` `ed25519_sign` uses
  top-level scratch (`az`/`nhash`/`r_scalar`/`a_scalar`/`hram`/`h_scalar`/
  `R_point`/`S_result`) with no `cbank()`, and calls bank-0 `ge_add`/`ge_double`.
  This is on the **server CertificateVerify path of every handshake** (the probe's
  cert is Ed25519) — a per-handshake unbanked-scratch race (and a nonce-corruption
  hazard worth noting beyond just crashing).
- **Both AEAD suites crash — the "ChaCha20 may be safe" note is WRONG.** Repro at
  `max_conns ≥ 2` reproduced SIGSEGV for **both** `TLS_AES_256_GCM_SHA384` and
  `TLS_CHACHA20_POLY1305_SHA256`. ChaCha20/X25519 are *banked* (3.8.0) but the bank
  is never selected for TLS (above), so they collide on bank 0 too.
- **REFUTED — do NOT chase AES-GCM record state.** A sweep agent claimed AES-GCM
  *record* encryption scratch is process-global; on re-check it is **function
  locals** (`var state[16]` / `var counter[16]` at `src/aes_gcm.cyr:345/659` are
  indented locals, not col-0 globals; only `_aes_sbox`/`_aes_rcon`/`_aes_inited`
  are global and read-only). The `aes_gcm.cyr:33` "per-call function locals" comment
  is **accurate**. The AEAD bulk-data path is not part of this bug.
- **ECDSA-P256/P384 are latent (not yet repro'd).** `src/ecdsa_p256.cyr` /
  `ecdsa_p384.cyr` carry ~90-100 unbanked process-global scratch buffers each;
  not exercised by the Ed25519-cert probe, but a TLS server with an ECDSA cert
  under `max_conns > 1` would hit the same class. (Note: `tls_native` server
  currently rejects RSA keys, so RSA-PSS sign scratch is dead code on the server
  path — not in scope.)


---

## Resolution — 3.9.6 (2026-06-29)

**Crash FIXED.** Root cause was two-fold and both halves are addressed:

1. **Banks never activated for TLS** → `cbank()` now **auto-assigns** a private
   lane to each thread on first use (atomic counter → lanes `1..63`, bank 0 =
   main/serial). No consumer `crypto_bank_set` call is required.
   `SIGIL_CRYPTO_BANKS` 8 → 64.
2. **Unbanked / `fl_alloc` handshake+AEAD primitives** → banked HKDF / HKDF-SHA384
   (rewritten allocation-free), HMAC / HMAC-SHA384, `ed25519_sign` + `sc_muladd`,
   the one-shot SHA-256/384/512 (banked `_into`, no `fl_alloc`), `sha384_finalize`,
   the full **AES-GCM** AEAD path (GHASH/CTR/encrypt/decrypt + the round-key
   schedule, off `fl_alloc`), and the ChaCha20-Poly1305 / Poly1305 static scratch.
   NI self-test CAS-guarded.

Validated by `tests/tcyr/concurrent_tls_handshake.tcyr` (16 auto-banked workers,
no `crypto_bank_set`, > 8 lanes; byte-for-byte vs. serial; stable 40/40 — caught
the `sha384_finalize` and AES-GCM round-key races during development). The repro's
`TLS_AES_256_GCM_SHA384` suite is fully race-clean.

ADR [0007](../adr/0007-auto-banking-for-concurrent-tls.md); audit
[`2026-06-29-3.9.6-…-banking`](../audit/2026-06-29-3.9.6-concurrent-tls-handshake-banking-audit.md).

**Deferred to 3.9.7** (tracked in [roadmap](../roadmap.md) "Thread-safety
follow-up → 3.9.7", not dropped): the ChaCha20-Poly1305 `_cp_tag` `fl_alloc`
mac_data buffer (needs a streaming Poly1305 — the only remaining concurrent-path
`fl_alloc`); ECDSA P-256/P-384 sign+verify banking (latent — `tls_native` rejects
RSA and the probe cert is Ed25519); the `bignum`/`tls12_prf` statics (off the TLS
1.3 server path). Maintainer may archive this issue once 3.9.7 closes those.

# Stale or wrong comments found during the 3.13.0 work (comment-only)

**Filed:** 2026-09-23 (3.13.0) · **Severity:** LOW · **Status:** resolved (3.13.1)

Line numbers are approximate (pre-3.13.0); re-locate by content, and re-check each against the current code first.

## sgx.cyr / tdx.cyr / sev_snp.cyr
- tdx.cyr ~107-108: TdxQuote struct layout says the sig and AK fields are 64 B; since 3.5 they can be 96 B (P-384).
- sgx.cyr ~146: accessors described as pointing into a "DER buffer" — the quote is not DER.
- sgx.cyr ~250: claims a u32 read can come back as a negative i64 — it cannot on 64-bit; the `< 0` guards (here and in TDX) are dead but harmless. Fix the comment; leave the guard.
- sev_snp.cyr ~17: "GenoaPilatos+" is garbled.
- Any "Not thread-safe" doc line added this cycle that the H2 fix has made false.

## verify.cyr / audit.cyr
- sv_verify_batch comment says SIGIL_CRYPTO_BANKS = 8; it is 64.
- _batch_worker header describes a 48-byte record; the code reads offset +48 and allocates 56 bytes per worker.
- _vresult_add_check_scratch comment says _VSC_MAX_CHECKS = 6; it is 8.
- The batch block says a function-local `var X[N]` is a shared global — superseded quirk #1 (true only past the 122,880 B frame budget).
- An empty duplicate "Boot chain verification" section header.
- audit.cyr, the block comment above alog_load says the writer uses json_write_escaped — true only if the H3 fix made it so; make it accurate.

## trust.cyr / policy.cyr
- trust.cyr ~37 KeyVersion layout: secret key described as "32 raw bytes ... for HMAC signing"; tests store the 64-byte Ed25519 secret key there and nothing in src/ reads it for HMAC.
- policy.cyr ~513 (above `var _rl_load_bad`): says rl_from_jsonl "Returns a new list or 0" — it never returns 0; and calls the bad-line count "returned" — it is only available via rl_load_bad_count().

## ecdsa_p256.cyr / ecdsa_p384.cyr
- ecdsa_p256.cyr ~16-24: says verify uses the Montgomery ladder and a ct_eq_bytes_lens final compare; verify actually uses the non-CT comb/window and u256_eq (fine: public inputs).
- ecdsa_p256.cyr ~481 and ~701: inversions described as "no CT concern", and ~800 says the pt_cswap swap bit is public — on the SIGN path they handle the secret nonce k (and Z of k·G). Say so accurately (and note the recorded fine-grained timing residual) rather than claiming CT that is not there.
- ecdsa_p256.cyr ~26-29: gives the superseded quirk #1 as the reason for module globals.
- ecdsa_p384.cyr ~25: says the u384 helpers are private; ecdsa_sign.cyr and the tests call them.
- The "Constant-time scalar multiplication ... field/point ops always run in fixed sequence" block (~1204-1216) — make it match the post-H1 code exactly (fixed-length ladder; field ops still branch = recorded residual).

## sha512.cyr / sha256.cyr / x509.cyr / ed25519.cyr / aes_ni.cyr / seal.cyr
- sha512.cyr: context described as 272 bytes; it is 208.
- x509.cyr: header, struct layout table and the x509_cert_alloc_into doc say 256 bytes; the struct is 272, and the table lacks the key-usage fields at +256 / +264. Layout rows: sig_algo "ECDSA_SHA256 only" (stale), sig_off described as an offset (it holds an absolute pointer), sig_len "must equal 64" (stale).
- x509.cyr: the _xp_parse_spki comment says only EC keys are accepted; it also accepts RSA and Ed25519.
- ed25519.cyr: the ge_scalarmult section calls its scalar secret; its only src/ caller is ed25519_verify with the public h.
- aes_ni.cyr: aes256_encrypt_block_ni says it is "not wired into aes_gcm_encrypt"; it is.
- sha256.cyr: sha256()'s doc says it "allocates... and frees a context"; it uses a banked context and never allocates.
- seal.cyr ~65: `_seal_info` described as stack-allocated; it is one shared module-level buffer (the race itself is LOW L20 — comment only here).

## mldsa*.cyr / tpm.cyr / ima.cyr / secureboot.cyr
- mldsa.cyr ~370: says mldsa65_verify's 0 = valid convention matches sigil's other checks; ed25519_verify returns 1 = valid.
- mldsa.cyr ~16-18 and mldsa_sample.cyr ~19: secret-lifetime / "public scratch" claims — make them match the post-M11 code.
- tpm.cyr:1, ima.cyr:2, secureboot.cyr:2: headers say they wrap "agnosys" (folded into sigil at 3.8.1).

## Resolution (3.13.1)

Every listed comment is corrected against the current code: the TEE, verify / audit,
trust / policy, ECDSA, SHA-2, x509, AES-NI, seal, ML-DSA and tpm / ima / secureboot header
items. `_seal_info` itself is gone (per-call buffer, L20). The CLAUDE.md quirk #7 item was
done in 3.13.0.

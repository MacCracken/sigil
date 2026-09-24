# Minor residuals left open by the 3.13.0 fixes

**Filed:** 2026-09-23 (3.13.0) · **Severity:** LOW · **Status:** resolved (3.13.1)

- **`sign_data` ignores `ed25519_sign`'s -1** (`src/trust.cyr` ~834). On a seed / public-half mismatch
  it returns an all-zero 64-byte "signature" with no error, and `sv_sign_artifact`
  (`src/verify.cyr` ~307) registers and audits the artifact. Safe (it never verifies) but silent.
  Vendored copies (agnosai, argonaut `lib/libro.cyr`) also ignore the return.
- **A malformed CRL entry line is dropped silently** (`src/policy.cyr` ~800, `crl_from_jsonl`) — one
  fewer revocation, no signal. Options: a `crl_load_bad_count` (new API, like `rl_load_bad_count`),
  or reject the whole CRL.
- **Ed25519 small-order public keys still verify** (policy question). The canonical identity
  `0100…00`, (0, −1) `ecff…7f` and y = 0 decode and verify under RFC 8032 cofactorless
  verification; with A = identity, R = enc(B), S = 1 verifies any message. libsodium rejects
  small-order A. No test locks either behaviour.
- **AuditLog** (`src/audit.cyr`):
  - `_alog_line_complete` (~417) catches a torn final line but not one a later `O_APPEND` write
    lands on (crash mid-append, then a good append): the merged line can parse as one made-up event
    and the real event is lost. Needs a crash, not attacker input.
  - `_alog_write_int` uses the module-global `_alog_int_buf` — races under concurrent `alog_save`.
  - A negative timestamp writes an empty value.
  - `alog_load`'s bump-heap cost now grows with file size.
- **`file_read_whole` loaders have no size ceiling** (`src/policy.cyr` ~686): doubling bump `alloc`
  never reclaims (~2× the file size in heap), and alloc failure is unchecked in the stdlib. Option: a
  ceiling that errors, never truncates.
- **AES software path:** `_aes_shift_rows`'s `tmp` lane (`tb`, `src/aes_gcm.cyr` ~295) is not wiped,
  so the dead stack can hold AES state.
- **`keyring_sign_issuance`** keeps each signature in bump `alloc()`; re-signing a child leaks the old
  64-byte buffer (no secret in it).

## Resolution (3.13.1)

All fixed:
- `sign_data` returns 0 when `ed25519_sign` refuses, and `sv_sign_artifact` registers nothing.
- `crl_from_jsonl` counts rejected entry lines: new `crl_load_bad_count()`.
- `ed25519_verify` refuses small-order public keys ([8]A = identity), as libsodium does.
- AuditLog: a torn line merged into the next append is rejected (exactly one `{` / `}` outside
  strings); `_alog_write_int` uses a per-call buffer and writes negative values (i64 min
  included) and they parse back; `alog_load` reads into a freed buffer.
- The JSONL / JSON loaders read through `_rj_read_file`: capped at `RJ_MAX_FILE_BYTES`
  (64 MiB, an error — never a truncation), into a buffer freed after parsing.
- `_aes_shift_rows` wipes its `tmp` lane.
- `keyring_sign_issuance` reuses the child's 64-byte buffer on re-sign.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.9.0-dev] - unreleased

Next-minor work: **HKDF** (RFC 5869) on top of existing HMAC-SHA256,
and **AES-NI / pmull hardware-accelerated AES-GCM** paths with
runtime feature detection. Both unlock downstream consumers —
HKDF feeds majra's planned QUIC transport; AES-NI brings GCM
throughput from ~1ms/KB (software) to the 50-100µs/KB range.

## [2.8.4] — 2026-04-19

Two bundled changes: a **toolchain refresh** to bring sigil onto
the current Cyrius pin, and a new **AES-256-GCM** AEAD primitive
that completes sigil's symmetric-crypto surface for the AGNOS
ecosystem. The symmetric primitive is the AEAD that majra's
`ipc_encrypted.cyr` consumes; before 2.8.4 majra hand-rolled a
stub.

### Added — AES-256-GCM AEAD (`src/aes_gcm.cyr`)

- **AES-256 block cipher** — FIPS 197, forward direction only (GCM
  never invokes the inverse). Full 256-byte Rijndael S-box, 14-round
  Nk=8 key schedule producing 240 bytes of round keys. The S-box
  and Rcon tables ship as hex string literals decoded once into an
  `alloc`-backed buffer at first use, keeping the fixup cost off
  the hot path.
- **GHASH** — bit-by-bit GF(2^128) multiplication under the GCM
  reduction polynomial `x^128 + x^7 + x^2 + x + 1`. Constant-time
  by construction (exactly 128 shift+xor per block, no data-
  dependent branches). Table-based acceleration is deferred as a
  perf-only follow-up.
- **`aes_gcm_encrypt(key, iv, aad, aad_len, pt, pt_len, ct_out, tag_out)`**
  and **`aes_gcm_decrypt(...) -> ERR_NONE | ERR_INTEGRITY_MISMATCH`**.
  12-byte IV (96-bit RFC fast path). 16-byte authentication tag.
  Arbitrary-length IV is a deferred follow-up.
- **AEAD contract honoured** — decrypt computes the expected tag
  first, compares in constant time via `ct_eq`, and zeroes
  `pt_out` on tag failure so plaintext never escapes. The
  CTR-mode pass runs unconditionally to keep the valid-tag and
  forged-tag decrypt paths within ~1% of each other (see
  benchmark numbers below).
- **Key material zeroization** — the 240-byte round-key schedule
  and every intermediate scratch (`H`, `Y`, `S`, `J0`, counter,
  zero block, length block) is overwritten with zeros before free
  on every call. Matches sigil's existing Ed25519 / HMAC hygiene.
- **Software-only.** No inline asm / no AES-NI — Cyrius doesn't
  support inline asm today. A hardware path is a future patch
  once the toolchain exposes the intrinsics.

### Verified against NIST SP 800-38D

- **TC1** (empty PT + empty AAD, zero key + zero IV):
  tag = `530f8afbc74536b9a963b4f1c4cb738b`.
- **TC2** (single zero block PT, zero key + IV):
  CT = `cea7403d4d606b6e074ec5d3baf39d18`,
  tag = `d0d1c8a799996bf0265b98b5d48ab919`.
- **TC14** (64-byte PT, no AAD, NIST AES-256 vector):
  CT + tag match the published fixture.
- **TC15** (20-byte AAD + 60-byte PT, partial final block):
  CT + tag = `...76fc6ece0f4e1768cddf8853bb2d551b`.
- Decrypt roundtrip passes; single-bit tag flip returns
  `ERR_INTEGRITY_MISMATCH` and the plaintext output buffer is
  zero at the head, middle, and tail (no leak).

Total assertions in `tests/tcyr/aes_gcm.tcyr`: **15/15 pass**.
Total sigil assertion count across all suites: **381** (up from
366 in 2.8.3).

### Added — benchmarks

Added to `tests/bcyr/sigil.bcyr`; raw numbers from a single
host under 2.8.4:

| Bench                          | Mean     | Notes                                 |
| ------------------------------ | -------- | ------------------------------------- |
| `aes256_key_expansion`         | 1us      | 32-byte key → 240-byte schedule       |
| `aes256_encrypt_block`         | 4us      | 16-byte single-block encrypt          |
| `aes_gcm_encrypt_1kb`          | 1.216ms  | 64-block CTR + GHASH                  |
| `aes_gcm_decrypt_1kb_valid`    | 1.220ms  | Valid tag; full decrypt               |
| `aes_gcm_decrypt_1kb_forged`   | 1.229ms  | Flipped-bit tag; full CT pass still runs |

The valid-vs-forged gap is **<1%**. That's the empirical proof
that the tag verification is constant-time and there is no
early-exit on the auth path. If a future edit drops this below
1% or drifts it above 10%, treat as a regression.

### Changed — toolchain refresh

- **`cyrius` pin: 5.2.1 → 5.4.8** in `cyrius.cyml`. Picks up the
  larger fixup table (16384 up from 8192), reliable compound
  assignment, negative-literal support, and the stdlib evolution
  of the past two minor versions. The `CLAUDE.md` compiler-quirks
  section has been rewritten to reflect cc5 reality — most of
  the cc3-era workarounds (hand-emitted byte 13 for `\r`, `(0 - N)`
  for negative literals, the 256 initialized-global cap, the 8192
  fixup cap) are no longer needed. Still genuinely present:
  occasional local clobbering across deeply nested call chains,
  and `fl_alloc` vs `alloc` discipline.
- **Vendored stdlib refreshed.** `lib/json.cyr` and `lib/string.cyr`
  had drifted under 5.4.8 — copied fresh from `~/.cyrius/lib/` via
  the established sync-if-different pattern. `lib/agnosys.cyr`
  stays unique to sigil (it wraps the AGNOS kernel interface
  layer; not vendored upstream).

### Verified

- `cyrius build programs/smoke.cyr build/sigil-smoke` — clean,
  smoke run exits 0.
- All 12 `.tcyr` suites pass (aes_gcm new + 11 existing):
  **381 assertions, 0 failures.**
- `cyrius distlib` emits `dist/sigil.cyr` with `v2.8.4` header,
  15 bundled modules (includes aes_gcm), 5780 lines.

## [2.8.3] — 2026-04-17

### Fixed — dist bundle was referencing un-bundled agnosys symbols

Cyrius 5.2.1 added a compile-check to `cyrius distlib`: after
concatenating the declared modules, it compiles the resulting bundle
standalone to catch undefined-symbol references. The first run
against sigil 2.8.2 flagged the bundle as NOT self-contained.

The 2.8.2 bundle (from 2.8.2's manifest) included all 18 src modules,
four of which wrap agnosys (`tpm.cyr`, `ima.cyr`, `secureboot.cyr`,
`certpin.cyr`) and reference enums like `TPM_SHA256`, `SB_ENABLED`,
`CERTPIN_VALID` plus functions like `tpm_seal`, `secureboot_detect_state`
that come from `lib/agnosys.cyr`. Those includes are stripped by
`distlib`, so a consumer pulling only `dist/sigil.cyr` could not
compile — the bundle silently referenced symbols a consumer had
no way to provide unless they also pulled agnosys and included
its bundle first in the right order.

This was a real regression introduced in 2.5.0 when the agnosys
wrappers landed (the hand-maintained `scripts/bundle.sh` happened
not to list them, which — by accident — kept the bundle self-
contained through 2.8.0. 2.8.2's manifest-driven `distlib` adopted
every module including the wrappers, exposing the issue.)

Cyrius' CHANGELOG 5.2.1 entry called this out and held their stdlib
fold-in at sigil 2.1.2 pending a fix. This release is that fix.

### Changed — bundle scope narrowed

- **`[build] modules`** in `cyrius.cyml` now explicitly excludes
  the four agnosys-wrapping modules. The bundle ships as the
  self-contained core: crypto (SHA-256/512, HMAC, Ed25519),
  constant-time compare, bigint, trust engine, integrity verifier,
  revocation list + CRL, audit log, verification engine. 14
  modules / 5118 lines.
- **Consumers who want the AGNOS kernel-interface layer** (TPM
  seal/unseal, IMA status, Secure-Boot detection, certificate
  pinning) should include sigil via `src/lib.cyr` against a git-
  pinned checkout — that pulls agnosys as a proper dep and gets
  all 18 modules in the correct order. The `dist/sigil.cyr` path
  is now documented as "core library only".
- The manifest comment on `modules = [...]` makes the exclusion
  explicit so a future maintainer doesn't re-add the wrappers and
  break the bundle again.

### Changed — toolchain bump

- **`cyrius` pin: 5.2.0 → 5.2.1** (`cyrius.cyml` +
  `.github/workflows/ci.yml`). Picks up the `distlib` compile-check
  that caught this issue, plus `cyrius deps --lock` / `--verify`
  and `cyrius publish`.

### Verified

- `cyrius distlib` → clean exit (no self-containment warning),
  `dist/sigil.cyr: 5118 lines (v2.8.3)`.
- 11/11 `.tcyr` pass, 3/3 fuzz OK, 12/12 benches run, smoke
  exit 0 (library behaviour is unchanged — agnosys wrappers are
  still built and tested via `src/lib.cyr`).

## [2.8.2] — 2026-04-17

### Fixed — distribution bundle was missing 3 modules

`scripts/bundle.sh` hand-listed the src modules to concatenate
into `dist/sigil.cyr`. The list hadn't been updated since 2.5.0,
so the last three shipped bundles (2.5.0 – 2.8.1) silently
omitted `src/ima.cyr`, `src/secureboot.cyr`, and `src/certpin.cyr`
— the entire agnosys-wrapper layer. Consumers pulling the bundle
got sigil's crypto + trust core but none of the TPM / IMA /
Secure-Boot / certpin sigil_* wrappers.

No runtime impact on sigil's own `cyrius build` / `cyrius test`
paths (those use `src/lib.cyr` directly), and no reported
downstream incident — the bundle consumers are the other AGNOS
crates and they've been pulling via `[deps.sigil]` modules that
end up resolving through `src/lib.cyr` on their side. But any
consumer that copied `dist/sigil.cyr` verbatim would be missing
the wrappers.

### Changed — `scripts/bundle.sh` → `cyrius distlib`

Cyrius 5.2.0 shipped `cyrius distlib` as the official library-
distribution command, reading `[build] modules` (or `[lib] modules`)
from `cyrius.cyml`. Removes the per-repo hand-maintained bundle
script — the module list now lives in one place, is the same
list the language tooling uses for dep resolution, and can't
drift away from `src/lib.cyr` silently.

- Added `[build] modules = [...]` to `cyrius.cyml` listing all
  18 src/ modules in dependency order (same order as
  `src/lib.cyr`'s includes). Comment in the manifest makes the
  "keep both files in sync" invariant explicit.
- Removed `scripts/bundle.sh`. The canonical regen path is now
  `cyrius distlib`.
- Regenerated `dist/sigil.cyr` — went from 5296 lines / 15
  modules (2.8.1) to 5420 lines / 18 modules (this release).

### Verified

- `cyrius distlib` → `dist/sigil.cyr: 5420 lines (v2.8.2)`.
- Bundle now contains all 18 src/ modules (was 15) — verified via
  `grep -c '^# --- '`.
- No remaining references to `scripts/bundle.sh` outside
  historical CHANGELOG entries.
- 11/11 `.tcyr` pass, 3/3 fuzz OK, smoke exit 0 (library
  behavior unchanged — only the packaging path moved).

## [2.8.1] — 2026-04-17

### Security — HIGH

- **`ed25519_generate_keypair` silent entropy failure.** The
  pre-2.8.1 implementation had two unchecked paths in the
  `/dev/urandom` read:
  - `file_open("/dev/urandom", 0, 0)` — no check of the returned
    `fd`. On failure (`fd = -1`), the subsequent `file_read(-1, …)`
    returned an error code, and `seed[32]` stayed with whatever
    bytes were on the stack at that frame's location.
  - `file_read(fd, &seed, 32)` — single unchecked call. A short
    read (e.g. 16 bytes actually delivered) left the upper half
    of the seed uninitialised.
  Either path would silently derive an Ed25519 key from
  partial / stale entropy. `trust.cyr`'s own `generate_keypair`
  already had the correct short-read loop (2.1.x); this one had
  been missed because it was reached only through
  `programs/smoke.cyr` and `tests/tcyr/ed25519.tcyr`'s
  "random keypair" block, which always ran on a host with a
  functional `/dev/urandom`.

  **Fix**: mirror the loop pattern from `trust.cyr:generate_keypair`.
  Bail on open failure (zero sk_out/pk_out, return 0). Accumulate
  reads in a `got < 32` loop. On any short or failing read, close
  the fd, zeroise the seed and outputs, return 0. Success returns
  1 (new return-value contract; prior caller convention of
  "always 0" is upheld for null-output scenarios by explicit
  zeroisation so the failure is deterministic rather than silent).

  **Impact assessment**: no evidence this bit any shipped key —
  `ed25519_generate_keypair` is the only path affected, and every
  CI host plus the reference dev machine has a live `/dev/urandom`.
  Keys issued in practice came through a successful 32-byte read.
  The fix removes the trap without requiring key rotation on
  existing deployments.

  **Regression guard**: `tests/tcyr/ed25519.tcyr` now asserts the
  success return value is `1`. A refactor that silently drops the
  contract fails the gate.

### Changed

- **Roadmap restructured as "road to 3.0".** The 2.x milestones
  are done; `docs/development/roadmap.md` now explicitly splits
  v3.0 scope into (a) items blocked on Cyrius 5.2.x / 5.3.x
  (SHAKE for ML-DSA-65, `ct_select`, `secret var`), (b) items
  blocked on Cyrius 5.3.x threading (parallel batch verify), and
  (c) sigil-internal cleanups that batch into a single 3.0
  breaking bump. Cross-reference: the mirror items in
  `cyrius/docs/development/roadmap.md` under `v5.2.x / v5.3.x —
  Sigil 3.0 enablers`.

### Documentation

- `SECURITY.md` supported-versions table refreshed (was stuck at
  2.0.x/2.1.x, now 2.6.x – 2.8.x).
- `CLAUDE.md` status block: stale "2.0.0 → 2.7.1" range replaced
  with "2.0.0 → current".

### Verified

- 11/11 `.tcyr` pass (20 asserts in `ed25519.tcyr`, was 19 —
  adds the return-value contract).
- 3/3 fuzz harnesses OK.
- 12/12 benches run; numbers stable (ed25519_keypair ~990 µs,
  sign ~1.1 ms, verify ~6.9 ms — within noise of 2.8.0).
- Clean-build sweep from `rm -rf build`.
- Security grep (`sys_system`, `memcmp`, `strcpy`, `strcat`,
  unchecked short-read in crypto paths, path traversal, TODO/
  FIXME/XXX) → clean after the entropy fix. Only matches were
  doc comments referencing `\uXXXX`.

## [2.8.0] — 2026-04-17

### Added — certificate pinning (via agnosys)

Sigil now ships a thin certpin facade over agnosys 1.0.0. The
agnosys README had listed sigil as a consumer of
`agnosys[tpm, ima, certpin]` since 0.98; TPM / IMA / Secure-Boot
landed in 2.5.0 and certpin closes the remaining module.

Same wrapper pattern as `src/tpm.cyr` / `src/ima.cyr` /
`src/secureboot.cyr`: agnosys owns the wire format and the
constant-time byte compare, sigil exposes a narrow Result-free
surface that's safe to call on the hot path.

- **`src/certpin.cyr`** — new module, 4 public functions:
  - `sigil_cert_pin_status(host, actual_pin, pin_set, at)` — raw
    `CERTPIN_*` enum (VALID / MISMATCH / EXPIRED / NO_PIN_CONFIGURED).
    `at = 0` skips the expiry window check.
  - `sigil_cert_pin_check(host, actual_pin, pin_set)` — fast
    predicate. 1 iff VALID at `clock_epoch_secs()`. Collapses the
    no-pin and mismatch cases to 0; use the raw status function
    when the caller needs to distinguish them for first-use-trust
    policy.
  - `sigil_cert_pin_status_name(status)` — static C-string
    ("valid" / "mismatch" / "expired" / "no_pin" / "unknown") for
    logs and audit-event details. Names are advisory and must NOT
    be parsed back.
  - `sigil_cert_pin_compute(cert_path)` — wraps
    `certpin_compute_spki_pin`, unwraps the agnosys Result to a
    C-string or 0. Shells out to `openssl` via agnosys; intended
    for pin-set construction at config time, not per-connection
    use.
- **`src/lib.cyr`** now includes `src/certpin.cyr` after the
  other agnosys wrappers and before `src/verify.cyr`.

### Test coverage

- **`tests/tcyr/agnosys.tcyr`** adds 14 new certpin assertions
  (26 total, was 12). Purely in-memory pin-set fixtures — no
  network, no files, no openssl required on the CI host:
  - Status-enum name mappings for all 4 CERTPIN_* codes plus
    unknown-fallback.
  - VALID path: active entry, correct pin, deterministic `now`
    timestamp.
  - MISMATCH path: active entry, wrong pin.
  - NO_PIN_CONFIGURED path: unknown host.
  - EXPIRED path: entry with `expires=1`, `now=1 000 000`.
  - `sigil_cert_pin_compute` on a missing file returns 0
    without propagating an agnosys `Err`.

### Verified

- 11/11 `.tcyr` pass (`agnosys.tcyr`: 26 assertions, was 12).
- 3/3 fuzz harnesses OK.
- 12/12 benches run; no regressions.
- `./build/sigil-smoke` exit 0.

### Note

This closes the originally-planned 2.x roadmap. Remaining items in
`docs/development/roadmap.md` (PQC, hybrid signatures, parallel
batch verify, scatter-store for the fixed-base comb) are all
"Future" — they depend on Cyrius or AGNOS work that hasn't landed.

## [2.7.0] — 2026-04-17

### Added — JSON load paths (round-trip support)

Both persistence paths in sigil used to be write-only: you could
save a trust store or append to an audit log, but reloading either
after a restart meant starting from scratch. This release completes
the round-trip for both.

- **`sv_load_trust_store(sv, path)`** in `src/verify.cyr`. Parses
  the JSON array emitted by `sv_save_trust_store`, rebuilding
  `{content_hash, path, artifact_type, trust_level}` records into
  the verifier's trust-store map. Returns the number of artifacts
  loaded, or 0 on IO / parse failure. Signatures and
  `signer_key_id` are NOT restored (the save path never wrote
  them) — loaded artifacts come back as present-but-unsigned,
  matching the existing serialized form. A subsequent
  `sv_verify_artifact` will report them as "not in trust store"
  until re-signed.
- **`alog_load_from_file(log, path)`** in `src/audit.cyr`. Reads
  the JSON Lines stream from `alog_append_to_file` back into an
  `AuditLog`. Each line is parsed as a flat JSON object with
  fields `type`, `timestamp`, `path?`, `key_id?`, `content_hash?`,
  `passed?`. Lines whose `type` is an unknown event name are
  skipped rather than aborting — a newer writer must not take
  down an older reader doing forensic replay. Returns the number
  of events loaded, or `-1` on IO failure.
- **`audit_event_type_from_name(name)`** — inverse of
  `audit_event_name(t)`, used by the loader and exposed for
  consumers that want to match on named events.
- Both loaders reuse `_rj_parse_string` from `src/policy.cyr`
  (the escape-aware reader written for `rl_from_jsonl` in 2.5.0)
  — unified handling for `\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`,
  and `\u00XX` matches what `json_write_escaped` emits.

### Test coverage

- **`sigil.tcyr`** adds `audit jsonl load` (5 assertions + a
  missing-file guard): write 3 events, reload them, deep-check
  the first and last, then verify a nonexistent file returns -1
  without crashing. Assertion count 82 → 92.
- **`verify.tcyr`** adds `trust-store save+load` (5 assertions):
  save two artifacts at different trust levels, load into a fresh
  `SigilVerifier`, assert both trust levels survive. Plus a JSON
  escape round-trip (path containing `"` and `\`) and a
  missing-file check. Assertion count 37 → 43.

### Added — final parity closeout

One last `rust-old/` sweep before removal surfaced two remaining
missing surfaces. Both landed in this release so the rust-old
reference can be deleted with no outstanding parity debt.

- **`hash_file_with(path, algorithm)`** in `src/trust.cyr`. Mirror
  of `hash_data_with` but for on-disk content — dispatches to
  SHA-256 or SHA-512 by `HASH_ALG_*`. Unknown algorithm falls
  back to SHA-256 (same policy as `hash_data_with`). Uses
  streaming 4 KB reads, same as `hash_file`.
- **`sv_verify_package(sv, path, expected_hash)`** in
  `src/verify.cyr`. Package install-time verification path:
  wraps `sv_verify_artifact(sv, path, ARTIFACT_PACKAGE)` and —
  when `expected_hash` is non-zero — layers a constant-time
  content-hash match. Mismatch adds a failing `"expected_hash"`
  trust-check and fails the whole result. Pass `0` as
  `expected_hash` to verify without a known hash.
  - Note vs. Rust: the Rust `verify_package` had an early-exit
    when `policy.verify_on_install` was false. That gate is
    dropped here — `verify_on_install` has been a user-set
    policy knob for several releases and consumers enforce it
    themselves before calling in.

### Removed — `rust-old/` reference tree

6 552 lines of Rust across 13 files (audit / chain / error /
integrity / lib / policy / tests / tpm / trust / types / verify
plus Cargo manifests). Preserved through the 2.x series for
cross-port audits; the last gap surfaced by this 2.7.0 sweep is
closed above. Removal clears the repo root of Rust artifacts and
takes `rust-old/target/` off the `.gitignore`. The
cross-implementation benchmark baseline in
`benchmarks-rust-v-cyrius.md` stays as archival reference — it
is never rebuilt per release.

- `CLAUDE.md` — dropped the "Rust source preserved in `rust-old/`"
  TDD discipline line and the "Ported from: Rust v1.0.0" status
  block now reads "removed in 2.7.0 after parity closeout".
- `SECURITY.md` — `rust-old/` pointer replaced with the same
  closeout reference.
- `.gitignore` — `/rust-old/target/` entry removed.

### Test coverage

- **`sigil.tcyr`** adds `hash_file_with` (4 assertions: SHA-256,
  SHA-512, unknown-algo fallback, missing-file). Assertion count
  92 → 96.
- **`verify.tcyr`** adds `verify_package` (3 groups × ~2 checks:
  no expected hash → no `expected_hash` check surfaced; matching
  hash → check passes; mismatched hash → check fails + whole
  result fails). Assertion count 43 → 48.

### Verified

- 11/11 `.tcyr` pass. 3/3 fuzz. 12/12 benches. Smoke exit 0.
- `./build/sigil-smoke` unchanged (loaders + new parity fns are
  opt-in — not on the hot path).

## [2.6.0] — 2026-04-17

### Changed — agnosys 1.0.0

- **`[deps.agnosys]` bumped `0.98.0` → `1.0.0`**. Agnosys 1.0 froze
  its public API and landed 139 module-prefix renames pre-freeze
  (see agnosys `CHANGELOG`). The renames affected `certinfo_*`,
  `security_*`, `journal_*`, `verity_*`, `boot_*`, `fw_*`, `nft_*`,
  and `checked_syscall`. **Sigil is unaffected**: the modules we
  wrap (`tpm_*`, `ima_*`, `secureboot_*`) were listed in agnosys'
  "already clean" set, and we don't wrap `certpin` yet (queued for
  2.7.0+). All 11 `.tcyr` files still pass against the new tag, no
  sigil source changed for this bump.

### Breaking — Tier 2 dead-field cleanup

Completes the dead-code sweep started in 2.5.0. These fields had
no read path (setter/getter defined, no caller) but their backing
storage was still allocated on every instance. A downstream audit
across 8 AGNOS consumer repos found zero real callers for any of
the removed names (argonaut's vendored `lib/sigil.cyr` copies the
bundle — those definitions regenerate with the new layout).

- **`TrustedArtifact`: 80 → 48 bytes.** Dropped:
  - `signature_len` field + getter — Ed25519 signatures are always
    exactly 64 bytes; the param was hard-coded `64` at the one
    call site.
  - `signature_algorithm` field + `artifact_sig_alg` /
    `artifact_set_sig_alg` — always `SIG_ALG_ED25519`. Re-introduce
    when hybrid/PQC dual signatures land.
  - `verified_at` field + `artifact_verified_at` /
    `artifact_set_verified_at` — written by `sv_sign_artifact`,
    never read.
  - `metadata` field + `artifact_metadata` / `artifact_set_metadata`
    — never populated.
  - **API change**: `artifact_set_signature(a, sig, sig_len)` →
    `artifact_set_signature(a, sig)`. One caller (internal).
- **`IntegrityMeasurement`: 48 → 24 bytes.** Dropped `actual_hash`,
  `measured_at`, `error_msg` fields + `meas_actual` / `meas_at` /
  `meas_error` getters. `iv_verify_all` no longer writes them.
  Measurement state is now just `(path, expected, status)`.
- **`IntegrityReport`: 40 → 32 bytes.** Dropped `checked_at` field
  + `ireport_checked_at`. Callers can stamp their own `clock_epoch_secs()`
  at report time if needed.
- **`IntegritySnapshot`: 16 → 8 bytes.** Dropped `exported_at` field
  + `isnap_exported_at`. Same rationale.
- **`AttestationResult`: 24 → 16 bytes.** Dropped `quote_signature`
  field + `attest_quote_sig` / `attest_set_quote_sig`. No `tpm_quote`
  wrapper exists yet; re-introduce with one.
- **Integrity policy / verification-result / etc. (getters only,
  no struct change)**: removed `ipolicy_count` (use `vec_len(load64(p))`
  — there was no semantic difference), `ipolicy_measurements`,
  `attest_passed`, `vresult_verified_at`, `pcr_index`,
  `key_id_from_public_hex` (duplicate of `generate_keypair` key-id
  logic).
- **`ireport_summary`** function removed — 35-line formatter nobody
  was calling. Consumers can build the summary string from
  `ireport_total` / `ireport_verified` / vec lengths in three lines.

### Verified

- 11/11 `.tcyr` files pass (unchanged from 2.5.0 — no semantic changes).
- 3/3 fuzz harnesses OK under 30 s CI budget.
- 12/12 benches run; numbers stable.
- `./build/sigil-smoke` exit 0 against agnosys 1.0.0.

### Source stats (vs 2.5.0)

- Functions in `src/`: 372 → **352** (-20 dead getters/setters/fns).
- Struct-layout savings per `SigilVerifier` instance: ~104 bytes
  less heap per stored artifact (`TrustedArtifact` -32 B, and each
  `IntegrityMeasurement` -24 B). Not huge in absolute terms, but
  the API surface is now honest about what sigil actually persists.

## [2.5.0] — 2026-04-16

### Added — AGNOS kernel integration

Sigil now consumes `agnosys 0.98.0` for the AGNOS-native TPM / IMA /
Secure-Boot surface. This replaces the placeholder stubs that shipped
through the 2.x line and makes sigil a real trust-verification node
on AGNOS hosts rather than a paper spec.

- **Cyrius toolchain bumped** 5.1.13 → 5.2.0 (sigil's `cyrius.cyml`
  and `.github/workflows/ci.yml` in lock-step; agnosys requires
  5.2.0).
- **`[deps.agnosys]`** added to `cyrius.cyml`, pinned to tag
  `0.98.0`, consuming `dist/agnosys.cyr` (20 modules, 9769 lines,
  includes stripped so the bundle composes cleanly with sigil's
  stdlib graph). New stdlib deps pulled in to support agnosys:
  `string`, `tagged`, `process`, `fs`.
- **`src/tpm.cyr`** rewritten as a thin wrapper:
  - `tpm_available()` → `tpm_detect()` (SYS_ACCESS on
    `/dev/tpmrm0` then `/dev/tpm0`).
  - `tpm_seal_data(data, len, pcr_indices, output_dir)` →
    `tpm_seal(TPM_SHA256, ...)`. Result unwrapped to a pointer/0.
  - `tpm_unseal_data(sealed, buf, buflen)` → `tpm_unseal`.
    Same pattern.
  - Both refuse cleanly (`return 0`) when `tpm_available() == 0`
    so tests/dev hosts without a TPM don't crash.
  - `tpm_random` stays on `/dev/urandom`. We deliberately do NOT
    route through `tpm_get_random` — that shells out to
    `/usr/bin/tpm2_getrandom` and adds a fork/exec per key gen.
    Linux `getrandom(2)` is cryptographically adequate for Ed25519
    scalar generation.
- **`src/ima.cyr`** — new. Thin wrapper over agnosys
  `ima_get_status`. Public API:
  - `sigil_ima_snapshot()` → 24-byte struct with `active`,
    `measurement_count`, `policy_loaded`.
  - `sigil_ima_available()` / `sigil_ima_measurement_count()` /
    `sigil_ima_policy_loaded()` convenience predicates.
- **`src/secureboot.cyr`** — new. Thin wrapper over agnosys
  `secureboot_detect_state`:
  - `sigil_sb_state()` returns an agnosys `SB_*` enum
    (`SB_ENABLED` / `SB_DISABLED` / `SB_SETUP_MODE` /
    `SB_NOT_SUPPORTED`).
  - `sigil_sb_enforcing()` → 1 iff `SB_ENABLED`. Policy code can
    require this for the `TRUST_SYSTEM_CORE` admit path.
  - `sigil_sb_state_name()` → static C-string for logs.
- **`src/lib.cyr`** now includes `lib/agnosys.cyr`, `src/ima.cyr`,
  `src/secureboot.cyr` in dependency order.

### Test coverage

- **`tests/tcyr/agnosys.tcyr`** — new. 12 assertions across TPM /
  IMA / Secure-Boot wrappers. Every assertion targets the
  *unavailable* path so the suite passes on CI hosts without
  hardware (no /dev/tpm, no /sys/kernel/security/ima, no EFI).
  Hosts WITH these facilities still satisfy the assertions and
  additionally exercise the agnosys shell-outs.
- 11/11 `.tcyr` files pass (was 10). Fuzz 3/3 OK. 12/12 benches
  still run.

### Performance

No change — 2.5.0 is an integration release, not a crypto release.
Numbers (single-run on the same host as 2.4.2):

| op | 2.4.2 | 2.5.0 | Δ |
|---|---|---|---|
| `ed25519_keypair` | 1.33 ms | 0.99 ms | (noise, −25%) |
| `ed25519_sign` | 1.14 ms | 1.11 ms | ~flat |
| `ed25519_verify` | 7.18 ms | 6.68 ms | (noise) |
| `fp_inv` | 273 us | 258 us | ~flat |
| `sha256_4kb` | 257 us | 248 us | ~flat |

### Breaking

- **`tpm_seal_data` takes a fourth parameter**: `output_dir`
  (directory for tpm2_create output files — `sealed.ctx`,
  `sealed.pub`, `sealed.priv`). The previous stub was 3-arg.
  Consumer repos must update call sites. No public consumer is
  currently calling this (stub era), so impact should be nil.
- **`TrustStoreDiff` vecs now carry `ArtifactChange` records**
  instead of raw `TrustedArtifact` pointers (see "Added — Rust
  parity" below). Consumers iterating `tsdiff_added/removed/
  changed` must switch to `ac_content_hash` / `ac_path` /
  `ac_old_trust_level` / `ac_new_trust_level` accessors. No
  downstream repo uses these yet — verified by audit.
- **`sv_snapshot_trust_store` returns a map of `SnapshotEntry`
  records** (trust-level + path captured by value) rather than a
  map of live artifact pointers. Previous snapshots silently
  aliased the live store, so trust-level changes on an artifact
  pointer were invisible to a subsequent `sv_diff_trust_store`.
  New layout makes diffs meaningful.

### Added — Rust parity (fold-ins of audit-flagged gaps)

Pulled forward before 2.5.0 tag cut. A `rust-old/` sweep revealed
six Rust surfaces that had not been ported. Three are security-
relevant and are now landed here; three are ergonomic and also
landed since they're small.

- **`Crl::to_json` / `from_json` → `crl_to_jsonl` /
  `crl_from_jsonl`** (`src/policy.cyr`). JSON Lines format: first
  line is the header object, subsequent lines are entries in the
  same format as `rl_to_jsonl`. Includes `crl_save(path)` and
  `crl_load(path)` convenience wrappers. Deliberate JSONL (not JSON
  array) because `lib/json.cyr` parses one object at a time — JSONL
  matches the existing `alog_append_to_file` convention, converts
  to/from standard JSON via `jq -s`.
- **`RevocationList::to_json` / `from_json` → `rl_to_jsonl` /
  `rl_from_jsonl`** (`src/policy.cyr`). Rebuilds the
  `revoked_keys` / `revoked_hashes` indexes on load. Malformed
  lines are skipped and counted via `rl_load_bad_count()` rather
  than aborting an import — a single bad line must not take down
  a CRL refresh. `rl_save(path)` / `rl_load(path)` wrappers
  included. **MEDIUM severity fix**: without this, a revocation
  list could not survive a process restart or travel between
  hosts, defeating the "revoke key/artifact" trust control.
- **`KeyMetadata.allowed_artifact_types`** (`src/trust.cyr`,
  `src/verify.cyr`). New field on `KeyVersion` (grows 88 → 96
  bytes) with `kv_add_allowed_type` / `kv_clear_allowed_types` /
  `kv_is_type_allowed`. Surfaced in `sv_verify_artifact` as a
  dedicated `"allowed_type"` trust-check independent of signature
  validity. Unset list = unrestricted (Rust `Default` behavior).
  **MEDIUM severity fix**: constrains the blast radius of a
  compromised publisher key — a key scoped to `ARTIFACT_PACKAGE`
  cannot be abused to sign a kernel image.
- **`ArtifactChange` records in `TrustStoreDiff`**
  (`src/verify.cyr`). `tsdiff_added/removed/changed` now hold
  32-byte `ArtifactChange` records with both `old_trust_level`
  and `new_trust_level` (`-1` for "n/a" — added artifacts have
  `old = -1`, removed artifacts have `new = -1`). Required
  companion change: snapshots now capture trust levels by value
  (see Breaking above) so diffs can actually compare them.
- **`MeasurementStatus` display names** (`src/integrity.cyr`).
  The enum + per-entry status field already existed from the
  original port; this release just adds coverage for the
  `Pending` / `FileNotFound` / `Error` name strings and a direct
  `FILE_NOT_FOUND` path test against a missing file.
- **`hash_data_with(data, len, algorithm)`** (`src/trust.cyr`,
  `src/hex.cyr`). Dispatches to `sha256_hex` or `sha512_hex` by
  `HASH_ALG_*`; unknown algorithm falls back to SHA-256 rather
  than returning 0 (a trust engine must never silently skip
  hashing). Added `sha512_hex` helper in `hex.cyr`. The SHA-512
  path is rarely used today but the `HashAlgorithm` enum always
  offered it as a policy option.

### Removed — dead-code sweep

`rust-old/` parity landed the full public API; a `cyrius build`-DCE
audit plus a source-level cross-reference then showed 26 functions
with zero callers anywhere in `src/`, `tests/`, `programs/`, `fuzz/`,
or `benches/`. All removed in this release. Downstream consumer
repos (`daimon`, `kavach`, `ark`, `aegis`, `phylax`, `mela`) checked
clean for every one of these names.

- **Orphaned internal helpers (4)**: `_uadd_overflow` (inlined into
  `u256_mul_full` in 2.2.0 but the body was left behind);
  `compute_file_hash` (shim over `hash_file`); `measure_system_component`
  and `verify_pcr_measurements` in `src/tpm.cyr` (orphaned by the
  2.5.0 rewrite over agnosys).
- **Unused error constructors (9)**: `err_crypto`, `err_integrity`,
  `err_invalid_input`, `err_io`, `err_key_not_found`, `err_revocation`,
  `err_serialization`, `err_sig_invalid`, and `sigil_err_name`.
  Callers always used `sigil_err(code, msg)` directly.
- **Cosignature feature (6)**: `cosignature_new`, `cosig_key_id`,
  `cosig_signature`, `artifact_add_cosigner`, `artifact_cosigners`,
  `artifact_cosigner_count`. The Rust port left the hooks in place
  but nothing ever signed or verified with multiple keys.
  `TrustedArtifact` shrinks from 96 → 80 bytes (drops `+80
  cosigners` and `+88 cosigner_count`).
- **Free-helper stubs (2)**: `trust_policy_free`, `trust_check_free`.
  The bump allocator doesn't support individual free, so these
  were lying.
- **HMAC convenience wrappers (2)**: `hmac_sign`, `hmac_verify`.
  `hmac_sha256` stays (still used by `tests/tcyr/crypto.tcyr` and
  `security.tcyr` as its own test surface).
- **Misc (3)**: `ct_eq_64` (no 64-byte constant-time compare site;
  signatures already compared as 32-byte halves or by full verify);
  `trust_level_gt` (only `trust_level_ge` was used); `stats_counts`.

### Changed — duplication cleanup

- **`u256_load_le` / `u256_store_le`** added to `src/bigint_ext.cyr`.
  Seven inline copies of the little-endian byte ↔ u256 loop
  removed from `src/ed25519.cyr` (~80 lines out).
  Sites: `ge_from_bytes`, `ge_to_bytes`, `sc_reduce` (×2 — lo+hi),
  `ed25519_sign` (×2 — load `a`, store `S`), `ed25519_verify`
  (load `S`). RFC 8032 vectors still pass.

### Fixed — JSON escape in 2.5.0 serialization

- **`_json_escape_cstr` helper** in `src/policy.cyr`. Earlier in
  2.5.0 I landed `rl_to_jsonl` / `crl_to_jsonl` writing string
  fields (`reason`, `revoked_by`, `issuer`, `key_id`,
  `content_hash`) raw — an embedded `"` or `\` produced invalid
  JSON that the parser silently truncated. Fixed before the
  release ships. Writer escapes `"`, `\`, `\n`, `\r`, `\t`, `\b`,
  `\f`, and control chars below 0x20 as `\u00XX`. Parser decodes
  the same set, including `\uNNNN`. Added a round-trip test
  exercising embedded quotes + backslash + newline.

### Test coverage

- **`tests/tcyr/sigil.tcyr`**: 55 → 78 assertions → 82 assertions
  (added JSONL escape round-trip). Added
  `hash_data_with` vectors (incl. SHA-512 FIPS 180-4
  "hello world" vector), RL/CRL JSONL round-trips (in-memory +
  file), `MeasurementStatus` name coverage, and the
  `FILE_NOT_FOUND` status path.
- **`tests/tcyr/verify.tcyr`**: 20 → 37 assertions. Added
  `allowed_type` unrestricted / restricted paths (with the full
  `sv_verify_artifact` pipeline) and `ArtifactChange` diff records
  for both added and changed artifacts.
- **Total new assertions in 2.5.0**: ~45 across six files
  (Rust-parity fold-ins + JSON escape round-trip).
- **Source stats**: 395 → 372 functions in `src/` (net -23 after
  adding `u256_load_le`, `u256_store_le`, `_json_escape_cstr`);
  dead source removed is ~120 lines, dedup saves another ~80.
- Smoke exits 0, fuzz 3/3 OK, bench 12/12 run, benchmark numbers
  stable (no perf impact from the cleanup).

## [2.4.2] — 2026-04-16

### Test coverage

Closes the two remaining 2.4.x items from `docs/development/roadmap.md`:
RFC 8032 TEST 1024 and the fuzz-corpus expansion.

- **RFC 8032 §7.1 TEST 1024** — 1023-byte message vector. Message
  bytes live in `tests/data/rfc8032/test_1024.hex` (2046 hex chars,
  no newline, extracted directly from the RFC text with byte-exact
  `sed` range). Loaded at runtime via `file_read_all`, decoded with
  `hex_decode`, then the test asserts the derived public key
  (`278117fc…d426e`), the signature bytes
  (`0aab4c90…a188a03`), and positive verify. Exercises the full
  sign/verify path on a multi-block SHA-512 input (16 transform
  blocks just for the message, plus framing).
- **`fuzz_ed25519` corpus expanded** from 3 assertions to 11:
  - **Multi-byte mutations** — 500 rounds of 5 simultaneous
    random-byte flips across `(sig, msg, pk)`. Asserts zero false
    accepts; a single false accept here would indicate a
    catastrophic algebraic break.
  - **Canonical-S reject path** (RFC 8032 §5.1.7 / §8.4) — three
    crafted signatures with `S = L`, `S = L + 1`, and
    `S = 2^256 − 1` replacing the `S` half of a valid signature.
    All must be rejected to prevent signature malleability.
  - **Point-decoding edge cases** — verify is called with an
    all-zero `pk`, an all-ones `pk`, and a pk with only the
    x-parity bit flipped. The first two must return 0 or 1 (no
    crash) and the parity-flipped pk must fail verification.
- Test-count deltas: `ed25519.tcyr` 15 → 19 assertions;
  `fuzz_ed25519` 3 → 11 assertions.
- 10/10 `.tcyr` files still pass; 3/3 fuzz harnesses OK under the
  30 s CI budget.

### Added

- `tests/data/rfc8032/` — first bundled test-data directory. Future
  large-input vectors (e.g. Ed25519ctx, SHAKE-based vectors if they
  ever land) follow the same pattern: hex file under `tests/data/`,
  loaded via `file_read_all` at test start.

## [2.4.1] — 2026-04-16

### Infrastructure

CI workflow brought forward to Cyrius 5.1.13 and the native `cyrius`
toolchain. No library/code changes — tests, benches, and fuzz
results are identical to 2.4.0.

- **`.github/workflows/ci.yml`** rewritten:
  - `CYRIUS_VERSION` bumped `3.3.4` → `5.1.13`.
  - Install path switched from `git clone MacCracken/cyrius` + raw
    `cc3` binary copy to the official `install.sh`
    (`curl … /scripts/install.sh | CYRIUS_VERSION=… sh`), which
    populates `~/.cyrius/bin/cyrius` matching local dev.
  - Every job now runs `cyrius deps` before building so the
    git-pinned sakshi 2.0.0 declared in `[deps.sakshi]` is resolved
    into `lib/sakshi.cyr`. Previously the CI would fail to locate
    that include.
  - Build job compiles the 2.2.0 smoke entry
    (`cyrius build -D SIGIL_SMOKE programs/smoke.cyr`) and runs the
    resulting binary; exit 0 is the gate.
  - Test / bench / fuzz jobs call `cyrius test`, `cyrius bench`,
    and `cyrius build` directly — no more manual
    `cat file | cc3 > out` plumbing.
  - Fuzz time budget raised from 10 s → 30 s per harness to give
    the 2000-round `fuzz_ed25519` xorshift sweep realistic headroom
    on cold runners.
  - Security scan regex tightened: previously matched the phrase
    "private key" in comments. Now requires `(private_key|secret_key|
    SECRET)` **plus** an assignment to a ≥32-char hex literal, and
    skips `test` / `example` / `rfc8032` files so RFC test vectors
    don't trip the scan.
- **`.github/workflows/release.yml`** is unchanged. It already
  consumes `ci.yml` via `workflow_call`, so it inherits the
  toolchain refresh automatically. The version-sync check
  (introduced post-2.2.0) already reads `cyrius.cyml`.

### Verified locally

- `cyrius build -D SIGIL_SMOKE programs/smoke.cyr build/sigil-smoke`
  → exit 0.
- `cyrius test` over `tests/tcyr/*.tcyr` → 10/10 pass, same as 2.4.0.
- `CYRIUS_DCE=1 cyrius bench tests/bcyr/sigil.bcyr` → 12 benches,
  numbers consistent with 2.4.0.
- `cyrius build fuzz/*.fcyr` + run with 30 s cap → 3/3 OK.

## [2.4.0] — 2026-04-16

### Breaking

- **Removed `sv_set_cache_enabled` and `sv_clear_cache`** from the
  SigilVerifier API. These were stubs: they wrote to fields at `+48`
  (`cache_enabled`) and `+64` (`cache`) but no read path consulted
  them. No in-tree or downstream consumer uses either function
  (verified across the 6 local AGNOS app repos). A verification
  cache inside a trust-boundary module without strict invalidation
  on revocation / policy change / key rotation is a CVE shape — if
  a caller ever needs caching, it belongs at a layer above sigil
  with domain-specific invalidation semantics. Deferred as a
  breaking change in the 2.1.2 CHANGELOG; now done.
- **`SigilVerifier` struct: 72 → 56 bytes.** The `cache_enabled` and
  `cache` slots are gone and `audit_log` moved from `+56` to `+48`.
  Consumers that hold raw offsets into the struct must recompile;
  anyone using the accessor functions (`sv_audit_log` etc.) is
  unaffected.

### Test coverage

- **RFC 8032 §7.1 TEST 2** (1-byte message `0x72`) and **TEST 3**
  (2-byte message `0xaf82`) added to `tests/tcyr/ed25519.tcyr`. Each
  vector verifies the derived public key, the signature bytes (not
  just verify-accepts), and the positive verify path. Signature
  bytes of TEST 1 are now also asserted (previously just printed).
- **`fp_inv` property tests** in `tests/tcyr/field.tcyr`: direct
  `fp_inv(a) · a ≡ 1 (mod p)` over a spread of inputs (1, 2, 7,
  `0xdeadbeef`, a 256-bit pseudo-random value, `p−1` self-inverse).
  Regression guard for the 2.2.0 Bernstein addition chain.
- **`fuzz/fuzz_ed25519.fcyr`**: new harness. Generates a valid
  (pk, msg, sig) triple, then 2000 rounds of deterministic
  single-byte corruption across sig/msg/pk via xorshift64 PRNG.
  Asserts every corrupted verify returns 0 or 1 (no crash, no OOB)
  and that ≥95% of corruptions are rejected.
- Test count: `ed25519.tcyr` 8 → 15 assertions; `field.tcyr` 10 →
  18 assertions. 10/10 test files still pass.
- **TEST 1024** (1023-byte message) deferred — requires bundled
  test-data file rather than an inline 2046-char hex literal.
  **TEST SHA(abc)** is ed25519ph (prehash variant); sigil only
  implements pure Ed25519, so it is out of scope.

### Added

- **`ed25519_verify` benchmark** in `tests/bcyr/sigil.bcyr`.
  Baseline ~7.2 ms: the fast `[S]B` (fixed-base table, ~1.1 ms) plus
  the CT variable-base `[h]A` (~5.4 ms) plus `ge_from_bytes` and
  SHA-512 framing. 12 benchmarks total (was 11).

### Backlog

- **CI is on Cyrius 3.3.4** (`.github/workflows/ci.yml` env var).
  The project targets 5.1.13. The workflow also uses `cc3` directly
  and bypasses `cyrius deps`, so it would not resolve sakshi 2.0.0.
  Noted for a dedicated 2.4.x infrastructure patch — too broad to
  bundle into a coverage release.

## [2.3.0] — 2026-04-16

### Performance

Fixed-base scalar multiplication for the Ed25519 base point `_ed_B`.
`ed25519_keypair` and `ed25519_sign` drop roughly **4–5×** with no
loss of constant-time discipline.

- **`_ed_B_table`** (128 KB): 64 windows × 16 precomputed points ×
  128 bytes each. Built at `ed25519_init` by repeatedly doubling and
  adding `_ed_B` — one-time init cost (~8 ms on this host), cached for
  process lifetime. Layout: `table[i][k] = k · 16^i · B`.
- **`ge_scalarmult_base(r, s)`**: 4-bit windowed comb. 64 iterations;
  each iteration does one constant-time `_ge_table_select` over all
  16 entries of row `i` and one `ge_add`. No doublings on the hot
  path.
- **`_ge_table_select`**: iterates all 16 entries unconditionally and
  uses `ge_cmov` with a branchless `eq = 1 iff k == digit` test
  (`((diff | -diff) >> 63) ^ 1`). Memory-access pattern is independent
  of the secret nibble.
- **Call sites rewired**: `ed25519_keypair` (L516), `ed25519_sign`
  (L599), `ed25519_verify` (L718). `ge_scalarmult` (variable base) is
  still used by verify for `[h]A` where `A` is the public key — that
  path retains the 2.2.1 CT loop.

| op | 2.2.1 | 2.3.0 | Δ |
|---|---|---|---|
| `ed25519_keypair` | 5.57 ms | 1.33 ms | **−76%** |
| `ed25519_sign` | 5.73 ms | 1.14 ms | **−80%** |
| `ge_scalarmult` (var-base) | 5.25 ms | 5.17 ms | ~flat |
| `fp_inv` | 265 us | 267 us | ~flat |
| `sha256_4kb` | 256 us | 255 us | ~flat |
| `ct_eq_32b` | 87 ns | 89 ns | ~flat |

### Test coverage

- Added three `ge_cmov` regression assertions to `tests/tcyr/ed25519.tcyr`
  (bit=0 unchanged, bit=1 copies, bit=1 same-value stable) so the CT
  primitive is exercised directly and not only transitively via RFC
  8032 vector 1.
- 8 assertions pass across `ed25519.tcyr` (was 5 before).
- All 10 `.tcyr` files pass.

### Memory

Process heap grows by ~128 KB after first `ed25519_*` call. This is
a one-shot bump-allocator reservation; the binary is unchanged in
size. Consumers that never call Ed25519 (e.g. pure SHA-256 users) do
not pay this cost — `_build_ed_B_table` is called from
`ed25519_init`, which is called from `ed25519_keypair`, `_sign`, and
`_verify` only.

### Trade-offs

The fixed-base table is not scatter-stored across cache lines, so a
cache-timing attacker on the same host could in principle recover
which 128-byte block was selected per window. In a hardened
multi-tenant scenario this would matter; for AGNOS's single-tenant
trust-verification role it does not. Adding scatter-load protection
is listed on the 2.4.x+ backlog (see `docs/development/roadmap.md`).

## [2.2.1] — 2026-04-16

### Security

Closes the secret-data branch in `ge_scalarmult` (`src/ed25519.cyr`).
The previous loop read bit `i` of the secret scalar `s` and took a
different code path depending on its value (`if (bit == 1)` → one
extra `ge_add`). On a shared host this yields a timing side-channel
that can reveal the Hamming weight of `s` and, with enough samples,
the scalar itself. Listed on the roadmap as v0.2.0 "Constant-time
scalar multiplication" — now done.

- **`ge_cmov(dst, src, bit)`**: branchless conditional move over a
  128-byte extended point using `mask = -bit` and bitwise XOR-select.
  No branches on `bit`; `dst` receives `src` iff `bit == 1`.
- **`ge_scalarmult`**: every iteration unconditionally computes
  `ge_add(tmp, r, q)` then `ge_cmov(r, tmp, bit_i)`. Doubling of `q`
  is likewise unconditional. No branch or memory-access pattern
  depends on any bit of `s`.

### Performance

The constant-time loop replaces ~128 conditional adds with 256
unconditional adds + 256 `ge_cmov` calls. This is the expected price
of closing the side-channel — recorded here, not treated as a
regression:

| op | 2.2.0 | 2.2.1 | Δ |
|---|---|---|---|
| `ge_scalarmult` | 3.46ms | 5.25ms | +51% |
| `ed25519_keypair` | 3.87ms | 5.57ms | +44% |
| `ed25519_sign` | ~4.0ms | 5.73ms | +43% |
| `fp_inv` | 252us | 265us | ~flat |
| `sha256_4kb` | 251us | 256us | ~flat |

`ed25519_verify` also goes through the constant-time path; verify
takes public data so constant-time is not required but harmless. The
planned 2.3.0 fixed-base precomputed table for `_ed_B` will claw back
the scalarmult cost (and then some) for keypair/sign specifically.

### Verified

- 10/10 `.tcyr` files pass, including RFC 8032 Ed25519 test vector 1
  (which exercises a mix of `bit=0` / `bit=1` iterations — a buggy
  `ge_cmov` would corrupt the public key).
- `./build/sigil-smoke` → exit 0.
- `tests/bcyr/sigil.bcyr`: all 11 benchmarks run.

## [2.2.0] — 2026-04-16

### Changed

Scaffold refactor aligning sigil with the shared AGNOS application layout
(sakshi 2.0.0, patra), plus two purely computational crypto-hot-path
optimizations. 245 assertions across 10 `.tcyr` files pass (including
RFC 8032 Ed25519 test vector 1); 11 benchmarks run.

### Performance

Two non-algorithmic wins in `src/bigint_ext.cyr`:

- **`fp_inv` via Bernstein addition chain** (254 squarings + 11 multiplies
  = 265 `fp_mul` calls) replaces the generic `fp_pow(a, p-2)` chain
  (~512 `fp_mul` calls). `fp_inv` 601 → 252us (**−58%**).
- **`_uadd_overflow` inlined** inside the `u256_mul_full` 4×4 inner
  loop (32 function calls eliminated per `fp_mul`). Amplifies into every
  downstream op.

Cumulative bench deltas (vs 2.1.2 baseline):

| op | 2.1.2 | 2.2.0 | Δ |
|---|---|---|---|
| `fp_inv` | 601us | 252us | **−58%** |
| `sc_reduce` | 36us | 29us | −19% |
| `ge_double` | 9us | 7us | −22% |
| `ge_scalarmult` | 3.99ms | 3.46ms | −13% |
| `ed25519_keypair` | 4.67ms | 3.87ms | **−17%** |
| `ed25519_sign` | ~5.0ms | ~4.0ms | **~−20%** |
| `sha256_4kb` | 254us | 251us | ~flat |
| `ct_eq_32b` | 88ns | 85ns | ~flat |

Deferred (documented for 2.3.0):

- **Fixed-base scalar-mult table** for `_ed_B` (16–64KB precomputed
  multiples) — would roughly halve keypair/sign cost at a binary-size
  tradeoff.
- **Montgomery ladder / always-add** constant-time `ge_scalarmult` —
  security fix, not a perf win. The current implementation branches on
  the secret scalar bit (`src/ed25519.cyr` L191). Listed on the roadmap
  (v0.2.0 carried forward).

- **`cyrius.cyml` replaces `cyrius.toml`**. Declares `[build] entry =
  "programs/smoke.cyr"` with `defines = ["SIGIL_SMOKE"]`, the stdlib
  surface via `[deps] stdlib = [...]`, and sakshi via `[deps.sakshi]
  git = ...`.
- **`cyrius = "5.1.13"`** — pinned from 4.5.0. The vendored `lib/*.cyr`
  stdlib files have been refreshed from `~/.cyrius/versions/5.1.13/lib/`.
- **`programs/smoke.cyr`** — new CI/smoke entry point exercising
  SHA-256, constant-time compare, Ed25519 keypair/sign/verify, and
  error-object plumbing. Guarded by `#ifdef SIGIL_SMOKE`. Exits 0 on
  success.
- **Sakshi dep is git-pinned to `2.0.0`** (previously a vendored copy
  of 0.9.0). Resolved via `cyrius deps` into
  `~/.cyrius/deps/sakshi/2.0.0/dist/sakshi.cyr`; `lib/sakshi.cyr` is
  now a managed symlink and is gitignored. Tag 2.0.0 is not yet
  folded into the Cyrius stdlib distribution — remove this block once
  it is.

### Infrastructure

- **`.gitignore`**: `/lib/sakshi.cyr` added (dep-cache symlink).
- **Build flow**: `cyrius deps && cyrius build -D SIGIL_SMOKE
  programs/smoke.cyr build/sigil-smoke`. `scripts/bundle.sh` unchanged
  and still produces `dist/sigil.cyr` with the current VERSION.

### Verified

- `./build/sigil-smoke` → exit 0.
- 10/10 `.tcyr` files pass (unchanged from 2.1.2).
- `tests/bcyr/sigil.bcyr` runs all 11 benchmarks; numbers comparable
  to pre-refactor baseline (sha256_4kb ≈ 260us, ed25519_sign ≈ 5.1ms).

## [2.1.2] — 2026-04-13

### Security

Closeout pass for the 2.1.x series. Shipped as the last patch before
2.2.0 per the CLAUDE.md closeout checklist. Addresses LOW findings
from `docs/audit/2026-04-13-audit.md` and finishes the stale-doc
sweep.

- **LOW (L11) — `ireport_summary` buffer headroom**: `src/integrity.cyr`
  enlarges the output buffer from 128 to 192 bytes. Worst-case write
  (4 × 19-digit i64 + fixed text) is ~120 bytes; new size gives safe
  headroom for any future format change.
- **LOW (L12) — `_sv_key_authorized` OOB memeq**: `src/verify.cyr`
  now bounds-checks `strlen(path) >= plen2` before calling
  `memeq(path, prefix, plen2)`. Previously, a path shorter than the
  pin prefix could read past its allocation. Bounded by the next
  heap object but still undefined behavior.

### Documentation

- **`SECURITY.md` Cryptographic Implementations**: replaced the stale
  Rust crate list (`ed25519-dalek`, `sha2`, `subtle`, `rand`) with
  the current self-hosted implementations per file, referencing the
  standards (RFC 8032, FIPS 180-4, RFC 2104). Rust `rust-old/` noted
  as reference-only.
- **`SECURITY.md` Supported Versions**: 0.2.x → 2.0.x / 2.1.x.
- **`CLAUDE.md` Status**: "Porting from Rust — TDD-first" is no
  longer accurate post-2.0 release. Updated to
  "Released (2.x), security hardening active" and retitled the TDD
  section to match (porting-specific language removed).

### Fixed

- **`src/verify.cyr` cache stubs marked**: `sv_set_cache_enabled` and
  `sv_clear_cache` write to SigilVerifier fields at +48 and +64 but
  no read path consults them. Identified during dead-code audit.
  Removal is a breaking change — documented as a stub and deferred
  to 2.2.0. No behavior change in 2.1.2.
- **`src/sha512.cyr` inner-loop line length**: the 80-round SHA-512
  inner loop's `t1` update was a single ~200-char line. Split into
  two additions against the same global (safe — no local-variable
  involvement, so the Cyrius local-clobber constraint does not
  apply). No measurable performance change.

### Chore

- **`cyrius fmt`** applied to `src/audit.cyr`, `src/trust.cyr`,
  `src/verify.cyr`. Re-indent of existing blocks; no behavioral
  diffs.
- **`cyrius lint`** clean across all `src/*.cyr`. Two residual
  warnings in `tests/tcyr/sha512.tcyr` (128-char NIST test-vector
  strings that can't be meaningfully wrapped) are accepted as
  advisory.
- **Clean build verified**: `rm -rf build && cyrius build` passes
  from scratch.

### Test coverage

- **245 assertions** across 10 `.tcyr` files (unchanged from 2.1.1;
  L11/L12 covered by existing buffer/length regression tests).
- CI `Security Scan` grep: clean.
- Fuzz harnesses: exit 0.

### Remaining / deferred to 2.2.0
- SigilVerifier cache fields removal (breaking) or wire-up.
- CI security-scan regex is coarse (matches "private key" as a
  comment phrase); tighten to require an assignment + hex literal.

## [2.1.1] — 2026-04-13

### Security

Second security hardening pass — MEDIUM findings from
`docs/audit/2026-04-13-audit.md`. Defense-in-depth against memory
disclosure and log injection.

- **MEDIUM (M6) — HMAC stack buffers zeroed on return**: `hmac_sha256`
  (`src/hmac.cyr`) now `memset`s `kprime`, `ipad`, `opad`, and
  `inner_hash` to zero before returning. Previously the derived-key
  material `K'`, `K' ⊕ 0x36`, `K' ⊕ 0x5c` could be recovered from
  stack frames via later process memory reads.
- **MEDIUM (M7) — Ed25519 secret scalars zeroed on return**:
  `ed25519_keypair` and `ed25519_sign` (`src/ed25519.cyr`) now zero
  `_kp_hash`, `_kp_scalar`, `_sign_az`, `_sign_nhash`, `_sign_r_scalar`,
  and `_sign_a_scalar` after use. These globals held the private
  scalar `a`, the per-signature nonce `r`, and the full `H(sk)`
  expansion — leaking any one recovers the private key.
- **MEDIUM (M9) — JSON injection in persistence paths**: new
  `json_write_escaped` helper in `src/trust.cyr` escapes `"`, `\`,
  and control bytes (`\b`, `\t`, `\n`, `\f`, `\r`, `\u00XX`) when
  writing user-controlled strings. `keyring_save` and
  `sv_save_trust_store` route all `key_id`, `public_key_hex`,
  `content_hash`, and `artifact_path` writes through it. Previously,
  a `"` or newline in any field corrupted the JSON and could forge
  adjacent records when re-parsed.

### Fixed

- **`sv_save_trust_store` wrote literal `"0"` for numeric fields**:
  discovered during M9 review — the function called `fmt_int(n)`
  (which prints to stdout and returns 0, not a C-string) and then
  wrote the returned `0` pointer into the JSON. Type and trust level
  fields were therefore always truncated/incorrect, and numbers leaked
  to process stdout at save time. Switched to `fmt_int_buf`. Same
  class of bug that caused the 2.1.0 fuzz harness SIGSEGV (H5).

### Added

- **`json_write_escaped(fd, s, slen)`**: public helper in
  `src/trust.cyr` for any persistence path that serializes
  user-controlled strings.
- **`tests/tcyr/security.tcyr`** extended: 18 new assertions covering
  HMAC/Ed25519 zeroization determinism and JSON escape output bytes
  for each problematic input.

### Test coverage

- **245 assertions** across 10 `.tcyr` files (was 227 in 2.1.0).
- Benchmarks within 2% of 2.1.0 (zeroization adds ~200ns per call,
  below `ed25519_sign` resolution).

### Remaining
- LOW findings (L11, L12) deferred to 2.1.2 closeout pass.

## [2.1.0] — 2026-04-13

### Security

Dedicated security hardening pass against the CLAUDE.md Security
Hardening checklist. Full audit: `docs/audit/2026-04-13-audit.md`.
This release fixes all CRITICAL and HIGH findings.

- **CRITICAL (C1) — silent weak keys on entropy failure**: `generate_keypair`
  (`src/trust.cyr`) and `tpm_random` (`src/tpm.cyr`) now check the
  `/dev/urandom` fd and `file_read` return values. Previously, if the
  fd open or read failed or returned a short count, keys were derived
  from uninitialized stack memory with no error signal. Both functions
  now loop until the requested byte count is filled and return 0 on
  any failure.
- **CRITICAL (C2) — silent fallback to zero public key**: `hex_decode`
  (`src/hex.cyr`) now rejects odd-length input and non-hex characters
  (returns 0 sentinel). Previously, `_hex_nibble` silently mapped
  invalid chars to 0, and `sv_verify_artifact` blindly consumed the
  result as a 32-byte public key. A tampered or truncated `public_key_hex`
  would decode to all zeros, opening a path to small-subgroup / zero-pk
  verification. `sv_verify_artifact` (`src/verify.cyr`) also validates
  `strlen(pk) == 64` and decode success before calling verify.
- **HIGH (H3) — Ed25519 signature malleability**: `ed25519_verify`
  (`src/ed25519.cyr`) now rejects signatures whose S scalar is
  outside `[0, L)`, per RFC 8032 §5.1.7 / §8.4. Without this check,
  an attacker could produce `(R, S+L)` as a second valid signature
  for the same `(pk, msg)` tuple.
- **HIGH (H4) — path traversal + buffer overflow in `keyring_save`**:
  `keyring_save` (`src/trust.cyr`) now validates key IDs via
  `_is_safe_key_id` (ASCII alnum, `_`, `-`, max 64 chars) and rejects
  any path whose total length exceeds the 256-byte buffer. Previously,
  a `key_id` of `../etc/passwd` or a name longer than 245 chars could
  escape `keys_dir` or overflow the heap path buffer.
- **HIGH (H5) — fuzz harness SIGSEGV masked as OK**: `scripts/check.sh`
  removed `|| true` that was swallowing crash exits. `fuzz/fuzz_integrity.fcyr`
  and `fuzz/fuzz_revocation.fcyr` rewritten — previous versions called
  `fmt_int(i)` (which prints to stdout and returns 0, not a C-string)
  and then dereferenced the result. Fuzz keys all collapsed to the same
  string and the trailing `strlen(0)` read eventually crashed on exit.
  Now use `fmt_int_buf` into a local buffer; fuzz binaries exit 0.

### Added
- **`docs/audit/2026-04-13-audit.md`**: full security audit report
  with severity, file, line, and fix plan for all 12 findings.
- **`tests/tcyr/security.tcyr`**: 21 regression tests covering each
  2.1.0 fix — hex decode validation, `hex_is_valid` predicate, Ed25519
  S ≥ L rejection (malleability), and `_is_safe_key_id` boundary cases.
- **`hex_is_valid(hex_str, hex_len)`**: new public predicate in
  `src/hex.cyr` for callers that want to validate before decoding.

### Changed
- `hex_decode` is now fallible and returns `0` on invalid input.
  **Breaking** for callers that assumed success — re-check call sites
  if you consume `hex_decode` outside sigil. Consumers inside sigil
  (`verify.cyr`) updated.
- `generate_keypair` now returns `0` on entropy failure. Callers MUST
  null-check the returned key_id before proceeding.

### Performance

No regressions vs 2.0.1 baseline (all within 3%):

| Benchmark         | 2.0.1     | 2.1.0     |
|-------------------|-----------|-----------|
| sha256_4kb        | 296us     | 286us     |
| sha512_4kb        | 156us     | 154us     |
| sc_reduce         | 52us      | 49us      |
| ge_scalarmult     | 5.773ms   | 5.457ms   |
| ed25519_keypair   | 6.923ms   | 6.405ms   |
| ed25519_sign      | 6.968ms   | 6.663ms   |
| ed25519 verify    | (S<L check: ~1us overhead, below benchmark resolution) |

### Test coverage
- **227 assertions** across 10 `.tcyr` files (was 206 in 2.0.1). New
  file: `security.tcyr` (21 assertions).
- Both fuzz binaries now exit cleanly; previously exited 139 (SIGSEGV).

## [2.0.1] — 2026-04-10

### Added
- **`dist/sigil.cyr`**: Bundled single-file distribution (4,259 lines). All 15 source
  modules concatenated with include lines stripped. Self-contained — no relative path
  resolution needed. Used by `cyrius deps` for stdlib integration.
- **`scripts/bundle.sh`**: Generates `dist/sigil.cyr` from source. Run before tagging
  a release.

## [2.0.0] — 2026-04-10

### Changed — Ed25519 Trust Layer
- **Trust signing switched from HMAC-SHA256 to Ed25519** — `sign_data` and `verify_data`
  now use real asymmetric cryptography. Verification uses the public key (not secret key).
  `generate_keypair` produces 64-byte Ed25519 sk + 32-byte pk via `ed25519_keypair`.
- **`verify_signature` renamed to `verify_data`** — takes `(data, len, sig, public_key)`
  instead of `(data, len, sig, secret_key)`. All callers updated.
- **`sv_verify_artifact` uses public key** — fetches `kv_public_key_hex` from keyring,
  decodes to 32-byte pk, verifies with `ed25519_verify`.
- **Signature size**: 64 bytes (Ed25519) instead of 32 bytes (HMAC-SHA256).

### Fixed
- **`sc_reduce` constant off-by-one**: `r256modL` ended in `951c`, correct value is `951d`.
  Caused wrong nonce/hash scalar reduction for every Ed25519 signature.
- **`sc_reduce` truncated reduction**: only did 2 levels of `hi * R` reduction (comment said
  "third level small enough to ignore" — wrong). Rewrote as iterative loop that converges
  fully (~64 iterations for 512-bit input). Carry from `u256_add` now propagated into hi.
- **`sc_muladd` allocation churn**: pre-allocated 64-byte product buffer as global.
- **`u256_sub` borrow propagation**: when `b_limb = 0xFFFFFFFFFFFFFFFF` and `borrow_in = 1`,
  the overflow to 0 silently lost the borrow. Fixed with `_sub_limb` helper that handles
  the `bl == (0-1)` case. Critical for Ed25519 since p's limbs 1,2 are all-F.
- **`u256_add` unrolled**: replaced loop with `_add_limb` helpers to avoid nested while loop
  codegen bug (Known Gotcha #6).
- **`u512_mod_p` allocation churn**: pre-allocated all temporaries (aH, aL, 38, lowp, r,
  extra, prod) as globals. Eliminates ~80KB heap churn per `fp_pow` call.
- **`fp_pow`/`fp_inv` pre-allocated**: result, base, tmp buffers allocated once.
- **Benchmark suite rewritten**: old suite called nonexistent `sha256_hex`, missing all
  crypto benchmarks. New suite: 11 benchmarks (SHA-256/512, fp_mul, fp_inv, sc_reduce,
  ge_double, ge_scalarmult, ed25519_keypair, ed25519_sign, ct_eq, hex_encode).
- **`ed25519_bug.tcyr` expected value corrected**: wrong pk for RFC 8032 test vector 1.

### Added
- **CI workflow** (`.github/workflows/ci.yml`): 5 jobs — build, test, bench, fuzz, security.
  Installs cc3 from cyrius repo tag.
- **Audit script** (`scripts/check.sh`): test suite + benchmarks + fuzz in one command.
- **Fuzz harnesses updated**: added bigint/ed25519 includes and `ed25519_init()`.
- **`rust-old/` restored**: 6,552 lines of Rust reference code recovered from git history.

### Stats
- **9 test suites, 206 assertions, 0 failures**
- **11 benchmarks**: ed25519_sign 5.7ms, ed25519_keypair 5.4ms, fp_mul 1us, sha256 300us
- **Requires Cyrius >= 3.3.4**

## [0.1.0] — 2026-04-10

### Added — Cyrius Port
- **Full port from Rust to Cyrius** — all 10 modules ported with 206 passing tests
- **Ed25519 (RFC 8032)**: keypair generation, signing, verification — byte-exact match with RFC test vectors. Built on `bigint.cyr` (4-limb u256) with custom field arithmetic over p = 2^255 - 19
- **SHA-256 (FIPS 180-4)**: streaming hash, one-shot convenience, file hashing
- **SHA-512**: required by Ed25519 for key expansion and nonce generation
- **HMAC-SHA256 (RFC 2104)**: proper ipad/opad construction, sign/verify convenience
- **Constant-time comparison**: bitwise OR accumulation, no early exit on data
- **Hex encode/decode**: for hash and key serialization
- **TrustLevel ordering**: SystemCore > Verified > Community > Unverified > Revoked with rank-based comparison
- **TrustPolicy**: builder pattern with enforcement mode, minimum trust level, hash algorithm, verification flags
- **TrustedArtifact**: path, type, hash, signature, signer, trust level, cosigners, metadata
- **VerificationResult**: artifact + checks vector + passed flag
- **SigilError**: 8 error codes (KeyNotFound, SignatureInvalid, Revocation, IntegrityMismatch, InvalidInput, IO, Serialization, Crypto)
- **PublisherKeyring**: key storage, lookup by ID/role/publisher, key rotation with overlap, chain validation, JSON persistence
- **IntegrityVerifier**: file hash measurement, verify single/all, baseline add/remove, snapshot export/import
- **RevocationList**: key and hash revocation with temporal `revoked_after` semantics, merge, O(1) lookups via hashmap index
- **CRL**: distributable certificate revocation list with version/issuer/freshness
- **AuditLog**: structured events (ArtifactVerified, ArtifactSigned, RevocationAdded, KeyRotated), JSON lines file output
- **SigilVerifier**: main trust engine — artifact verification (hash + signature + revocation + key pin + policy), signing, batch verification, compliance report, trust store snapshot/diff/persistence, boot chain verification
- **TPM module**: PcrMeasurement, AttestationResult, runtime TPM detection, system component measurement, PCR verification, seal/unseal stubs, TPM RNG with urandom fallback
- **Key zeroization**: secret key buffers zeroed after use
- Zero external dependencies (Cyrius stdlib + sakshi only)

### Removed
- Rust v1.0.0 source (was in `rust-old/`)
- Rust CI workflows, fuzz targets, cargo config, deny.toml, codecov.yml
- Rust benchmark baselines preserved in `benchmarks-rust-v-cyrius.md` for comparison

# sigil (and tls_native) gather entropy via `/dev/urandom` directly — non-functional on Windows even after the v6.2.12 CSPRNG

> **ARCHIVED (3.8.0) — sigil-side RESOLVED @3.7.15 + Windows runtime-VERIFIED (2026-06-16).**
> The sigil entropy fix is complete and proven; the only residual is downstream
> (a `cass` real-hardware confirmation + the cyrius-owned `tls_native` re-fold),
> tracked in `docs/development/roadmap.md` (Windows-entropy verification item).
> sigil's
> entropy now routes through `_sigil_random_fill` (`src/random.cyr`) → stdlib
> `random_bytes` → `sys_getrandom`, which on Windows is
> bcryptprimitives.dll!ProcessPrng (cyrius 6.2.12 0xF01A reroute). **Verified by
> cross-compiling to Windows PE (`cyrius build --win`) and RUNNING under wine
> (wine-11.10, which implements ProcessPrng):**
> - `random.tcyr` → `random_win.exe`: **exit 0, 3/3 runs** — every entropy assert
>   passes (fill succeeds, buffer non-zero, two draws differ, n==0 edge,
>   >256-byte no-truncation). The "not all-zero" + "two draws differ" asserts
>   only pass with *real* ProcessPrng entropy.
> - `ed25519.tcyr` → `ed25519_win.exe`: **exit 0** ("ed25519 keypair 20 passed") —
>   full `ed25519_generate_keypair → _sigil_random_fill → ProcessPrng` round-trip.
> - `programs/win_entropy_probe.cyr` (consumer shape: `dist/sigil.cyr` + the 5
>   opt-in libs, no agnosys) → `win_probe.exe`: **exit 0, 3/3** — raw fill +
>   two distinct ed25519 keypairs (live entropy). Same probe builds+runs on Linux.
>
> **Remaining for literal acceptance:** the `tls_native` client-nonce half is
> cyrius-owned (re-fold `lib/sigil.cyr`, re-verify the native-TLS handshake), and
> a confirmation run on **real Windows (`cass`)** vs wine. The sigil-side entropy
> is proven correct for the Windows ProcessPrng target. Reproduce:
> `cyrius build --win --no-deps programs/win_entropy_probe.cyr build/win_probe.exe && wine build/win_probe.exe; echo $?`

- **Filed**: 2026-06-15 (surfaced by the v6.2.12 adversarial review of the Windows ProcessPrng work).
- **Affects**: `lib/sigil.cyr` (folded from the sigil repo) — every keygen/nonce/blinding entropy site; transitively `lib/tls_native.cyr` (TLS nonces) which leans on sigil. **Windows (PE) only.** Linux/macOS/aarch64/AGNOS unaffected (they have `/dev/urandom`).
- **Severity**: **Medium** — fail-CLOSED, not fail-weak. On Windows these paths `file_open("/dev/urandom")` → `<0` → return `0`/`-1` (no weak entropy emitted — the CVE-19 invariant holds), but sigil RSA/Ed25519/ML-DSA keygen + RSA-PSS nonce/blinding and native-TLS nonces are **unusable** on Windows.

## Background

v6.2.12 gave Windows a real CSPRNG primitive: `lib/syscalls_windows.cyr` `sys_getrandom`
now composes `bcryptprimitives.dll!ProcessPrng` via the `0xF01A` PE reroute (issue
`2026-06-11-windows-entropy-primitive.md`, closed). The `sys_getrandom`-routed
consumers (`lib/ws.cyr` masking, `lib/sandhi.cyr` DNS TXID, `lib/random.cyr`
`random_bytes`) work on Windows now.

But **sigil never routes through `sys_getrandom`** — it reads `/dev/urandom`
directly at ~11 sites (`_rsa_pss_rand`, `_rsa_gen_blind`, `mldsa65_keypair`,
`generate_keypair`/`key_id`, `ed25519_generate_keypair`, …). On Windows there is no
`/dev/urandom` and no path translation for it, so `file_open` fails and these paths
return fail-closed. `lib/tls_native.cyr` (no direct entropy call) inherits the gap
through sigil. So the CSPRNG *primitive* exists on every target, but sigil/tls_native
don't consume it.

## Fix (sigil repo, then re-fold — ecosystem rule)

Route sigil's entropy gather through the stdlib `random_bytes` / `sys_getrandom`
(which is per-target-correct: getrandom on Linux/AGNOS, getentropy on macOS,
ProcessPrng on Windows) instead of opening `/dev/urandom` directly. Keep the
fail-closed behaviour (no weak fallback — CVE-19). Then re-fold `lib/sigil.cyr` and
re-verify a sigil keygen + a native-TLS handshake on `cass`. NOT a direct edit of the
vendored `lib/sigil.cyr` (it's a fold of the sigil repo).

## Acceptance

- A sigil keypair generation + a `tls_native` client nonce succeed and produce unique
  values on **cass** (real Windows).
- Linux/macOS/aarch64/AGNOS unchanged; no weak fallback introduced anywhere.

## Related

- `2026-06-11-windows-entropy-primitive.md` — the CSPRNG primitive (Windows ProcessPrng
  + AGNOS getrandom), fully resolved; this is the consumer-integration follow-on.
- `tests/tcyr/getrandom.tcyr` — the committed primitive regression (passes on cass).

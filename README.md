# Sigil

**System-wide trust verification for AGNOS.**

Sigil (Latin: seal) is the single crypto / trust boundary for the
AGNOS operating system — boot chain integrity, agent binary
signing, package verification, TEE remote attestation, and
revocation management.

## Language

Cyrius (ported from Rust v1.0.0; original Rust source removed in
2.7.0). **Zero external _crypto_ dependencies** — every primitive is
implemented in-house. The full (small) dependency set — cyrius stdlib +
two AGNOS first-party crates — is listed under [Dependencies](#dependencies).

**Cyrius pin:** `6.2.12` (synced across `cyrius.cyml` and CI).

## Crypto stack

All cryptography implemented in Cyrius — no external crypto libraries:

- **Ed25519** (RFC 8032) — asymmetric signing/verification
- **ECDSA P-256 / P-384** (FIPS 186-4) — secp256r1 / secp384r1
  verify **and** RFC 6979 deterministic signing (raw + DER)
- **X25519** (RFC 7748) — Curve25519 ECDH key agreement
- **SHA-256 / SHA-384 / SHA-512** (FIPS 180-4) — hashing
- **HMAC-SHA256 / HMAC-SHA384** (RFC 2104 / FIPS 198-1) — keyed hashing
- **HKDF-SHA256 / HKDF-SHA384** (RFC 5869) — key derivation
- **TLS 1.2 PRF** (RFC 5246 §5) — P_SHA256 / P_SHA384 key schedule
- **RSA PKCS#1 v1.5** (RFC 8017) — signature verify **and** sign,
  SHA-256/384, with DER/PEM key parsing (PKCS#1, SPKI, PKCS#8); on a
  general big-integer engine — constant-time Montgomery modexp for the
  secret exponent, **base blinding + CRT**, and a verify-after-sign
  (Bellcore) fault guard
- **AES-256-GCM / AES-128-GCM** (FIPS 197 + NIST SP 800-38D) — AEAD
  with runtime-detected AES-NI dispatch
- **ChaCha20-Poly1305** (RFC 8439) — AEAD (ChaCha20 cipher +
  Poly1305 one-time MAC)
- **ML-DSA-65** (FIPS 204) — post-quantum signing, **default-on since
  3.7.6** (`-D SIGIL_PQC` is now a back-compat no-op; needs `lib/keccak.cyr`)
- **Private-key parsers** — PEM + DER for ECDSA P-256/P-384 (SEC1 /
  PKCS#8) and Ed25519 (PKCS#8); X.509 + PEM cert parsing
- **Constant-time comparison** — bitwise-OR accumulation; no
  early-exit branches on secret data
- **Cryptographic RNG** — kernel CSPRNG via the stdlib `random_bytes`
  (getrandom / getentropy / ProcessPrng), fail-closed (no weak fallback)

## Modules

### Crypto primitives

- **`sha256.cyr`**, **`sha384.cyr`**, **`sha512.cyr`** — hashing
- **`sha_ni.cyr`** — SHA-256-NI hardware dispatch (runtime probe)
- **`hmac.cyr`**, **`hkdf.cyr`** — HMAC/HKDF-SHA256
- **`hmac_sha384.cyr`**, **`hkdf_sha384.cyr`** — HMAC/HKDF-SHA384
- **`tls12_prf.cyr`** — TLS 1.2 PRF (RFC 5246 §5), P_SHA256/P_SHA384
- **`bignum.cyr`** — general variable-width big integers + modexp
- **`rsa.cyr`** — RSA PKCS#1 v1.5 verify + sign + key parsing (RFC 8017)
- **`bigint_ext.cyr`** — 256-bit field arithmetic for Ed25519/X25519
- **`ed25519.cyr`** — Ed25519 signatures
- **`x25519.cyr`** — X25519 ECDH key agreement
- **`ecdsa_p256.cyr`**, **`ecdsa_p384.cyr`** — ECDSA verify
- **`ecdsa_sign.cyr`** — ECDSA P-256/P-384 RFC 6979 deterministic sign
- **`privkey.cyr`** — EC + Ed25519 private-key parsers (PEM + DER)
- **`aes_gcm.cyr`**, **`aes_ni.cyr`** — AES-256/128-GCM AEAD
- **`chacha20.cyr`**, **`poly1305.cyr`**, **`chacha20poly1305.cyr`**
  — ChaCha20-Poly1305 AEAD
- **`mldsa_*.cyr`** — ML-DSA-65 (PQC, default-on since 3.7.6)
- **`hex.cyr`** — hex encode/decode

### Trust engine

- **`types.cyr`** — TrustLevel, TrustPolicy, TrustedArtifact, etc.
- **`error.cyr`** — SigilError codes, Result pattern
- **`trust.cyr`** — PublisherKeyring, signing, key management
- **`integrity.cyr`** — file hash measurement and verification
- **`policy.cyr`** — revocation lists and CRL
- **`audit.cyr`** — structured audit logging
- **`verify.cyr`** — SigilVerifier main trust engine (single +
  parallel-batch entry points)
- **`certpin.cyr`** — TLS cert SPKI pinning

### TEE remote attestation (3.2.x + 3.4 cycles)

- **`x509.cyr`** — minimal X.509 cert parser + chain walker
  (P-256 and P-384 SPKIs; ECDSA-SHA256 chain-link signatures)
- **`pem.cyr`** — RFC 4648 base64 + PEM block decoder
- **`sgx.cyr`** — Intel SGX DCAP v3 quote parser +
  `sgx_quote_verify_with_pck` + `sgx_quote_verify_full`
- **`tdx.cyr`** — Intel TDX v4 TD-quote parser + verify
  orchestrators; dispatches on `att_key_type` (P-256 or P-384)
- **`sev_snp.cyr`** — AMD SEV-SNP attestation report parser +
  `snp_report_verify` + `snp_report_verify_full`
- **`seal.cyr`** — SGX sealing-key derivation (HKDF-bound)

### System integration

- **`tpm.cyr`** — TPM interface (runtime detection, PCR measurement)
- **`ima.cyr`** — Linux IMA log verification
- **`secureboot.cyr`** — Secure Boot chain verification

## Architecture overview

```
                    ┌─────────────────┐
                    │  consumer apps  │  daimon, kavach, ark, aegis,
                    │   (AGNOS)       │  phylax, mela, stiva, argonaut
                    └────────┬────────┘
                             │
                  ┌──────────▼──────────┐
                  │  verify.cyr         │  SigilVerifier
                  │  trust.cyr          │  PublisherKeyring
                  │  integrity.cyr      │  file hash verify
                  │  policy.cyr         │  revocation
                  │  certpin.cyr        │  SPKI pinning
                  └──────────┬──────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
│  TEE attest    │  │ system integ    │  │  primitives     │
│  sgx / tdx /   │  │  tpm / ima /    │  │  ed25519, ecdsa,│
│  sev_snp /     │  │  secureboot     │  │  sha2, hmac,    │
│  seal / x509 / │  │                 │  │  hkdf, aes-gcm, │
│  pem           │  │                 │  │  mldsa          │
└────────────────┘  └─────────────────┘  └─────────────────┘
```

See [`docs/architecture/overview.md`](docs/architecture/overview.md)
for the full module map and data flow.

## Dependencies

Sigil implements **all cryptography itself** — there are no external crypto
libraries. The complete dependency set (declared in [`cyrius.cyml`](cyrius.cyml))
is the Cyrius standard library plus two AGNOS first-party crates:

### Cyrius stdlib — pinned `6.2.12`

- **Auto-included** (cyrius pulls these on symbol reference — nothing for a
  consumer to do): `syscalls`, `alloc`, `freelist`, `assert`, `str`,
  `string`, `vec`, `hashmap`, `io`, `fs`, `fmt`, `result`, `fnptr`, `bayan`,
  `chrono`, `tagged`, `process`, `slice` (`bench` for the benchmark harness).
  (`json` + `bigint` were carved into `bayan` at cyrius 6.1.25; 6.2.x ships
  neither standalone.)
- **Opt-in — the consumer MUST `include` these** (they are *not* in the
  cyrius auto-prepend union, and `dist/sigil.cyr` does not carry them):
  - `lib/ct.cyr` — constant-time compares (`ct_eq_bytes_lens` / `ct_select`),
    every verify path
  - `lib/keccak.cyr` — `shake256` for ML-DSA-65 (default-on since 3.7.6)
  - `lib/thread.cyr` — `thread_create` / `thread_join`, parallel batch verify
  - `lib/thread_local.cyr` — per-thread crypto banks (`cbank()`), every banked
    primitive
  - `lib/random.cyr` — `random_bytes` (kernel CSPRNG: getrandom / getentropy /
    ProcessPrng), every keygen / nonce / blinding draw (since 3.7.15)

  See [Usage](#usage--stdlib-include-order-36) below for the include order and
  why omitting these is a **runtime** crash under cyrius 6.1.x. Requires
  **cyrius ≥ 6.0.52** (the release that shipped `lib/thread_local.cyr`).

### AGNOS first-party crates (git deps)

| Crate | Pin | Provides | Required by |
|---|---|---|---|
| [**sakshi**](https://github.com/MacCracken/sakshi) | `2.2.6` | structured tracing / spans (`dist/sakshi.cyr`) | `programs/smoke.cyr` and the full `src/lib.cyr` build — **not** referenced by the `dist/sigil.cyr` crypto bundle |
| [**agnosys**](https://github.com/MacCracken/agnosys) | `1.3.2` | AGNOS kernel interfaces — TPM seal/unseal, IMA measurements, Secure Boot state (`dist/agnosys.cyr`) | **only** the kernel-integration modules (`tpm.cyr`, `ima.cyr`, `secureboot.cyr`, `certpin.cyr`) |

**`dist/sigil.cyr` is self-contained** beyond the four opt-in stdlib modules
above: it references **no sakshi and no agnosys** symbols. The four
agnosys-wrapping modules are deliberately excluded from the bundle —
consumers who need the kernel layer include via `src/lib.cyr` against a
sibling agnosys checkout (which pulls agnosys as a proper dep). The bundle is
the self-contained crypto + trust engine core.

## Usage — stdlib include order (3.6+)

Sigil is consumed as a vendored distlib: `cyrius deps` resolves it into your
`lib/sigil.cyr`, which you then `include`.

**Five stdlib modules must be `include`d _before_ `lib/sigil.cyr`.** They are
*not* part of the cyrius auto-prepend union — cyrius stdlib is **opt-in**, not
auto-associated. The base stdlib (`string`/`alloc`/`str`/`vec`/`io`/…) *is* in
the auto union, so those stay automatic; these five are not, and sigil's bundle
deliberately does **not** carry them (it bundles only sigil's own crypto/trust
modules, leaving lib selection to you). This is the same opt-in pattern as
[mabda](https://github.com/MacCracken/mabda)'s manual deps:

```cyrius
include "lib/ct.cyr"             # ct_eq_bytes / ct_eq_bytes_lens / ct_select — every constant-time compare (all verify paths)
include "lib/keccak.cyr"         # shake256 / _keccak_* — ML-DSA-65 post-quantum signing (default-on since 3.7.6)
include "lib/thread.cyr"         # thread_create / thread_join — parallel-batch verify
include "lib/thread_local.cyr"   # thread_local_init/get/set — per-thread crypto banks
include "lib/random.cyr"         # random_bytes — kernel CSPRNG for keygen/nonce/blinding (getrandom/getentropy/ProcessPrng)
include "lib/sigil.cyr"          # sigil itself — MUST come last

fn main(): i64 {
    alloc_init();
    # build a PublisherKeyring + TrustPolicy, then:
    var sv = sigil_verifier_new(keyring, policy);
    var r = sv_verify_agent(sv, "/path/to/agent");
    # single OR sv_verify_batch parallel verify — both now safe, no caller mutex
    return 0;
}
```

**Why these five are required:**

- **`lib/ct.cyr`** — `ct_eq_bytes_lens` / `ct_select` back **every** constant-time
  comparison: Ed25519/ECDSA verify, HMAC/AEAD tag checks, hash compares.
- **`lib/random.cyr`** — `random_bytes` is sigil's only entropy source; every
  keygen / nonce / blinding draw funnels through `_sigil_random_fill`
  (`src/random.cyr`). It dispatches per-target — getrandom on Linux/AGNOS,
  getentropy on macOS, ProcessPrng on Windows (cyrius 6.2.12) — and is
  fail-closed (no weak fallback). Omitting it is the same runtime-crash footgun
  as the others. (Replaced the prior direct `/dev/urandom` path in 3.7.15, which
  was non-functional on Windows.)
- **`lib/keccak.cyr`** — `shake256` drives ML-DSA-65, which is **default-on since
  3.7.6** (the `-D SIGIL_PQC` gate was dropped). Required even if you never call
  the PQC surface, unless you DCE it out (`CYRIUS_DCE=1`).
- **`lib/thread.cyr` / `lib/thread_local.cyr`** — 3.6 replaced the
  `_sigil_batch_mutex` with per-thread crypto-scratch *banks* backed by
  thread-local storage. `cbank()` is on the hot path of **every** banked
  primitive (`sha_ni` onward) and lazily calls `thread_local_init()`, so even a
  single *serial* `sha256` / `ed25519_verify` / `sv_verify_*` reaches it — the
  dependency is unconditional, not parallel-batch-only.

> ⚠️ **Omitting any of these is a runtime crash, not a build failure.** Cyrius
> only *warns* on an undefined function (`undefined function 'thread_local_init'`,
> `'ct_eq_bytes_lens'`, `'shake256'`, `'random_bytes'`, …) and compiles the call site to a `ud2`
> trap. Under **cyrius 6.1.x** that means the program builds, then **SIGILLs
> (exit 132)** the moment a crypto path touches the missing symbol — e.g.
> `sha256("abc")` dies while software `sha1` runs fine. Add the five includes
> above and the crash disappears. (This was the 3.7.8 fix; see
> `docs/development/issues/archive/2026-06-09-cyrius-6120-rebreaks-ni-paths-sigill.md`.)

Requires **cyrius ≥ 6.0.52** (the release that shipped `lib/thread_local.cyr`).

## Tests

1481 assertions across 54 test files, 0 failures (3.7.17). Crypto
suites use published known-answer vectors (RFC / FIPS / NIST); the
TEE attestation arc ships synthesised end-to-end fixtures.
`tests/tcyr/batch_parallel.tcyr` doubles as the parallel-verify race
detector — run mutex-off since 3.6.

```sh
cyrius build programs/smoke.cyr build/sigil   # full build
for t in tests/tcyr/*.tcyr; do cyrius test "$t"; done
```

## Roadmap

**Current cycle — v3.7 (perf + x509), in progress.** Shipped highlights:
Solinas word-level field reduction for P-256/P-384 (3.7.0/.1), AES-GCM
arbitrary-length IVs (3.7.2), the `_into` caller-scratch API + audit-floor
clear (3.7.3), off-diagonal ECDSA x509 chain-link verify (3.7.4/.5),
**ML-DSA-65 PQC default-on** (3.7.6), and the **ECDSA verify scalar-mult
speedup** — fixed-base comb + windowed mul, ~2× both curves
(`ecdsa_p256_verify` 24.7 → 11.6 ms, `ecdsa_p384_verify` 54.6 → 26.3 ms)
(3.7.8). The 3.6 cyrius-native-TLS arc closed at 3.6.8 (parallel batch
verify, full RSA PKCS#1 v1.5 + PSS, RSA/P-384 x509 chain-link).

Open: the ≤ 10 ms P-256 verify squeeze, a buried-deferral CI gate, and the
cycle-close bench re-run.

See [`docs/development/roadmap.md`](docs/development/roadmap.md) for the full
forward-looking work + backlog, and [`CHANGELOG.md`](CHANGELOG.md) for
per-version detail.

## Documentation

- [`CHANGELOG.md`](CHANGELOG.md) — every release entry
- [`CLAUDE.md`](CLAUDE.md) — development process + cyrius quirks
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — work loop and submission
  checklist
- [`SECURITY.md`](SECURITY.md) — supported versions, reporting,
  scope, crypto implementations
- [`docs/architecture/overview.md`](docs/architecture/overview.md)
  — module map, data flow, consumers
- [`docs/development/roadmap.md`](docs/development/roadmap.md)
  — forward-looking work
- [`docs/audit/`](docs/audit/) — security audit reports per cycle

## License

GPL-3.0-only

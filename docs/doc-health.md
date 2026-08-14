---
name: Sigil Documentation Health
description: Living ledger of doc currency in the sigil repo — fresh / stale / archive / open-question, refreshed as docs are touched.
type: state
---

# Documentation Health — sigil

> **Last refresh**: 2026-08-14 (**3.12.9 — RSA sign de-banking**: the sign /
> blind / CRT workspace (23 globals) and the whole bignum engine (17 more) are
> now function-scope stack locals, closing the last two wider-scope items of the
> 2026-08-08 forged-signature issue, which is **CLOSED**. The Bellcore
> verify-after-sign guard had both compare operands in one shared lane — the
> same shape as the v1.5 verify bypass. Secret zeroization moved per-lane →
> per-call. New `crypto_banks_exhausted()` / `crypto_banks_claimed()` make lane
> exhaustion detectable. Static data **10,779,648 → 785,408 B (−92.7%)**, which
> surfaced a new invariant: a module-level `var X[N]` costs **8N** bytes, not N
> — [note 003](architecture/003-global-arrays-are-eight-bytes-per-element.md).
> Suite **1,672 / 0 across 65 files**; fuzz 3/3; no perf change. Header rows
> only — the per-file Tier tables were **not** re-inventoried.)
>
> **Prior refresh**: 2026-08-14 (**3.12.8 — `err_*` → `sigil_err_*`
> namespace rename + toolchain 6.5.21**: the 14 bare error constructors in
> `src/sys_error.cyr` are now `sigil_err_*` across 124 call sites in 9
> files — name-only, no behavioural change, but **breaking** for any
> consumer that calls them. Motivated by a live collision, not style:
> kavach pins `[deps.sigil]` *and* defines the same 14 bare names in its
> own `src/sys_error.cyr`, for 14 duplicate definitions in one link.
> Toolchain pin 6.5.17 → 6.5.21, `lib/` re-synced (107 files byte-identical
> to the snapshot), `cyrius.lock` hand-refreshed (10 hashes). Suite
> **1,665 / 0 across 65 files**; fuzz 3/3; doc-check 0 undocumented; audit
> floor stays **empty**. This refresh updated the header rows only — the
> per-file Tier tables below were **not** re-inventoried. Prior refresh
> prose follows.)
>
> **Prior refresh**: 2026-07-30 (**3.12.2 — native `asm{}` multiply +
> public-exponent modexp + Authenticode verify**: new `src/mul64.cyr`
> puts the 64×64→128 unsigned multiply in an x86-64 `asm{}` block
> (`MUL r/m64`, no CPUID probe — it's baseline x86-64; portable
> aarch64 fallback), replacing four separate 32-bit-halves copies
> under `bignum.cyr` / `bigint_ext.cyr` / `ecdsa_p384.cyr`; new
> `bn_mont_modexp_pub` runs a **deliberately** non-constant-time
> square-and-multiply for public exponents only (e = 65537:
> 51 → 20 Montgomery multiplies), with `bn_mont_modexp` retained for
> RSA `d`/`dp`/`dq`; `src/authenticode.cyr` gains the verify half
> (`authenticode_pe_verify` / `_ex` / `_chain` / `_chain_ex`,
> `authenticode_pe_hash_signed`) plus an RFC 6979 P-256 signer.
> **Security, in shipped code**: `authenticode_pe_sign` hashed
> `pe[0, pe_len)` while writing the cert table at the 8-aligned
> `cert_start`, so for any unaligned image sigil signed a byte range
> firmware / `sbverify` / Windows never recompute — fixed, and
> regression-locked by a mutation-proven 253-byte round-trip test;
> aligned inputs still produce byte-identical signatures to 3.12.1.
> Plus PE-parser hardening on untrusted input (the audit's F3 —
> optional-header magic allow-list, `NumberOfRvaAndSizes` /
> `e_lfanew` minima, cert-table placement and `WIN_CERTIFICATE`
> checks) and the removal of `authenticode_pe_hash`'s 144-byte
> per-call SHA-256 context leak. Perf, same host
> and same pin on both sides: `rsa2048_verify_sha256` 3.276 → **1.178
> ms** (2.78×), `rsa2048_sign_sha256_crt` 70.132 → **41.276 ms**
> (1.70×), `ed25519_verify` 6.425 → **5.146 ms** (1.25×),
> `ecdsa_p256_verify` 10.539 → **9.732 ms** — **below the 10 ms target
> ADR 0006 parked as "not reachable with current approaches"**; ML-DSA
> and SHA-256 controls unmoved. Prior arcs: the 3.6 cyrius-native-TLS
> arc closed at 3.6.8; the v3.7 EC-squeeze cycle closed at 3.7.17; the
> 3.8.x housekeeping bookend closed at 3.8.1 (**agnosys dependency
> dropped**); the 3.9.x thread-safety-banking arc completed at 3.9.7.
> Per-version detail lives in
> [`CHANGELOG.md`](../CHANGELOG.md) and per-cycle audit docs in
> [`docs/audit/`](audit/) — the daily-stack notes that used to live here
> were retired in favour of those sources.
>
> **Headline changes since the last full row-refresh (3.4.1 inventory):**
> - **Version `3.12.9`**, cyrius pin **`6.5.21`** (was 3.5.4 / 6.0.3 at
>   the 3.4.1 inventory). Deps: **ZERO git deps** — sakshi moved from
>   `[deps.sakshi]` into `[deps].stdlib` at 3.12.7, so **sakshi `2.4.10`**
>   and **bayan `1.4.1`** now both arrive with the toolchain snapshot and
>   their only machine-visible trace is the `lib/sakshi.cyr` /
>   `lib/bayan.cyr` hashes in `cyrius.lock` — deliberately absent from the
>   dependency tables in README / state.md. **agnosys was DROPPED at
>   3.8.1** (its trust primitives were internalized as `src/*_core.cyr` +
>   `src/sys_error.cyr` / `src/sys_util.cyr`); `cyrius.cyml [deps]` no
>   longer references agnosys. **3.12.8 renamed the 14 bare `err_*`
>   constructors in `src/sys_error.cyr` to `sigil_err_*`** — a breaking
>   but name-only change, motivated by a live 14-way duplicate-symbol
>   collision in kavach.
> - **Audit floor: EMPTY** as of the 2026-08-14 3.12.8 audit
>   ([`2026-08-14-3.12.8-err-namespace-toolchain-audit.md`](audit/2026-08-14-3.12.8-err-namespace-toolchain-audit.md)),
>   a **scoped** maintenance pass (rename blast-radius, toolchain/lock
>   integrity, and a full-tree quirk #1 cumulative-stack-budget re-probe)
>   that found nothing. **Gap, named plainly and now WIDER than the note
>   below records:** on top of 3.10.0 → 3.12.1, releases **3.12.3 →
>   3.12.7 also filed no audit doc** — including **3.12.6, which fixed an
>   RSA-PSS authentication bypass**. The 3.12.8 audit explicitly does not
>   cover that range; a catch-up pass is tracked in the roadmap as
>   the maintainer's call. Historical detail follows.
> - **Audit floor: EMPTY** as of the 2026-07-30 3.12.2 audit — every
>   finding of that cycle was resolved in-cycle (F1 HIGH signer
>   pad-in-hash + F2 LOW `authenticode_pe_hash` allocator leak both
>   fixed, F3's four PE-header hardenings applied; F4/F5 are INFO). The
>   floor had been EMPTY since 3.7.3. **Gap, named plainly:** there is
>   **no per-cycle audit doc for 3.10.0 → 3.12.1** — the 3.12.2 audit is
>   the first since 2026-06-29, so the floor for those six releases was
>   never independently re-verified. See Tier 4.
> - **65 `.tcyr` files (`ls tests/tcyr/*.tcyr`) / 1672 assertions**, 0
>   failures @3.12.9 (was ~1178 at the 3.4.1 inventory), confirmed by two
>   independent counting methods that agree exactly. ⚠ 3.12.7's CHANGELOG
>   claimed **1,730**, which reproduces under neither method — see the
>   roadmap item. Fuzz: **24 / 0** across
>   3 `fuzz/*.fcyr` files (`fuzz_ed25519` 11, `fuzz_integrity` 6,
>   `fuzz_revocation` 7). **The old assertion-count caveat is DEAD —
>   do not re-add it.** Through 3.11.x this file said the 3
>   `*_verify_full` tests drop their summary under a pipe and their 44
>   assertions must be added back to a scripted grep-sum; `state.md`'s
>   "Counting note" (revised @3.12.0) says the opposite. **state.md is
>   right**: re-measured under the current pin, all 64 files emit their
>   `N passed` line through a redirect, so the grep-sum already
>   **includes** those 44 and adding them back double-counts. The two
>   docs disagreed from 3.12.0 until this refresh; this file was the
>   wrong one. New modules/surfaces since the 3.9.x banking arc:
>   `authenticode.cyr` (3.10.0), `efi_sigdb.cyr` (3.11.1),
>   `blake2b.cyr` + `argon2.cyr` (3.12.0), `mul64.cyr` (3.12.2) — with
>   `tests/tcyr/{authenticode,efi_sigdb,blake2b,argon2}.tcyr` the four
>   files added since the 60 at 3.9.7.
> - **Audit docs**: **38 dated artifacts** under `docs/audit/`, running
>   3.5.6-retro → 3.6.x → 3.7.x → 3.8.0 → the two 2026-06-29 banking
>   audits → the 2026-07-30 3.12.2 audit.
> - **`dist/` now carries 14 bundles** — the full `sigil.cyr` plus 13
>   per-profile cuts (`argon2`, `sha`, `hmac`, `hkdf`, `aes`, `chacha`,
>   `ed25519`, `ecdsa`, `mldsa`, `x509`, `authenticode`, `secureboot`,
>   `tpm`), each with its `.deps` sidecar, all emitted by
>   `cyrius distlib` from the `[lib.*]` profiles in `cyrius.cyml`.
> - **`docs/architecture/` numbered notes are no longer empty** — `001`
>   (`var X[N]` static semantics + banked crypto scratch) and `002` (the
>   native `asm{}` 64×64→128 multiply, 3.12.2) both exist.
> - **`docs/architecture/` runs 001 → 003** (003 = the 8N global-array
>   sizing rule, 3.12.9).
> - **ADRs run 0001 → 0008**; `0008` (native asm multiply + the
>   public-exponent modexp) was accepted 2026-07-30.
> - **CHANGELOG / roadmap / state.md / sources.md are all current through
>   3.12.2** (all four were refreshed in this pass; this ledger was the
>   most stale doc in the tree, frozen at 3.9.7 / 2026-06-29).
>   `docs/development/issues/` is **clear again — 0 open, 16 archived**;
>   both issues open through 3.12.1 closed at 3.12.2. Two items stay
>   open and are named here so they don't get buried: ADR 0006's parked
>   **"≤ 10 ms"** target, which 3.12.2 measured at 9.732 ms and which
>   the roadmap now carries as **DECISION NEEDED** (the maintainer's call —
>   declare met, re-measure on a second host, or set a new target), and
>   the **release post-hook state-drift**, now on its third recorded
>   occurrence.
> - **`docs/architecture/overview.md` is the one stale doc left** — its
>   module map predates five modules. See Tier 2.
>
> **Refresh cadence**: when docs are touched, update the
> affected row inline. Full audit at minor closeout
> (next: the 3.12.x cycle close).
>
> **Scope**: this repo only (`sigil`) — the entire `docs/` tree
> plus root-level files (README, CHANGELOG, CLAUDE.md, VERSION,
> cyrius.cyml, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT,
> benchmarks-rust-v-cyrius). Cross-repo state lives in
> agnosticos.

This is a **ledger**, not a one-time audit. Rewrite-in-place as
docs change.

---

## At a glance — 2026-05-22 inventory (3.4.1)

> Historical 3.4.1 snapshot; for current counts see the 3.12.2 header
> refresh above and the per-tier tables. The audit-doc count alone has
> grown from ~6 to **38** files since this snapshot, and the whole tree
> from ~38 markdown files to **82** (75 of them under `docs/`).

**~38 markdown files** across the repo (post-sweep).

| Bucket | Count | What it means |
|---|---|---|
| ✅ **Fresh / touched in current cycle** | ~25 | Touched within the 3.4.x cycle. See per-tier tables. |
| 🟡 **Stale — refresh in place** | 0 | None flagged. |
| 🟠 **Read-through outstanding** | 0 | None. |
| 🔵 **Probably evergreen** | ~7 | ADRs (3) + closed-cycle scope docs (3) + `benchmarks-rust-v-cyrius.md`. Re-read at minor closeout. |
| 📦 **Archive — frozen by design** | ~6 | `docs/development/issues/archive/` + closed-cycle scope docs (3.0, 3.2, 3.2-tee-arc). |
| ❓ **Open strategic question** | 0 | None. |

Numbers approximate; rolls up from the per-tier tables below.

**Why now**: doc-health convention adopted 2026-05-22 alongside
the agnosticos first-party-standards drift sweep. Sigil's doc
tree was actively maintained per-release (CHANGELOG + roadmap +
audit docs are current per cycle) but the **aggregate**
currency had no surface. This file is that surface.

**2026-05-22 sweep summary** — three classes of finding:

1. **CLAUDE.md drift from template** (largest fix): inlined
   volatile state (consumers, test counts, port-history),
   wrong agnosticos planning path (`applications/` → `planning/`),
   missing pointer-block to `state.md`. Restructured to the
   `example_claude.md` template shape; state moved to
   `docs/development/state.md` (new).
2. **README + architecture/overview stale** (six minor
   versions of drift): README claimed "206 tests" (actual:
   1178); module list missing aes_gcm, ecdsa, sha384, hkdf,
   x509, pem, sgx, tdx, sev_snp, seal, mldsa, certpin, ima,
   secureboot. Same drift in `docs/architecture/overview.md`.
   Both rewritten.
3. **CONTRIBUTING + SECURITY supported-version drift**:
   CONTRIBUTING.md still said `cargo test`; SECURITY.md
   supported-versions table topped at 2.8.x (we're on 3.4.x).
   Both rewritten.

Three new scaffolding directories created at this pass: `adr/`
(3 seed ADRs covering retained batch mutex, ML-DSA cmdline
gate, and bump-alloc-drift-until-3.6); `architecture/` ADR-
sibling index (README seed; numbered notes deferred to first
grep-from-the-wild); `sources.md` consolidated RFC/FIPS/NIST
citation index for every crypto primitive.

---

## Tier 1 — Structural docs (root)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-07-30 | ✅ Fresh | Refreshed this cycle: toolchain pin `6.5.3` (header + the stdlib section heading), sakshi `2.4.7` in the git-dep table, the test claim now "1661 assertions across 64 test files, 0 failures (3.12.2)" plus the 24-assertion fuzz line (path corrected to `fuzz/*.fcyr` — an earlier draft of this pass wrote `tests/fcyr/`, which does not exist). Modules section now carries `blake2b.cyr` / `argon2.cyr`, `mul64.cyr`, `authenticode.cyr` incl. the 3.12.2 verify surface + P-256 signer, and `efi_sigdb.cyr`. Roadmap narrative extended through v3.12.x, with the ADR 0006 ≤ 10 ms crossing recorded as an **open** disposition rather than a closed one. (Deliberately no line numbers here — they rot on every insertion into README.) |
| `CHANGELOG.md` | 2026-07-30 | ✅ Fresh | Source of truth per CLAUDE.md. **Through 3.12.2** (`## [3.12.2] — 2026-07-30`, leading with the `authenticode_pe_sign` Security section). Refreshed every release. |
| `CLAUDE.md` | 2026-07-14 | ✅ Fresh | agnosticos `example_claude.md` template; durable rules only. 3.6.8 fixed the stale `benches/sigil.bcyr` → `tests/bcyr/sigil.bcyr` Quick-Start path. |
| `CONTRIBUTING.md` | 2026-06-29 | ✅ Fresh | Cyrius work loop + commit/hook rules; no Rust/cargo references. |
| `SECURITY.md` | 2026-07-30 | ✅ Fresh | Supported-versions table tops at **3.12.x** (current minor) / 3.11.x (prior), `< 3.11.0` unsupported. |
| `CODE_OF_CONDUCT.md` | (per upstream) | 🔵 Evergreen | Standard contributor covenant. |
| `LICENSE` | (per upstream) | 🔵 Evergreen | GPL-3.0-only. |
| `VERSION` | 2026-07-30 | ✅ Fresh | **`3.12.2`**. Bumped every release. |
| `cyrius.cyml` | 2026-07-30 | ✅ Fresh | `[lib].modules` now lists **65** modules — every file in `src/` except the `src/lib.cyr` umbrella, so the module-list drift gate below is currently clean; `mul64.cyr` added this cycle to `[lib]` and to the `ed25519` / `ecdsa` / `mldsa` / `x509` / `authenticode` profiles. Toolchain pin **`6.5.3`** (6.0.87 @3.7.8 → 6.2.x → 6.3.5 @3.9.6 → 6.4.65 @3.12.1 → **6.5.3** @3.12.2). Deps: **sakshi 2.4.7 ONLY — agnosys DROPPED @3.8.1**; `bayan` is in the `[deps].stdlib` list (1.3.0 with the toolchain), not a pinned `[deps.*]` entry; `json` / `bigint` were dropped at the 6.2.1 pin (bigint → bayan). |
| `dist/sigil.deps` + `cyrius distlib` | 2026-07-30 | ✅ Fresh | **@3.9.5+**: the bash `scripts/regen-dist.sh` retired — the sovereign `cyrius distlib` (≥6.2.48) folds `dist/sigil.cyr` AND emits the `dist/sigil.deps` sidecar (stdlib leaves, captured from the modules + the `src/lib.cyr` umbrella). `dist/` now holds **14 `.cyr` bundles + 14 `.deps` sidecars**: the full `sigil.cyr` plus the 13 `[lib.*]` profile cuts (`argon2`, `sha`, `hmac`, `hkdf`, `aes`, `chacha`, `ed25519`, `ecdsa`, `mldsa`, `x509`, `authenticode`, `secureboot`, `tpm`). Re-run `cyrius distlib` after a `[lib].modules` or VERSION change. |
| `dist/sigil.cyr` | 2026-07-30 | ✅ Fresh | Regenerated every release (last, after the VERSION bump — CI has a stale-dist gate). Header reads **`# Version: 3.12.2`**; carries the 3.7.8 NI `param_load` migration, the 3.7.15 `src/random.cyr` entropy boundary, the agnosys-drop internalized trust modules, the 3.9.x full concurrent-crypto banking, and the 3.10–3.12 `authenticode` / `efi_sigdb` / `blake2b` / `argon2` / `mul64` surfaces incl. the `authenticode_pe_sign` pad-in-hash security fix. |
| `benchmarks-rust-v-cyrius.md` | (closed) | 🔵 Evergreen | Frozen cross-implementation perf baseline; not rebuilt per release. |

---

## Tier 2 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-06-29 | ✅ Fresh | Index + conventions. The numbered series is **no longer empty** — `001` is promoted and indexed; the README's "candidates" list still names `002-preprocessor-output-cap.md` (quirk #8) as the next candidate, but **`002` was taken** by the native-asm-multiply note at 3.12.2, so that candidate needs renumbering to `003` when it is written (**never renumber the existing series**). |
| `001-var-array-static-semantics.md` | 2026-06-29 | ✅ Fresh | Quirk #1 promoted from CLAUDE.md — `var X[N]` arrays are function-scope statics, the invariant every `cbank()` bank follows from, incl. the 3.9.7 `secret var`-arrays-race corollary. |
| `002-native-asm-multiply.md` | 2026-07-30 | ✅ Fresh | New this cycle (written by the operator). The `src/mul64.cyr` `asm{}` contract and the four big-integer engines that consume it; the third `asm{}` site in `src/` after `sha_ni.cyr` / `aes_ni.cyr` and the first with no runtime feature detection. |
| `overview.md` | 2026-06-29 | 🟡 Stale | Module map + TEE data-flow + parallel-batch framing. Current through the 3.9.x banking arc (auto-lane `cbank()`, banks 8→64, `secret var`-array gotcha, agnosys drop, PQC-gate removal, bayan/stdlib list are all correct). **Stale**: the module map predates five modules — `authenticode.cyr` (3.10.0), `efi_sigdb.cyr` (3.11.1), `blake2b.cyr` + `argon2.cyr` (3.12.0) and `mul64.cyr` (3.12.2) are absent, as is any mention of the `[lib.*]` per-profile dist cuts. Add `mul64.cyr` with a pointer to architecture note `002`. |

---

## Tier 3 — ADRs (`docs/adr/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-06-29 | ✅ Fresh | ADR index + conventions (per agnosticos template). |
| `template.md` | 2026-05-22 | ✅ Fresh | Verbatim shape from `sit/docs/adr/template.md`. |
| `0001-retain-batch-mutex-until-caller-scratch.md` | 2026-06-03 | ✅ Fresh / 🔵 Evergreen-ish | Mutex-drop deferral rationale. Superseded by its own outcome — the `_sigil_batch_mutex` was dropped at **3.6.0** via per-worker banks (extended to ChaCha20/X25519 at 3.8.0, then to every concurrent path at 3.9.6/3.9.7). |
| `0002-mldsa-cmdline-gate.md` | 2026-06-16 | ✅ Fresh | Captures the `-D SIGIL_PQC` gate rationale (cyrius preprocessor 1 MB cap). **Resolved**: cyrius 6.0.87 raised the cap; PQC went default-on at 3.7.6 and `-D SIGIL_PQC` is now a back-compat no-op. |
| `0003-bump-alloc-drift-acceptable-until-3-6.md` | 2026-05-27 | 🔵 Resolved | The batched-closure target it tracked is **done**: the audit floor was cleared at 3.7.3 (4 LOWs resolved via the `_into` API, 4 reclassified as correct init-once). Confirm the ADR body carries a Resolved/Superseded marker. |
| `0004-per-lane-zeroization-for-banked-crypto-arrays.md` | 2026-06-16 | ✅ Fresh | The 3.8.0 rule: banked secret scratch is plain `var` + a per-lane `memset`, **never** `secret var` (a whole-array wipe on scope exit clobbers a sibling worker's live lane). |
| `0005-keep-karatsuba-u256-mul-full.md` | 2026-06-16 | ✅ Fresh | Keeps the 3.7.17 Karatsuba `u256_mul_full` with schoolbook retained as oracle. Still accurate at 3.12.2 — `mul64.cyr` replaces the *limb* multiply underneath Karatsuba, not the Karatsuba decomposition itself. |
| `0006-park-ec-scalarmul-10ms-target.md` | 2026-06-16 | 🟡 Needs revisit | Parked the "EC scalar-mult ≤ 10 ms" target as *not reachable with current approaches* at a ~10.9 ms floor, with exotic levers (asm / alt-representation) sent to the Backlog. **3.12.2 took one of those exotic levers (the native `asm{}` multiply) and measured `ecdsa_p256_verify` at 9.732 ms — under the target.** The ADR needs a Superseded/Revisited marker and the roadmap's parked item needs re-opening or closing-as-met; that is the maintainer's call, not a doc edit. |
| `0007-auto-banking-for-concurrent-tls.md` | 2026-06-29 | ✅ Fresh | The 3.9.6 decision: `cbank()` auto-assigns a per-thread lane on first use (atomic counter → lanes 1..63, bank 0 = main), `SIGIL_CRYPTO_BANKS` 8→64, no consumer `crypto_bank_set` call. |
| `0008-native-asm-multiply-and-public-modexp.md` | 2026-07-30 | ✅ Fresh | New this cycle (written by the operator). Accepted 2026-07-30: why a hand-written `MUL r/m64` earns its keep on the hottest path, and why a deliberately non-constant-time `bn_mont_modexp_pub` is safe when reachability from a secret exponent is proven. **Link check**: its context block points at `../development/issues/archive/2026-07-30-rsa-verify-uses-secret-exponent-ladder.md` — a **dangling link until that issue is moved into `archive/`** (see Tier 6). |

---

## Tier 4 — Audits (`docs/audit/`)

Per-cycle audit reports; per-audit timestamped (don't refresh
in place — supersede with a new audit doc when the affected
finding closes).

| File | Last touched | Status |
|---|---|---|
| `2026-04-13-audit.md` | 2026-04-13 | 🔵 Dated artifact |
| `2026-05-01-audit.md` | 2026-05-01 | 🔵 Dated artifact |
| `2026-05-21-audit.md` | 2026-05-21 | 🔵 Dated artifact (3.2.1 closeout) |
| `2026-05-22-audit.md` | 2026-05-22 | 🔵 Dated artifact (3.2.2 closeout — predates 3.4.x numbering convention) |
| `2026-05-23-audit.md` | 2026-05-23 | 🔵 Dated artifact (3.2.3 closeout) |
| `2026-05-24-audit.md` | 2026-05-24 | 🔵 Dated artifact (3.2.4 closeout) |
| `2026-05-25-audit.md` | 2026-05-25 | 🔵 Dated artifact (3.2.5 closeout) |
| `2026-05-26-audit.md` | 2026-05-26 | 🔵 Dated artifact (3.2.6 closeout + TEE arc close) |
| `2026-05-22-3.4.0-audit.md` | 2026-05-22 | 🔵 Dated artifact (3.4.0 closeout) |
| `2026-05-22-3.4.1-audit.md` | 2026-05-22 | 🔵 Dated artifact (3.4.1 closeout) |
| `2026-05-22-3.4.2-audit.md` | 2026-05-22 | 🔵 Dated artifact (3.4.2 closeout — packaging-fix release; INFO-only) |
| `2026-05-23-3.4.3-audit.md` | 2026-05-23 | 🔵 Dated artifact (3.4.3 — `secret var` aes_gcm sweep) |
| `2026-05-27-3.5-arc-audit.md` | 2026-05-27 | 🔵 Dated artifact (**3.5 arc, 3.5.0–3.5.4**) — consolidates the four per-bite audits; the per-bite `3.5.0/.1/.2/.3-audit.md` files were merged here and removed. |
| `2026-05-28-3.5.7-aes128-gcm-audit.md` | 2026-05-28 | 🔵 Dated artifact (3.5.7 — AES-128-GCM) |
| `2026-05-28-3.5.8-privkey-parsers-audit.md` | 2026-05-28 | 🔵 Dated artifact (3.5.8 — private-key parsers) |
| `2026-05-28-3.5.9-ecdsa-sign-audit.md` | 2026-05-28 | 🔵 Dated artifact (3.5.9 — ECDSA RFC 6979 signing) |
| `2026-06-03-3.6.0-parallel-verify-audit.md` | 2026-06-03 | 🔵 Dated artifact (3.6.0 — parallel batch verify / per-worker banks) |
| `2026-06-03-3.6.1-tls12-prf-audit.md` | 2026-06-03 | 🔵 Dated artifact (3.6.1 — TLS 1.2 PRF) |
| `2026-06-03-3.6.2-rsa-verify-audit.md` | 2026-06-03 | 🔵 Dated artifact (3.6.2 — RSA verify) |
| `2026-06-03-3.6.3-rsa-keys-sign-audit.md` | 2026-06-03 | 🔵 Dated artifact (3.6.3 — RSA keys + sign) |
| `2026-06-03-3.6.4-rsa-hardening-audit.md` | 2026-06-03 | 🔵 Dated artifact (3.6.4 — RSA hardening) |
| `2026-06-04-3.5.6-hmac-hkdf-sha384-audit.md` | 2026-06-04 | 🔵 Dated artifact (3.5.6 retro — HMAC/HKDF-SHA384) |
| `2026-06-04-3.6.5-pss-x509-rsa-audit.md` | 2026-06-04 | 🔵 Dated artifact (3.6.5 — PSS + X.509 RSA) |
| `2026-06-04-3.6.6-montgomery-pem-rsak-audit.md` | 2026-06-04 | 🔵 Dated artifact (3.6.6 — Montgomery + PEM RSA keys) |
| `2026-06-04-3.6.7-p384-chainlink-aes128-seal-audit.md` | 2026-06-04 | 🔵 Dated artifact (3.6.7 — P-384 chain-link + AES-128 seal) |
| `2026-06-04-3.6.8-closeout-audit.md` | 2026-06-04 | 🔵 Dated artifact (3.6.8 — 3.6 closeout) |
| `2026-06-04-3.7.0-p256-solinas-audit.md` | 2026-06-04 | 🔵 Dated artifact (3.7.0 — P-256 Solinas) |
| `2026-06-04-3.7.1-p384-solinas-audit.md` | 2026-06-04 | 🔵 Dated artifact (3.7.1 — P-384 Solinas) |
| `2026-06-04-3.7.2-gcm-arbitrary-iv-audit.md` | 2026-06-04 | 🔵 Dated artifact (3.7.2 — GCM arbitrary IV) |
| `2026-06-04-3.7.3-into-api-audit.md` | 2026-06-04 | 🔵 Dated artifact (3.7.3 — `_into` API; audit floor cleared) |
| `2026-06-07-3.7.5-offdiag-ecdsa-audit.md` | 2026-06-07 | 🔵 Dated artifact (3.7.5 — off-diagonal ECDSA) |
| `2026-06-15-3.7.15-windows-entropy-audit.md` | 2026-06-15 | 🔵 Dated artifact (3.7.15 — Windows-entropy single boundary) |
| `2026-06-16-3.7.16-ec-inversion-mixedadd-audit.md` | 2026-06-16 | 🔵 Dated artifact (3.7.16 — EC inversion addition-chains + affine comb mixed-add) |
| `2026-06-16-3.7.17-karatsuba-multiply-audit.md` | 2026-06-16 | 🔵 Dated artifact (3.7.17 — Karatsuba `u256_mul_full`) |
| `2026-06-16-3.8.0-chacha-x25519-banking-audit.md` | 2026-06-16 | 🔵 Dated artifact (3.8.0 — ChaCha20 + X25519 per-worker banking) |
| `2026-06-29-3.9.6-concurrent-tls-handshake-banking-audit.md` | 2026-06-29 | 🔵 Dated artifact (3.9.6 — concurrent-TLS-handshake crash fix; `cbank()` auto-lane banking, banks 8→64) |
| `2026-06-29-3.9.7-ecdsa-bignum-banking-audit.md` | 2026-06-29 | 🔵 Dated artifact (3.9.7 — ECDSA/bignum/PRF thread-safety banking; F1 MEDIUM DER-wrapper race + F2 LOW RSA-sign residue, both fixed in-cycle) |
| `2026-07-30-3.12.2-asm-multiply-authenticode-verify-audit.md` | 2026-07-30 | 🔵 Dated artifact (3.12.2 — `mul64.cyr` asm multiply, `bn_mont_modexp_pub` reachability proof, Authenticode verify + P-256 signer, plus the 6.4.65→6.5.3 / sakshi 2.4.3→2.4.7 / bayan 1.1.0→1.3.0 bumps. **1 HIGH fixed** — `authenticode_pe_sign` signed a byte range no verifier checks — **4 hardenings applied, 1 LOW fixed, 2 INFO, no CRITICAL**) |

> **Table complete through 3.12.2** — all **38** dated audit artifacts under
> `docs/audit/` are itemised above. **Gap, tracked not buried: there is no
> per-cycle audit doc for 3.10.0, 3.10.1, 3.11.0, 3.11.1, 3.12.0 or 3.12.1.**
> CLAUDE.md § Security Hardening calls for a dedicated audit pass before *any*
> version release, so those six releases — which include the whole
> `authenticode.cyr` / `efi_sigdb.cyr` / `blake2b.cyr` / `argon2.cyr` surface,
> all of it parsing untrusted input — shipped without a filed audit artifact.
> The 2026-07-30 audit is the first since 2026-06-29 and covers only the
> 3.12.2 deltas plus the modules it reaches. (As before, there are no separate
> 3.9.0–3.9.5 audit docs; those bites were housekeeping/bundling/CVE-trust-chain
> work covered by CHANGELOG.)

**Audit floor**: **EMPTY as of the 2026-07-30 3.12.2 audit.** The seven (then eight,
+3.6.5 RSA SPKI block) bump-allocator LOWs ADR 0003 batched are
resolved (4 via the `_into` caller-scratch API) or reclassified as
correct init-once singletons (4); the 3.9.6 and 3.9.7 banking audits resolved
every finding in-cycle; the 3.12.2 audit resolved F1 (HIGH — signer pad-in-hash,
in *shipped* code, found by spec review not by a test) and F2 (LOW —
`authenticode_pe_hash`'s 144-byte per-call leak on a non-thread-safe allocator),
applied F3's four PE-header validation hardenings, and recorded F4/F5 as INFO
(the asm multiply *improves* the CT posture; `bn_mont_modexp_pub` is
non-constant-time by design with reachability proven). Zero findings of
any severity outstanding — but see the 3.10–3.12.1 audit-doc gap above: the
floor was not independently re-verified across those releases.

Naming convention note: multi-cycle days disambiguate via
`YYYY-MM-DD-<version>-audit.md`; the bare `YYYY-MM-DD-audit.md` form is
reserved for the first cycle of a day.

---

## Tier 5 — Development (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-07-30 | ✅ Fresh | **Through 3.12.2**: "Closed cycles" now carries the **3.12** entry (3.12.0 BLAKE2b + Argon2, 3.12.1 bank-slot move, 3.12.2 native asm multiply + public-exponent modexp + Authenticode verify) alongside 3.6–3.11. Open items are named, not buried — the headline one is **"EC scalar-mult ≤ 10 ms — DECISION NEEDED: the target is now met"**: ADR 0006 parked it as unreachable, 3.12.2's `src/mul64.cyr` measured `ecdsa_p256_verify` at 9.732 ms, and the ADR was **deliberately left open** because a ~7 % single-host crossing is the maintainer's call, not a perf side-effect. **Opened by 3.12.2**: the UEFI firmware-interop gate (last item of the now-archived authenticode issue, moved here so it survives archival), the **missing 3.10 / 3.11 rows in `benches/history.csv`** (left honest — fill forward only), and a full `asm{}` CIOS inner loop (unscoped by choice). Carried backlog: TDX/SGX in-quote PCK chain walk, retire-bank-indexing, scatter-store, CLMUL-GHASH, ML-KEM-768, `#derive(Serialize)` completeness, Windows-entropy `cass` ProcessPrng confirmation, retire-`sysinfo.cyr`. **Open audit findings — NONE.** |
| `state.md` | 2026-07-30 | ✅ Fresh | Live state snapshot — bumped every release. **Through 3.12.2**: version / pin `6.5.3` / sakshi `2.4.7` + bayan `1.3.0`-as-stdlib-module, last release audit = the 2026-07-30 3.12.2 audit, test surface **1661 / 0 across 64 files**. Its **Counting note (revised @3.12.0)** is the authoritative one — the `*_verify_full` summaries no longer drop under a pipe, so the grep-sum already includes those 44 and they must **not** be added back; this file (doc-health) carried the opposite claim from 3.12.0 until the 2026-07-30 refresh and was the wrong one. Standing open item, escalated this cycle: the ⚠️ **state-drift note** now records the **third** occurrence of the release post-hook failing to bump the volatile fields (3.9.0–3.9.5, 3.9.6–3.11.0, 3.12.0–3.12.1 — at one point three different versions asserted in one section). Per CLAUDE.md ("if the hook doesn't, fix the hook — don't hand-maintain state") the hook fix stays flagged for the maintainer. |
| `3.0-handoff-2026-04-22.md` | 2026-04-22 | 📦 Archive | Frozen by design — closed-cycle handoff doc. |
| `3.0-scope.md` | (closed) | 📦 Archive | Frozen by design — closed-cycle scope doc. |
| `3.2-scope.md` | (closed) | 📦 Archive | Frozen by design — closed-cycle scope doc. |
| `3.2-tee-arc.md` | (closed 2026-05-26) | 📦 Archive | Frozen by design — closed-arc plan doc; arc summary moved to roadmap.md "Closed cycles" header at 3.2.6 close. |

---

## Tier 6 — Issues (`docs/development/issues/`)

Open issues are tracked artifacts (filed by consumers or
internal observation). Archived when resolved.

### Open issues

**0 open** — `docs/development/issues/` holds only `archive/` (**16 files**
inside) as of 3.12.2. The two issues open through 3.12.1 were both resolved and
archived this cycle: the **authenticode-pe-signing** issue (gnoboot/agnova
sovereign UEFI Secure Boot — P1+P2 @3.10.0, P3 @3.11.1 via `efi_sigdb.cyr`,
P4 @3.12.2; its one remaining non-sigil item, the OVMF firmware-interop run, was
**moved to the roadmap so it survives archival**) and the agnosai
**rsa-verify-uses-secret-exponent-ladder** report (resolved by
`bn_mont_modexp_pub` + `mul64.cyr`, decision recorded in ADR 0008, which links
the issue at its `archive/` path). Earlier: the **err-io-enum-collision** and
**concurrent-tls-handshake global-scratch-race** issues were archived in the
3.9.x cycle, and the Windows-entropy issue at 3.8.0 after wine/ProcessPrng
runtime verification.

### Archived issues

16 files under `docs/development/issues/archive/`:

| File | Resolution | Status |
|---|---|---|
| `archive/2026-04-22-cyrius-fixup-cap-raises.md` | Resolved upstream | 📦 Archive |
| `archive/2026-04-25-sha-ni-compress-design.md` | Resolved at 2.9.x SHA-NI landing | 📦 Archive |
| `archive/2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md` | Resolved at 3.7.8 (NI `param_load` migration) | 📦 Archive |
| `archive/2026-05-10-ed25519-verify-aarch64-accepts-wrong-pk.md` | Resolved at 3.0.x cycle | 📦 Archive |
| `archive/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md` | Closed by 3.2.x TEE arc + 3.4 verify_full | 📦 Archive |
| `archive/2026-05-11-tlsh-distance-segfault-phylax.md` | Consumer-filed (phylax); resolved/closed | 📦 Archive |
| `archive/2026-05-28-cyrius-tls-arc-full-audit.md` | Resolved at the 3.6 cyrius-native-TLS arc | 📦 Archive |
| `archive/2026-05-28-cyrius-tls-native-needs-hkdf-sha384.md` | Resolved at 3.5.6 (HMAC/HKDF-SHA384) | 📦 Archive |
| `archive/2026-06-06-x509-off-diagonal-ecdsa-verify.md` | Resolved at 3.7.5 (off-diagonal ECDSA) | 📦 Archive |
| `archive/2026-06-09-cyrius-6120-rebreaks-ni-paths-sigill.md` | Resolved at 3.7.8 (bundle opt-in stdlib includes) | 📦 Archive |
| `archive/2026-06-12-attestation-cert-pointer-arrays-undersized.md` | Resolved at 3.7.13 (byte-vs-slot fix) | 📦 Archive |
| `archive/2026-06-15-sigil-windows-entropy-not-via-getrandom.md` | Resolved at 3.7.15, archived at 3.8.0 (wine/ProcessPrng verified) | 📦 Archive |
| `archive/2026-06-23-err-io-enum-collision-namespace.md` | Resolved + archived at 3.9.x (err/io enum namespace collision) | 📦 Archive |
| `archive/2026-06-28-concurrent-tls-handshake-global-scratch-race.md` | Resolved at 3.9.6/3.9.7 (`cbank()` auto-lane banking + full concurrent-crypto banking) | 📦 Archive |
| `archive/2026-07-03-authenticode-pe-signing.md` | P1+P2 @3.10.0, P3 @3.11.1 (`efi_sigdb.cyr`), P4 @3.12.2 (`authenticode_pe_verify` + P-256 signer); archived this cycle, residual firmware-interop gate moved to the roadmap | 📦 Archive |
| `archive/2026-07-30-rsa-verify-uses-secret-exponent-ladder.md` | Consumer-filed (agnosai); resolved at 3.12.2 (`bn_mont_modexp_pub` + `mul64.cyr`), archived same day; see ADR 0008 | 📦 Archive |

---

## Tier 7 — Reference / Citations (`docs/sources.md`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `sources.md` | 2026-07-30 | ✅ Fresh | RFC / FIPS / NIST / SEC1 / Intel / AMD / Microsoft / UEFI citation index, refreshed this cycle. This row's own note was the stale one and is corrected: RFC 6979 **does** have an entry (`### ECDSA P-256 / P-384 deterministic signing — src/ecdsa_sign.cyr`, `:296`), the ML-DSA heading reads "default-on since 3.7.6; `-D SIGIL_PQC` is a back-compat no-op" (`:308`), the P-384 "planned for v3.6" parenthetical and the X.509 "RSA chain-link verify is not wired in yet (backlog)" claim are both gone, and the RNG section cites the `random_bytes` per-target boundary — getrandom / getentropy / ProcessPrng — rather than raw `/dev/urandom` (`:402`). Added this cycle: the RSA section split for verify-vs-sign with the `mul64.cyr` limb source called out (`:130`–`:186`, `:162`), `### Authenticode PE signing + verification` (`:394`, Microsoft Authenticode v1.0 + RFC 5652 CMS) and `### UEFI Secure Boot enrollment artifacts — src/efi_sigdb.cyr` (`:447`, UEFI §32.4.1 `EFI_SIGNATURE_LIST` / `EFI_VARIABLE_AUTHENTICATION_2`). |

---

## What's deliberately NOT here

These doc-types from the agnosticos first-party-documentation
catalog have not been earned yet — sigil's surface or release
cadence doesn't justify them:

- `docs/guides/` — task-oriented how-tos. Sigil's surface is
  internal-AGNOS today; downstream consumers integrate via
  AGNOS-specific entry points (`daimon`, `kavach`, `ark`, …),
  not via direct sigil-API how-tos. Earn this when a non-AGNOS
  consumer surfaces.
- `docs/examples/` — runnable example programs. `programs/smoke.cyr`
  serves the build-probe role; standalone usage examples
  earn this directory when a non-AGNOS consumer surfaces.
- `docs/development/sprint-history.md` — sigil has been on a
  per-release CHANGELOG cadence rather than a sprint-tagged
  dev log. The CHANGELOG plus per-cycle audit docs cover the
  same surface.
- `docs/development/process-notes.md` — CLAUDE.md serves this
  role today. Earn a separate doc when the day-to-day
  workflow accretes detail that doesn't fit the CLAUDE.md
  template's "Process" section.
- `docs/development/threat-model.md` / `docs/security/` —
  SECURITY.md has the threat-model paragraphs inline today.
  Earn a dedicated `docs/security/` subtree when a future
  cycle has a multi-doc threat-model write-up (e.g., a kavach
  integration threat model, a multi-tenant deployment threat
  model).
- `docs/development/migration-*.md` — sigil has been on a
  semver-disciplined release cadence with breaking changes
  documented in CHANGELOG. Earn when a major version cut
  requires its own migration narrative.
- `docs/development/performance.md` — `benches/history.csv`
  + benchmarks-rust-v-cyrius.md cover the perf surface.
  Earn a dedicated doc when the prose narrative gets long
  enough to outgrow the CHANGELOG entry.
- `docs/standards/` — every external standard sigil implements
  is cited inline in the affected module's header + indexed
  in `sources.md`. The standards themselves are external
  artifacts; sigil's not authoring any standards docs.
- `docs/compliance/` — N/A. No regulatory framework binds
  sigil today. CNSA 2.0 informs sigil's PQC inclusion but
  doesn't certify against sigil.
- `docs/faq.md` — no recurring questions yet (only-consumer
  loop is AGNOS; questions surface in the consumer repos'
  issues, not as sigil questions).
- `docs/index.md` / `docs/README.md` — **threshold crossed, decision
  outstanding.** The rule written here was "earn an index when the tree
  grows past ~60 files"; the tree now stands at **82 markdown files, 75
  of them under `docs/`** (38 of those are dated audit artifacts). README
  + the CLAUDE.md Docs pointer block still cover the landing surface, so
  this is flagged for the maintainer rather than actioned — either an index gets
  written or the threshold gets restated.
- `docs/articles/` — N/A. Sigil is a library, not a
  narrative-owning project.

When any of these are needed, the appropriate cycle's
documentation step (per CLAUDE.md § Work Loop step 8) is the
right place to add them — not a one-off doc-tree expansion.

---

## Programmatic gates (future)

The cyrius doc-health ledger maintains programmatic gates
(`_doc_size_currency_gate`, `_cap_drift_gate`, etc.) that
flag stale numeric claims. Sigil doesn't have these yet; the
3.4.1 sweep and this 3.12.2 sweep both flushed the version-number
drift manually — which is the second time the same drift class
has been caught by hand.

**Shipped (DONE)**: the **buried-deferral gate** is now enforced
natively by `cyrlint` (every AGNOS repo) — any untracked deferral
must cross-reference a CHANGELOG / issue / roadmap entry or carry
`#skip-lint` (the 2 `\uXXXX` false positives in `src/policy.cyr`
are suppressed). It was never a sigil-local script; superseded the
manual 3.7.7 buried-deferral sweep.

Candidates for future programmatic gates:

- **Assertion-count drift gate**: `state.md`'s "Total assertions:
  **1661**" cross-checked against `for t in tests/tcyr/*.tcyr;
  do cyrius test "$t"; done`. **No correction term** — as of 3.12.0 the
  3 `*_verify_full.tcyr` summaries survive a pipe/redirect, so the
  scripted grep-sum already covers all 64 files and adding their 44
  back would double-count (that correction applied pre-3.12.0 only).
  A gate should pin that fact so the caveat doesn't get re-introduced.
- **`.tcyr` file-count drift gate**: `state.md` + README carry the
  raw `ls tests/tcyr/*.tcyr | wc -l` count (**64** as of 3.12.2; the
  four added since 3.9.7 are `authenticode`, `efi_sigdb`, `blake2b`,
  `argon2`). A gate would pin the counting basis (`ls`-count, not a
  hand-maintained tally) and stop the tree-vs-doc drift from recurring
  each release.
- **Module-list drift gate**: `cyrius.cyml [lib].modules`
  cross-checked against `ls src/*.cyr` (this sweep caught
  `pem.cyr` missing from the dist bundle — a programmatic
  gate would have flagged it earlier). Currently clean: 65 modules
  vs 66 `src/*.cyr`, the difference being the `src/lib.cyr` umbrella.
- **Dist-version drift gate**: every `dist/*.cyr`'s `# Version:` header
  cross-checked against `VERSION`. CI has a stale-dist gate on the
  bundle content; a header check across all **14** bundles would catch a
  partial regen (one profile re-folded, the rest left behind) that a
  content diff on `dist/sigil.cyr` alone would miss.
- **Audit-cadence gate**: every released version has a matching
  `docs/audit/` artifact. Would have flagged the 3.10.0 → 3.12.1
  gap (six releases, no audit doc) as it opened rather than six
  releases later.
- **README test-count drift gate**: README's test-count claim
  cross-checked against `state.md`.

When a sweep catches the same drift class twice, file the gate
in `programs/check.cyr` (or wherever sigil's pre-release
verification lives).

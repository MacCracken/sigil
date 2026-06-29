---
name: Sigil Documentation Health
description: Living ledger of doc currency in the sigil repo — fresh / stale / archive / open-question, refreshed as docs are touched.
type: state
---

# Documentation Health — sigil

> **Last refresh**: 2026-06-29 (**3.9.7 — thread-safety banking arc
> completed**: banked every remaining concurrent-path crypto scratch so
> **every reachable concurrent crypto path is race-free** — streaming
> Poly1305 (`_cp_tag` last `fl_alloc` gone), ECDSA P-256/P-384 sign+verify
> incl. DER wrappers + RFC 6979 DRBG, bignum/rsa/tls12_prf; security: fixed
> the latent `secret var`-array DER-wrapper race (TLS CertificateVerify
> path) + closed an RSA-sign secret-residue gap; new
> `ecdsa_concurrent.tcyr` + `bignum_tls12_concurrent.tcyr` race-detectors,
> red→green; prior: 3.9.6 concurrent-TLS-handshake crash fix —
> `cbank()` auto-assigns a per-thread lane, `SIGIL_CRYPTO_BANKS` 8→64, new
> `concurrent_tls_handshake.tcyr`). The 3.6 cyrius-native-TLS arc closed at
> 3.6.8; the v3.7 EC-squeeze cycle closed at 3.7.17 (≤ 10 ms not reached,
> ~10.9 ms floor, parked per ADR 0006); the 3.8.x housekeeping bookend
> closed at 3.8.1 (**agnosys dependency dropped** — trust primitives
> internalized as `src/*_core.cyr` + `sys_error.cyr`/`sys_util.cyr`); the
> 3.9.x thread-safety-banking arc completed at 3.9.7.
> Per-version detail lives in
> [`CHANGELOG.md`](../CHANGELOG.md) and per-cycle audit docs in
> [`docs/audit/`](audit/) — the daily-stack notes that used to live here
> were retired in favour of those sources.
>
> **Headline changes since the last full row-refresh (3.4.1 inventory):**
> - **Version `3.9.7`**, cyrius pin **`6.3.5`** (was 3.5.4 / 6.0.3 at
>   the 3.4.1 inventory). Deps: **sakshi 2.3.0 ONLY** — **agnosys was
>   DROPPED at 3.8.1** (its trust primitives were internalized as
>   `src/*_core.cyr` + `src/sys_error.cyr` / `src/sys_util.cyr`);
>   `cyrius.cyml [deps]` no longer references agnosys.
> - **Audit floor: EMPTY** (cleared at 3.7.3, holds through 3.9.7 — see
>   state.md). The seven bump-allocator LOWs ADR 0003 batched are
>   resolved/reclassified; ADR 0003 is now closed-out. The 3.9.6/3.9.7
>   banking audits resolved every finding in-cycle (3.9.7: F1 MEDIUM
>   DER-wrapper race + F2 LOW RSA-sign residue, both fixed before ship).
> - **60 `.tcyr` files (`ls tests/tcyr/*.tcyr`) / 1576 assertions** (was
>   ~1178 at the 3.4.1 inventory). README + state.md now carry the true
>   **60**. Assertion-count caveat (unchanged): the 3 `*_verify_full`
>   tests print their summary to a tty-only path dropped under pipe/
>   redirect, so a scripted grep-sum yields 1532 across the other 57 files
>   and undercounts by their combined 44 — add it back for the true figure
>   1576 (see state.md "Counting note"). New modules/surfaces across
>   3.6/3.7/3.8/3.9: `bignum`, `tls12_prf`, `hmac_sha384`, `hkdf_sha384`,
>   `random`, the internalized trust `*_core.cyr` / `sys_error.cyr` /
>   `sys_util.cyr` (agnosys-drop @3.8.1), and the RSA / PSS / Solinas /
>   `_into` / off-diagonal-ECDSA / Karatsuba / ChaCha20+X25519-banking /
>   **full concurrent-crypto banking (3.9.x)** surfaces; new bench files
>   `tests/bcyr/{rsa,ecdsa_p384}.bcyr`; new tests
>   `tests/tcyr/{x509_offdiag,random,banking_concurrent,concurrent_tls_handshake,ecdsa_concurrent,bignum_tls12_concurrent}.tcyr`
>   (3 of those new in 3.9.x: `concurrent_tls_handshake` @3.9.6,
>   `ecdsa_concurrent` + `bignum_tls12_concurrent` @3.9.7).
> - **Audit docs**: 3.5.6 retro + 3.6.0–3.6.8 + 3.7.0–3.7.5 + 3.7.15–3.7.17
>   + 3.8.0 + the two 2026-06-29 banking audits (3.9.6 + 3.9.7) under
>   `docs/audit/` (per-cycle, dated artifacts).
> - **CHANGELOG / roadmap / state.md** are current through 3.9.7;
>   roadmap.md reflects the closed v3.7 EC-squeeze cycle (≤ 10 ms parked),
>   the 3.8.x housekeeping bookend (agnosys drop @3.8.1), and the
>   completed 3.9.x thread-safety-banking arc. README carries a
>   **Dependencies** section identifying the cyrius stdlib (auto + the
>   opt-in modules: `ct`, `keccak`, `thread`, `thread_local`, `random`)
>   plus sakshi (agnosys removed @3.8.1).
>
> **Refresh cadence**: when docs are touched, update the
> affected row inline. Full audit at minor closeout
> (next: the 3.9.x cycle close).
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

> Historical 3.4.1 snapshot; for current counts see the 3.9.7 header
> refresh above and the per-tier tables. The audit-doc count alone has
> grown from ~6 to **37** files since this snapshot.

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
| `README.md` | 2026-05-22 | ✅ Fresh | Rewritten this sweep; trimmed module-list duplication against `docs/architecture/overview.md`. |
| `CHANGELOG.md` | 2026-06-29 | ✅ Fresh | Source of truth per CLAUDE.md. **Through 3.9.7.** Refreshed every release. |
| `CLAUDE.md` | 2026-06-04 | ✅ Fresh | agnosticos `example_claude.md` template; durable rules only. 3.6.8 fixed the stale `benches/sigil.bcyr` → `tests/bcyr/sigil.bcyr` Quick-Start path. |
| `CONTRIBUTING.md` | 2026-05-22 | ✅ Fresh | Cyrius work loop + commit/hook rules; no Rust/cargo references. |
| `SECURITY.md` | 2026-06-29 | ✅ Fresh | Supported-versions table tops at **3.9.x** (current minor) / 3.8.x (prior); crypto-primitive surface lists RSA/PSS/GCM-IV/ChaCha20-Poly1305/X25519 + PQC default-on; audit-floor note holds EMPTY through 3.9.7 (3.9.6/3.9.7 banking findings resolved in-cycle). |
| `CODE_OF_CONDUCT.md` | (per upstream) | 🔵 Evergreen | Standard contributor covenant. |
| `LICENSE` | (per upstream) | 🔵 Evergreen | GPL-3.0-only. |
| `VERSION` | 2026-06-29 | ✅ Fresh | **`3.9.7`**. Bumped every release. |
| `cyrius.cyml` | 2026-06-29 | ✅ Fresh | `[lib].modules` extended across 3.6–3.9 (bignum, tls12_prf, hmac/hkdf_sha384, random, the internalized trust `*_core`/`sys_error`/`sys_util`, …); toolchain pin **`6.3.5`** (6.0.87 @3.7.8 → 6.2.x @3.7.13–3.7.15 → 6.2.48 → **6.3.5** @3.9.6). Deps: **sakshi 2.3.0 ONLY — agnosys DROPPED @3.8.1** (trust primitives internalized); `json` / `bigint` previously dropped at the 6.2.1 pin (bigint → bayan). |
| `dist/sigil.deps` + `cyrius distlib` | 2026-06-29 | ✅ Fresh | **@3.9.5+**: the bash `scripts/regen-dist.sh` retired — the sovereign `cyrius distlib` (≥6.2.48) folds `dist/sigil.cyr` AND emits the `dist/sigil.deps` sidecar (stdlib leaves, captured from the modules + the `src/lib.cyr` umbrella). Re-run `cyrius distlib` after a `[lib].modules` or VERSION change. |
| `dist/sigil.cyr` | 2026-06-29 | ✅ Fresh | Regenerated every release (last, after the VERSION bump). Header reads **`# Version: 3.9.7`**; carries the 3.7.8 NI `param_load` migration, the 3.7.15 `src/random.cyr` entropy boundary, the 3.8.x ChaCha20/X25519 banking + agnosys-drop internalized trust modules, and the **3.9.x full concurrent-crypto banking** (auto-lane `cbank()`, streaming Poly1305, ECDSA/bignum banking). |
| `benchmarks-rust-v-cyrius.md` | (closed) | 🔵 Evergreen | Frozen cross-implementation perf baseline; not rebuilt per release. |

---

## Tier 2 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-05-22 | ✅ Fresh | New this sweep. Index + candidates for the first numbered notes (currently empty; promote from CLAUDE.md's "Known Cyrius Compiler Quirks" when a reader hits one from grep — a strong candidate is now the 3.8.0 banked-secret-scratch "plain `var` + per-lane wipe, NOT `secret var`" invariant). |
| `overview.md` | 2026-05-27 | 🟡 Stale | Module map + TEE data-flow + parallel-batch framing; 3.5 arc added the four modern-crypto modules (poly1305, chacha20, chacha20poly1305, x25519). **Stale**: agnosys still listed as a dep — **agnosys was DROPPED at 3.8.1**; remove it from the module map / dep refs and add the internalized trust `*_core.cyr` + `sys_error.cyr` / `sys_util.cyr` modules. Also stale: stdlib list still names dropped `json`/`bigint` (now `bayan`); `src/random.cyr` (3.7.15 entropy boundary) absent from the map; the `[SIGIL_PQC]` gate + "without the flag … under cap" narrative describe a gate removed at 3.7.6; the parallel-batch note omits the 3.8.0 ChaCha20/X25519 banking and the **3.9.x full concurrent-crypto banking** (auto-lane `cbank()`, banks 8→64; per-lane zeroize, not `secret var`). |

---

## Tier 3 — ADRs (`docs/adr/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-05-22 | ✅ Fresh | New this sweep. ADR index + conventions (per agnosticos template). |
| `template.md` | 2026-05-22 | ✅ Fresh | New this sweep. Verbatim shape from `sit/docs/adr/template.md`. |
| `0001-retain-batch-mutex-until-caller-scratch.md` | 2026-05-27 | ✅ Fresh / 🔵 Evergreen-ish | Mutex-drop deferral rationale. Superseded by its own outcome — the `_sigil_batch_mutex` was dropped at **3.6.0** via per-worker banks (the banking pattern extended to ChaCha20/X25519 at 3.8.0; see the per-lane-zeroize-not-`secret var` rule below). |
| `0002-mldsa-cmdline-gate.md` | 2026-05-22 | ✅ Fresh | Captures the `-D SIGIL_PQC` gate rationale (cyrius preprocessor 1 MB cap). **Resolved**: cyrius 6.0.87 raised the cap; PQC went default-on at 3.7.6 and `-D SIGIL_PQC` is now a back-compat no-op. |
| `0003-bump-alloc-drift-acceptable-until-3-6.md` | 2026-06-16 | 🔵 Resolved | The batched-closure target it tracked is **done**: the audit floor was cleared at 3.7.3 (4 LOWs resolved via the `_into` API, 4 reclassified as correct init-once); holds EMPTY through 3.9.7. Confirm the ADR body carries a Resolved/Superseded marker. |

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

> **Table complete through 3.9.7** — every dated audit artifact under
> `docs/audit/` is itemised above. (There are no separate 3.9.0–3.9.5 audit
> docs; those bites were housekeeping/bundling/CVE-trust-chain work covered by
> CHANGELOG. The v3.7 cycle closed at 3.7.17, 3.8.0 shipped, and the 3.9.x
> thread-safety-banking arc closed at 3.9.7 with the two 2026-06-29 audits.)

**Audit floor**: **EMPTY (cleared at 3.7.3, holds through 3.9.7).** The seven (then eight,
+3.6.5 RSA SPKI block) bump-allocator LOWs ADR 0003 batched are
resolved (4 via the `_into` caller-scratch API) or reclassified as
correct init-once singletons (4). The 3.9.6 and 3.9.7 banking audits resolved
every finding in-cycle (3.9.7: F1 MEDIUM DER-wrapper `secret var`-array race +
F2 LOW RSA-sign secret-residue gap, both fixed before ship). Zero findings of
any severity outstanding.

Naming convention note: multi-cycle days disambiguate via
`YYYY-MM-DD-<version>-audit.md`; the bare `YYYY-MM-DD-audit.md` form is
reserved for the first cycle of a day.

---

## Tier 5 — Development (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-06-29 | ✅ Fresh | **Through 3.9.7**: the EC-squeeze cycle closed at 3.7.17 (4 levers shipped, ≤ 10 ms unreached / parked at ~10.9 ms per ADR 0006); ChaCha20/X25519 parallel-banking shipped at 3.8.0; **agnosys dropped at 3.8.1**; the 3.9.x thread-safety-banking arc completed at 3.9.7 (concurrent-TLS crash fix @3.9.6, streaming Poly1305 / ECDSA / bignum banking @3.9.7). Open backlog (carried forward, not buried): TDX/SGX in-quote PCK chain walk, exotic EC levers (asm / alt-representation, ADR 0006), retire-bank-indexing, scatter-store, CLMUL-GHASH, ML-KEM-768, `#derive(Serialize)` completeness, Windows-entropy `cass` ProcessPrng confirmation, retire-sysinfo. The buried-deferral gate is done — superseded by `cyrlint`'s native untracked-deferral check. |
| `state.md` | 2026-06-29 | ✅ Fresh | Live state snapshot — bumped every release. **Through 3.9.7**; audit floor EMPTY (holds through 3.9.7); EC-squeeze cycle closed (≤ 10 ms parked); 3.8.x = ChaCha20/X25519 banking + backlog-accuracy sweep + Windows-entropy issue archived + **agnosys dropped @3.8.1**; 3.9.x thread-safety-banking arc completed @3.9.7. |
| `3.0-handoff-2026-04-22.md` | 2026-04-22 | 📦 Archive | Frozen by design — closed-cycle handoff doc. |
| `3.0-scope.md` | (closed) | 📦 Archive | Frozen by design — closed-cycle scope doc. |
| `3.2-scope.md` | (closed) | 📦 Archive | Frozen by design — closed-cycle scope doc. |
| `3.2-tee-arc.md` | (closed 2026-05-26) | 📦 Archive | Frozen by design — closed-arc plan doc; arc summary moved to roadmap.md "Closed cycles" header at 3.2.6 close. |

---

## Tier 6 — Issues (`docs/development/issues/`)

Open issues are tracked artifacts (filed by consumers or
internal observation). Archived when resolved.

### Open issues

**0 open** — `docs/development/issues/` is clear as of 3.9.7 (only
`archive/` remains; **14 files** inside). The two most recent open items
were resolved and archived this cycle: the **err-io-enum-collision**
namespace issue and the **concurrent-tls-handshake global-scratch-race**
issue (the latter is the 3.9.6/3.9.7 banking work — `cbank()` auto-lane
banking + full concurrent-crypto banking). Earlier, the Windows-entropy
issue was archived at 3.8.0 after wine/ProcessPrng runtime verification.

### Archived issues

14 files under `docs/development/issues/archive/`:

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
| `archive/2026-06-23-err-io-enum-collision-namespace.md` | Resolved + archived this cycle (err/io enum namespace collision) | 📦 Archive |
| `archive/2026-06-28-concurrent-tls-handshake-global-scratch-race.md` | Resolved at 3.9.6/3.9.7 (`cbank()` auto-lane banking + full concurrent-crypto banking), archived this cycle | 📦 Archive |

---

## Tier 7 — Reference / Citations (`docs/sources.md`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `sources.md` | 2026-05-27 | 🟡 Stale | RFC / FIPS / NIST / SEC1 / Intel / AMD citation index. Has RFC 8017 (RSA v1.5/PSS) and RFC 5246 §5 (TLS 1.2 PRF). **Stale**: ML-DSA heading still says "opt-in via `-D SIGIL_PQC`" (default-on since 3.7.6); P-384 Solinas still parenthesised "(planned for v3.6 cycle)" (shipped 3.7.1); no RFC 6979 entry for `src/ecdsa_sign.cyr` (deterministic ECDSA signing); the Cryptographic-RNG section still cites raw `/dev/urandom` (replaced 3.7.15 by the single `_sigil_random_fill` boundary over stdlib `random_bytes` — getrandom/getentropy/ProcessPrng). |

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
  Earn a dedicated doc when the 3.6 Solinas cycle ships and
  the prose narrative gets long enough to outgrow the
  CHANGELOG entry.
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
- `docs/index.md` / `docs/README.md` — README + CLAUDE Docs
  pointer block cover the landing surface for the current
  ~38-file doc tree. Earn an index when the tree grows past
  ~60 files.
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
3.4.1 sweep flushed the obvious version-number drift
manually.

**Shipped (DONE)**: the **buried-deferral gate** is now enforced
natively by `cyrlint` (every AGNOS repo) — any untracked deferral
must cross-reference a CHANGELOG / issue / roadmap entry or carry
`#skip-lint` (the 2 `\uXXXX` false positives in `src/policy.cyr`
are suppressed). It was never a sigil-local script; superseded the
manual 3.7.7 buried-deferral sweep.

Candidates for future programmatic gates:

- **Assertion-count drift gate**: `state.md`'s "Total
  assertions: 1576" cross-checked against `for t in tests/tcyr/*.tcyr;
  do cyrius test "$t"; done` summary (caveat: the 3 `*_verify_full.tcyr`
  tty-only summaries drop 44 under any pipe/redirect — the gate must add
  them back; scripted grep-sum 1532 + 44 = 1576).
- **`.tcyr` file-count drift gate**: `state.md` + README now carry the
  raw `ls tests/tcyr/*.tcyr | wc -l` count (**60** as of 3.9.7; +3 in the
  3.9.x cycle: `concurrent_tls_handshake`, `ecdsa_concurrent`,
  `bignum_tls12_concurrent`). A gate would pin the counting basis
  (`ls`-count, not a hand-maintained tally) and stop the tree-vs-doc
  drift from recurring each release.
- **Module-list drift gate**: `cyrius.cyml [lib].modules`
  cross-checked against `ls src/*.cyr` (this sweep caught
  `pem.cyr` missing from the dist bundle — a programmatic
  gate would have flagged it earlier).
- **README test-count drift gate**: README's test-count claim
  cross-checked against `state.md`.

When a sweep catches the same drift class twice, file the gate
in `programs/check.cyr` (or wherever sigil's pre-release
verification lives).

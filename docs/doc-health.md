---
name: Sigil Documentation Health
description: Living ledger of doc currency in the sigil repo — fresh / stale / archive / open-question, refreshed as docs are touched.
type: state
---

# Documentation Health — sigil

> **Last refresh**: 2026-06-03 (**3.6.3 — RSA key parse + PKCS#1 v1.5 sign**).
> Added to `src/rsa.cyr`: `rsa_pubkey_from_der` (PKCS#1 + SPKI),
> `rsa_privkey_from_der` (PKCS#1 + PKCS#8, reusing x509 `der_walk`),
> `rsa_pkcs1v15_sign_sha256/384` (CT ladder + verify-after-sign); and
> `bn_mont_modexp` (constant-time Montgomery) to `src/bignum.cyr`.
> Tests `rsa.tcyr` +21 / `bignum.tcyr` +3 (50 files, 1305→1329).
> Audit `docs/audit/2026-06-03-3.6.3-rsa-keys-sign-audit.md` (LOW-1:
> base blinding deferred to 3.6.4). `sources.md` extended (RFC 8017
> §8.2.1/§A.1.2, Montgomery, Bellcore); `privkey.cyr` stale "3.5.10"
> comments refreshed to point at `rsa_privkey_from_der`. **CRT +
> blinding + a security audit pass = 3.6.4.** Earlier same-day
> refreshes (3.6.2 RSA verify, 3.6.1 PRF, 3.6.0 parallel verify) below.
>
> **Earlier 2026-06-03 (3.6.2 — RSA PKCS#1 v1.5 verify).**
> Added `src/bignum.cyr` (general big-int + modexp engine) +
> `src/rsa.cyr` (`rsa_pkcs1v15_verify_sha256/384`, RFC 8017) +
> `tests/tcyr/{bignum,rsa}.tcyr` (+12, KAT-validated to RSA-2048) +
> audit `docs/audit/2026-06-03-3.6.2-rsa-verify-audit.md` +
> `sources.md` (RFC 8017) + roadmap (RSA verify shipped; DER-parse /
> sign / PSS remain) + README/state.md. Suite 48→50 files,
> 1293→1305 assertions. Verify-only, public-data path (no CT/zeroize
> obligation; engine is single-threaded/unbanked, flagged not-for-sign).
> Same-day prior refreshes (3.6.1 PRF, 3.6.0 parallel verify) below.
>
> **Earlier 2026-06-03 (3.6.1 — TLS 1.2 PRF).**
> Added `src/tls12_prf.cyr` (RFC 5246 §5 `tls12_prf_sha256/384`) +
> `tests/tcyr/tls12_prf.tcyr` (+9, canonical IETF vectors) + audit
> `docs/audit/2026-06-03-3.6.1-tls12-prf-audit.md` + `sources.md`
> (RFC 5246 §5) + roadmap (PRF marked shipped, flagged to cyrius).
> Toolchain pin 6.0.52 → **6.0.53** (README + state.md + roadmap).
> Suite 47→48 files, 1284→1293 assertions. Same-day prior refresh
> (3.6.0 — parallel verify) summarized below.
>
> **Earlier 2026-06-03 (3.6.0 — parallel verify).**
> Dropped `_sigil_batch_mutex`; `sv_verify_batch` now runs the
> crypto concurrently (3.42× at 64 artifacts / 4 workers) on the
> back of cyrius 6.0.52 thread-local storage. This sweep: added
> `src/crypto_scratch.cyr` (per-thread crypto banks) + the
> `docs/audit/2026-06-03-3.6.0-parallel-verify-audit.md` audit +
> `benches/history.csv` row `v3.6-parallel-crypto`; per-thread
> banking landed across `sha_ni`/`sha256`/`sha512`/`bigint_ext`/
> `ed25519`/`trust`; toolchain pin 6.0.14 → **6.0.52**, agnosys
> 1.2.7 → 1.3.2, sakshi 2.2.5 → 2.2.6 (README + state.md + roadmap
> repinned); **ADR 0001 marked Superseded** (mutex dropped via TLS
> banks, not the caller-scratch design it anticipated). The three
> unshipped cyrius-native-TLS items (RSA, TLS 1.2 PRF, closeout)
> were renumbered 3.5.10–12 → **3.6.x** in `state.md` + `roadmap.md`.
> No new RFC/FIPS surface (threading refactor) — `sources.md`
> unchanged. Injected `lib/thread_local.cyr` + `src/crypto_scratch.cyr`
> includes into the 36 standalone test/bench files that compile a
> banked module. Prior refresh: 2026-05-27 (3.5.4 arc closeout); see
> git history for the 3.5.x sweep detail.
>
> **Refresh cadence**: when docs are touched, update the
> affected row inline. Full audit at minor closeout
> (next: the 3.6.x cyrius-native-TLS items → close).
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
| `CHANGELOG.md` | 2026-05-27 | ✅ Fresh | Source of truth per CLAUDE.md. Through 3.5.4. Refreshed every release. |
| `CLAUDE.md` | 2026-05-22 | ✅ Fresh | Restructured to agnosticos `example_claude.md` template. Durable rules only — volatile state moved to `docs/development/state.md`. |
| `CONTRIBUTING.md` | 2026-05-22 | ✅ Fresh | Rewritten this sweep — removed Rust/cargo references; Cyrius work loop + commit / hook rules from CLAUDE.md. |
| `SECURITY.md` | 2026-05-22 | ✅ Fresh | Rewritten this sweep — supported versions table moved to 3.4.x / 3.3.x; full crypto-primitive surface (added ECDSA, AES-GCM, HKDF, ML-DSA, X.509, PEM). |
| `CODE_OF_CONDUCT.md` | (per upstream) | 🔵 Evergreen | Standard contributor covenant. Refresh only when upstream covenant rev. |
| `LICENSE` | (per upstream) | 🔵 Evergreen | GPL-3.0-only. |
| `VERSION` | 2026-05-27 | ✅ Fresh | `3.5.4`. Bumped every release. |
| `cyrius.cyml` | 2026-05-27 | ✅ Fresh | 3.5 arc added `poly1305`, `chacha20`, `chacha20poly1305`, `x25519` to `[lib].modules`; toolchain pin bumped 6.0.1 → 6.0.3. (3.4.2 added `pem.cyr` + the test-layout comment block.) |
| `scripts/regen-dist.sh` | 2026-05-27 | ✅ Fresh | New at 3.4.2 (replaces the retired `cyrius distlib`). 3.5 arc added the four new crypto modules to its `MODULES` list (kept in sync with `cyrius.cyml`). Re-run when `[lib].modules` changes. |
| `dist/sigil.cyr` | 2026-05-27 | ✅ Fresh | Regenerated each 3.5.x bite. ~14,768 lines after the four crypto modules landed (14,086 at 3.4.2). |
| `benchmarks-rust-v-cyrius.md` | (closed) | 🔵 Evergreen | Frozen cross-implementation perf baseline. CLAUDE.md (Current Status, retired) declares this archived comparison — not rebuilt per release. |

---

## Tier 2 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-05-22 | ✅ Fresh | New this sweep. Index + candidates for the first numbered notes (currently empty; promote from CLAUDE.md's "Known Cyrius Compiler Quirks" when a reader hits one from grep). |
| `overview.md` | 2026-05-27 | ✅ Fresh | Module map + TEE data-flow + parallel-batch framing; 3.5 arc added the four modern-crypto modules (poly1305, chacha20, chacha20poly1305, x25519) to the map. |

---

## Tier 3 — ADRs (`docs/adr/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-05-22 | ✅ Fresh | New this sweep. ADR index + conventions (per agnosticos template). |
| `template.md` | 2026-05-22 | ✅ Fresh | New this sweep. Verbatim shape from `sit/docs/adr/template.md`. |
| `0001-retain-batch-mutex-until-caller-scratch.md` | 2026-05-27 | ✅ Fresh / 🔵 Evergreen-ish | Mutex-drop deferral rationale. **Amended 2026-05-27**: parallel-verify cycle renumbered 3.5 → 3.6 (the 3.5 slot became the modern-crypto arc). Re-read at 3.6 cycle open. |
| `0002-mldsa-cmdline-gate.md` | 2026-05-22 | ✅ Fresh | Captures the `-D SIGIL_PQC` gate rationale (cyrius preprocessor 1 MB cap). Re-read when cyrius raises the cap. |
| `0003-bump-alloc-drift-acceptable-until-3-6.md` | 2026-05-27 | ✅ Fresh | Seven open LOW findings as a batched closure target. **Amended 2026-05-27**: cycle renumbered 3.6 → 3.7 (filename keeps its immutable NNNN index). Re-read at 3.7 cycle open. |

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

**Audit floor**: 7 open LOW findings (bump-allocator
lifetime), batched closure at **3.7** per ADR 0003 (renumbered
from 3.6 when the 3.5 slot became the modern-crypto arc). Zero
CRITICAL / HIGH / MEDIUM outstanding.

Naming convention note: multi-cycle days (e.g. 2026-05-22
shipped 3.3.0 + 3.4.0 + 3.4.1) disambiguate via
`YYYY-MM-DD-<version>-audit.md`. The bare `YYYY-MM-DD-audit.md`
form is reserved for the first cycle of a day.

---

## Tier 5 — Development (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-05-27 | ✅ Fresh | 3.5 arc: new v3.5 crypto cycle (Poly1305/ChaCha20/AEAD/X25519, all shipped), parallel-verify slid to v3.6 and perf/Solinas to v3.7; 3.5.4 closeout note added. |
| `state.md` | 2026-05-27 | ✅ Fresh | Live state snapshot — bumped every release. Through 3.5.4; in-flight slots show the shipped 3.5 bites + planned 3.6/3.7 gating. |
| `3.0-handoff-2026-04-22.md` | 2026-04-22 | 📦 Archive | Frozen by design — closed-cycle handoff doc. |
| `3.0-scope.md` | (closed) | 📦 Archive | Frozen by design — closed-cycle scope doc. |
| `3.2-scope.md` | (closed) | 📦 Archive | Frozen by design — closed-cycle scope doc. |
| `3.2-tee-arc.md` | (closed 2026-05-26) | 📦 Archive | Frozen by design — closed-arc plan doc; arc summary moved to roadmap.md "Closed cycles" header at 3.2.6 close. |

---

## Tier 6 — Issues (`docs/development/issues/`)

Open issues are tracked artifacts (filed by consumers or
internal observation). Archived when resolved.

### Open issues

| File | Filed | Status |
|---|---|---|
| `2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md` | 2026-05-10 | 🔴 Open — upstream-blocked (cyrius `asm`-block global-symbol pseudo). Workaround: 3.2.0 runtime self-test gate. Closure tied to roadmap backlog "NI dispatch structural fix". |
| `2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md` | 2026-05-10 | 🟢 Mostly closed by 3.2.x TEE arc + 3.4 verify_full completion. Re-verify scope against current consumer integration shape next time kavach work touches sigil. |
| `2026-05-11-tlsh-distance-segfault-phylax.md` | 2026-05-11 | 🔴 Open — consumer-filed (phylax). Pending phylax-side repro. |

### Archived issues

| File | Resolution | Status |
|---|---|---|
| `archive/2026-04-22-cyrius-fixup-cap-raises.md` | Resolved upstream | 📦 Archive |
| `archive/2026-04-25-sha-ni-compress-design.md` | Resolved at 2.9.x SHA-NI landing | 📦 Archive |
| `archive/2026-05-10-ed25519-verify-aarch64-accepts-wrong-pk.md` | Resolved at 3.0.x cycle | 📦 Archive |

---

## Tier 7 — Reference / Citations (`docs/sources.md`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `sources.md` | 2026-05-27 | ✅ Fresh | RFC / FIPS / NIST / SEC1 / Intel / AMD citation index for every primitive. 3.5 arc added ChaCha20 + ChaCha20-Poly1305 (RFC 8439 §2.3/§2.4/§2.8) and X25519 (RFC 7748). |

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
manually. Candidates for future programmatic gates:

- **Assertion-count drift gate**: `state.md`'s "Total
  assertions: 1178" cross-checked against `for t in tests/tcyr/*.tcyr;
  do cyrius test "$t"; done` summary.
- **Module-list drift gate**: `cyrius.cyml [lib].modules`
  cross-checked against `ls src/*.cyr` (this sweep caught
  `pem.cyr` missing from the dist bundle — a programmatic
  gate would have flagged it earlier).
- **README test-count drift gate**: README's test-count claim
  cross-checked against `state.md`.

When a sweep catches the same drift class twice, file the gate
in `programs/check.cyr` (or wherever sigil's pre-release
verification lives).

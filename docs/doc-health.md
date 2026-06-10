---
name: Sigil Documentation Health
description: Living ledger of doc currency in the sigil repo — fresh / stale / archive / open-question, refreshed as docs are touched.
type: state
---

# Documentation Health — sigil

> **Last refresh**: 2026-06-09 (**3.7.8 — cyrius-6.1.20 bundle-consumer
> SIGILL fix (README opt-in stdlib-include docs + NI `param_load` fix),
> ECDSA verify scalar-mult speedup (~2× both curves), README
> dependency-section sweep, and a roadmap completed-item cleanup**; prior:
> 3.7.7 buried-deferral sweep, 3.7.6 PQC default-on, 3.7.5 off-diagonal
> ECDSA verify). The 3.6 cyrius-native-TLS arc closed at 3.6.8 and the v3.7
> cycle is in progress; this is a consolidated refresh across the whole
> 3.6.5 → 3.7.8 run.
> Per-version detail lives in
> [`CHANGELOG.md`](../CHANGELOG.md) and per-cycle audit docs in
> [`docs/audit/`](audit/) — the daily-stack notes that used to live here
> were retired in favour of those sources.
>
> **Headline changes since the last full row-refresh (3.4.1 inventory):**
> - **Version `3.7.8`**, cyrius pin **`6.1.20`** (was 3.5.4 / 6.0.3 at
>   the 3.4.1 inventory). Deps agnosys 1.3.2, sakshi 2.2.6.
> - **Audit floor: EMPTY** (cleared at 3.7.3, holds through 3.7.5 — see
>   state.md). The seven bump-allocator LOWs ADR 0003 batched are
>   resolved/reclassified; ADR 0003 is now closed-out.
> - **53 `.tcyr` files / 1459 assertions** (was ~1178 at the 3.4.1
>   inventory). New modules across 3.6/3.7: `bignum`, `tls12_prf`,
>   `hmac_sha384`, `hkdf_sha384` and the RSA / PSS / Solinas / `_into` /
>   off-diagonal-ECDSA surfaces; new bench files
>   `tests/bcyr/{rsa,ecdsa_p384}.bcyr`; new test `tests/tcyr/x509_offdiag.tcyr`.
> - **Audit docs**: 3.5.6 retro + 3.6.0–3.6.8 + 3.7.0–3.7.5 added under
>   `docs/audit/` (per-cycle, dated artifacts).
> - **CHANGELOG / roadmap / state.md** are current through 3.7.8;
>   roadmap.md "Outstanding work" was re-cleaned 2026-06-09 (the resolved
>   cyrius-6.1.20 P1, x509-complete note, done NI-dispatch fix, and done
>   PQC-default item removed; EC scalar-mult trimmed to its open ≤ 10 ms
>   squeeze). README gained a **Dependencies** section identifying the
>   cyrius stdlib (auto + the four opt-in modules) plus sakshi/agnosys.
>
> The per-tier tables below predate this run and are **partially stale
> on dates/counts** (flagged inline where load-bearing); a full
> row-by-row re-sweep is the next doc-health task (queued for the v3.7
> closeout).
>
> **Refresh cadence**: when docs are touched, update the
> affected row inline. Full audit at minor closeout
> (next: the v3.7 perf cycle close).
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
| `CHANGELOG.md` | 2026-06-07 | ✅ Fresh | Source of truth per CLAUDE.md. **Through 3.7.7.** Refreshed every release. |
| `CLAUDE.md` | 2026-06-04 | ✅ Fresh | agnosticos `example_claude.md` template; durable rules only. 3.6.8 fixed the stale `benches/sigil.bcyr` → `tests/bcyr/sigil.bcyr` Quick-Start path. |
| `CONTRIBUTING.md` | 2026-05-22 | ✅ Fresh | Cyrius work loop + commit/hook rules; no Rust/cargo references. |
| `SECURITY.md` | 2026-05-22 | 🟡 Stale | Supported-versions table topped at 3.4.x/3.3.x — refresh to 3.7.x at the v3.7 closeout. Crypto-primitive surface predates the RSA/PSS/GCM-IV additions. |
| `CODE_OF_CONDUCT.md` | (per upstream) | 🔵 Evergreen | Standard contributor covenant. |
| `LICENSE` | (per upstream) | 🔵 Evergreen | GPL-3.0-only. |
| `VERSION` | 2026-06-07 | ✅ Fresh | **`3.7.7`**. Bumped every release. |
| `cyrius.cyml` | 2026-06-07 | ✅ Fresh | `[lib].modules` extended across 3.6/3.7 (bignum, tls12_prf, hmac/hkdf_sha384, …); toolchain pin **`6.0.87`** (6.0.3 → .14 → .52/.53 → .58 → .61 → .62 → .87 over the 3.5→3.7 run; 3.7.5 bump 6.0.62 → 6.0.87). |
| `scripts/regen-dist.sh` | 2026-06-04 | ✅ Fresh | Replaces the retired `cyrius distlib`. `MODULES` kept in sync with `cyrius.cyml [lib].modules`. Re-run after every VERSION bump (embeds the header). |
| `dist/sigil.cyr` | 2026-06-07 | ✅ Fresh | Regenerated every release (last, after the VERSION bump). Regenerated at 3.7.7 (header bump; comment-only src changes). |
| `benchmarks-rust-v-cyrius.md` | (closed) | 🔵 Evergreen | Frozen cross-implementation perf baseline; not rebuilt per release. |

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
| `0003-bump-alloc-drift-acceptable-until-3-6.md` | 2026-06-04 | 🟡 Superseded-ish | The batched-closure target it tracked is **done**: the audit floor was cleared at 3.7.3 (4 LOWs resolved via the `_into` API, 4 reclassified as correct init-once). Mark Resolved/Superseded in the ADR body at the v3.7 closeout. |

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

> **Stale table** — the per-audit rows above stop at the 3.5 arc. The
> 3.5.6 retro + 3.6.0–3.6.8 + 3.7.0–3.7.5 audit docs (all dated
> artifacts under `docs/audit/`) are not yet itemised here; full
> re-sweep queued for the v3.7 closeout.

**Audit floor**: **EMPTY (cleared at 3.7.3, holds through 3.7.7).** The seven (then eight,
+3.6.5 RSA SPKI block) bump-allocator LOWs ADR 0003 batched are
resolved (4 via the `_into` caller-scratch API) or reclassified as
correct init-once singletons (4). Zero findings of any severity
outstanding.

Naming convention note: multi-cycle days disambiguate via
`YYYY-MM-DD-<version>-audit.md`; the bare `YYYY-MM-DD-audit.md` form is
reserved for the first cycle of a day.

---

## Tier 5 — Development (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-06-07 | ✅ Fresh | Through 3.7.7: the P1 off-diagonal ECDSA, PQC-default, and buried-deferral-sweep items are **closed**; Backlog grew (ChaCha20/X25519 parallel, TDX chain walk, scalar-inversion addition-chain, `bn_modexp` dead-code). Open: buried-deferral gate, EC scalar-mult speedup, bench re-run, cyrius-gated backlog. |
| `state.md` | 2026-06-07 | ✅ Fresh | Live state snapshot — bumped every release. **Through 3.7.7**; audit floor EMPTY; in-flight = buried-deferral gate + EC scalar-mult + bench re-run. |
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

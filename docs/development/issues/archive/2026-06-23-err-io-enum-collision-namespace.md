# `ERR_IO` enum constant collides ecosystem-wide — namespace `SigilError` as `SIGIL_ERR_*`

**Filed:** 2026-06-23 (by a hoosh consumer — hoosh 2.4.7 toolchain bump to cyrius 6.2.37)
**Severity:** Medium — `last-definition-wins` build warning today; latent
value-dependent-logic hazard when sigil is compiled alongside another lib that
also defines a bare `ERR_IO`.
**Component:** `src/error.cyr:15` (`enum SigilError { … ERR_IO = 6; … }`) → `dist/sigil.cyr:4141`.
**sigil's role: FIX OWNER for its own error enum.** Part of a coordinated
ecosystem-wide error-enum namespacing effort (see Cross-references).
**Repos:** sigil `3.9.2` (mirrors filed in yukti, bote, sakshi, ai-hwaccel; majra
has a sibling `ratelimit_*` rename issue).

## Summary

Cyrius enum members are **global constants** — the enum name (`SigilError`) does
*not* namespace them. So sigil's `ERR_IO` is the bare global `ERR_IO`, and it
collides by name (with a *different value*) against every other ecosystem lib
that defines its own `ERR_IO`:

| Library | Enum | `ERR_IO` | Source |
|---|---|---|---|
| **sigil 3.9.2** | `SigilError` | **6** | `src/error.cyr:15` → `dist/sigil.cyr:4141` |
| yukti 2.2.6 | `YuktiErrorKind` | 14 | `src/error.cyr:25` → `dist/yukti.cyr:77` |
| bote 2.7.6 | `BoteErrTag` | 11 | `src/error.cyr:16` → `dist/bote-core.cyr:24` |

Cyrius include semantics are textual paste + **last-definition-wins (with a
warning)**. A consumer that includes sigil **and** bote (e.g. hoosh, which uses
sigil for sha256/HMAC/audit-chain *and* bote-core for MCP) gets exactly ONE
global `ERR_IO` — whichever bundle is included last. Observed in hoosh's build:

```
warning:src/vendor/bote-core.cyr:24: duplicate symbol 'ERR_IO' redefined with conflicting value (last definition wins)
```

## Why this is more than a warning

Within one compiled binary there is only ONE `ERR_IO` value after last-wins, so
intra-module comparisons stay self-consistent. The latent hazard is
**value-dependent logic**: any code that serializes the numeric code (JSON/wire
error responses), uses it as a table/array index, or maps it across a module
boundary silently uses the *other* lib's integer. If bote's `ERR_IO = 11` wins,
sigil code returning `ERR_IO` now emits `11` where it documented `6`.

## The precedent already exists in-tree

The stdlib already namespaces exactly these to avoid the clash —
`TLS_ERR_IO` (tls_native), `PATRA_ERR_IO` (patra), `SANDHI_ERR_TIMEOUT` (sandhi).
sigil should follow the same convention.

## Recommended fix

Prefix the **entire `SigilError` enum** `ERR_* → SIGIL_ERR_*` (not just `ERR_IO`
— `ERR_NONE`/`ERR_PARSE`-style siblings collide with other libs too), and update
sigil's internal callers (`sigil_is_ok`/`sigil_is_err`/`sigil_err` and every
`ERR_*` reference under `src/`). Regenerate `dist/sigil.cyr`. This is a breaking
change to sigil's exported error surface → suggest **sigil 3.10.0**, optionally
keeping bare aliases for one minor if downstreams compare against `ERR_*`
directly.

## Interim (consumer-side)

hoosh tolerates the warning today (last-wins is currently benign for its reachable
paths — it doesn't serialize sigil's `ERR_IO`). The upstream rename retires the
warning and the latent hazard for all sigil+bote consumers.

## Cross-references

- yukti `docs/development/issues/2026-06-23-err-enum-collision-namespace.md` (ERR_IO + ERR_TIMEOUT).
- bote `docs/development/issues/2026-06-23-err-io-enum-collision-namespace.md`.
- sakshi / ai-hwaccel `…2026-06-23-err-timeout-enum-collision-namespace.md`.
- Precedent: bote × ai-hwaccel `registry_new` collision (`2026-06-11-registry-new-collision.md`).

---

**CLOSED (2026-06-29) — sigil-side shipped at 3.9.4.** The recommended rename
landed at **3.9.4**: the entire `SigilError` + `sys_error` enum was namespaced
`ERR_* → SIGIL_ERR_*` (BREAKING; no compat aliases; enum values unchanged) —
zero bare `ERR_*` definitions remain in `src/` (verified: `src/error.cyr` uses
`SIGIL_ERR_*`, `SIGIL_ERR_IO = 6`). The "suggest sigil 3.10.0" framing is
superseded — it shipped as a patch. See CHANGELOG `[3.9.4]`. Archived.

> **ARCHIVED — RESOLVED (2026-06-15).** Sigil-owned. The byte-vs-slot OOB-write at all 6 cert-pointer-array sites (sgx/tdx/sev_snp) fixed in **3.7.13** via the `var name: i64[4]` slot spelling; present in src + 3.7.15 dist.
> Issue cross-walk: 3.7.15 triage + `docs/audit/2026-06-15-3.7.15-windows-entropy-audit.md`.

# Attestation cert-pointer arrays `parsed[4]`/`inters[4]` are byte-undersized (×6 sites)

**Filed:** 2026-06-12
**Severity:** MEDIUM (HIGH on the SGX/TDX/SNP attestation paths) — silent OOB writes
into adjacent statics during cert-chain assembly
**Status:** OPEN — fix below. **The working tree is in a MIXED, half-edited state —
reset first (see bottom).**

## The bug

The three `*_quote_verify_full_into` / `*_report_verify_full_into` functions build a
local array of cert **pointers** (8 bytes each) using the slot idiom
`store64(&parsed + i*8, …)` / `load64(&parsed + i*8)`, plus `memset(&inters, 0, 32)`:

| File | fn | arrays |
|---|---|---|
| `src/sgx.cyr` | `sgx_quote_verify_full_into` | `parsed[4]`, `inters[4]` |
| `src/sev_snp.cyr` | `snp_report_verify_full_into` | `parsed[4]`, `inters[4]` |
| `src/tdx.cyr` | `tdx_quote_verify_full_into` | `parsed[4]`, `inters[4]` |

Cyrius `var[N]` is **byte-sized**, so `[4]` reserves **8 bytes = 1 pointer slot**,
not 4. Writing slots 1..3 (`&x + 8/16/24`) and `memset(&inters, 0, 32)` both run
past the 8-byte buffer into adjacent statics. Works by luck today (latent until a
layout shift) — the daimon route-404 class, flagged by the cyrius v6.2.1 audit.
(Note: the cyrius-side audit ran on the vendored fold and caught only 5 of these;
the **6th** — snp `parsed[4]` — was found checking the source. Fix all 6.)

## The fix: byte-bump to `[32]` (match sigil's own convention; pin stays 6.1.20)

sigil already byte-sizes pointer/record arrays — e.g. `src/sgx.cyr:454`
`var chain[64];  # 4 entries × 16 bytes`. The consistent fix is the same:

```
var parsed[32];   # 4 cert-pointer slots = 32 bytes (was [4]=8B)
var inters[32];   # 4 cert-pointer slots = 32 bytes (memset(&inters,0,32) needs 32B)
```

- **Pin stays 6.1.20.** `[32]` is a toolchain-agnostic byte resize. Do NOT use
  `var parsed: i64[4]` (the cyrius 6.2.1 element-typed-array spelling) — it would
  force a 6.1.20 → 6.2.1 pin jump (and sigil's `[deps]` lists `json`, carved into
  bayan at 6.1.25, so a 6.2.x jump has its own resolution work first — separate).

Verify + cut (3.7.13):
```sh
grep -rn 'var \(parsed\|inters\)\[' src/    # expect six `[32]`
sh scripts/regen-dist.sh && sh scripts/check.sh && cyrius bench tests/bcyr/sigil.bcyr
```

## Working-tree note — RESET BEFORE APPLYING

The working tree is mid-edit and inconsistent (a session switched some sites to
`[32]`, left others at `i64[4]`):
```sh
git -C . status --short        # src/sev_snp.cyr, src/sgx.cyr, src/tdx.cyr modified
git restore src/sev_snp.cyr src/sgx.cyr src/tdx.cyr   # reset to HEAD, then apply the 6 `[32]` edits uniformly
```
Apply all six as `[32]` (above), keep pin 6.1.20, regen dist, run check.sh + bench,
add a CHANGELOG `### Security` entry, bump VERSION 3.7.12 → 3.7.13.

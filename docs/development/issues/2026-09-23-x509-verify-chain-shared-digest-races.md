# `x509_verify_chain` hashes every TBS into one shared buffer — a forged link verifies under concurrency

**Filed:** 2026-09-23 (3.13.0) · **Severity:** HIGH · **Status:** open

**Where:** `src/x509.cyr` `_xvl_digest` / `_xvl_init` (~1160), used by `_x509_verify_link`. Reached
from `x509_verify_chain` in `src/sgx.cyr` (~512), `src/tdx.cyr` (~512) and `src/sev_snp.cyr` (~378) —
i.e. every `*_verify_full` / `*_verify_full_into`.

`_x509_verify_link` writes each certificate's TBS digest into the module-global `_xvl_digest`
(lazily `alloc(48)`), then checks the issuer signature over it. Two concurrent verifies share that
buffer, so one can check its signature against the other's digest. A probe during the 3.13.0 work
accepted a TBS-mutated leaf carrying the genuine CA signature **4 times, and falsely rejected a
genuine leaf 3 times, in 8 × 400 concurrent verifies** — the shape of the 3.12.3 RSA shared-lane
bypass.

3.13.0 fixed the same race in `sgx_quote_verify_with_pck`, `tdx_quote_verify_with_pck` and
`snp_report_verify`, not here, so `*_verify_full_into` is still unsafe to call from more than one
thread (stated in CHANGELOG 3.13.0 and in `tests/tcyr/tee_verify_concurrent.tcyr`'s header).

**Fix direction (not applied):** a function-local `var digest[48];` in `_x509_verify_link` (well
inside the frame budget); delete `_xvl_digest` / `_xvl_init`; add a race-detector group to
`tests/tcyr/tee_verify_concurrent.tcyr` — even threads verify the genuine PCK leaf link, odd threads
a leaf with one TBS byte flipped and the genuine signature.

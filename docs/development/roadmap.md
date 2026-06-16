# Sigil Roadmap

Forward-looking work only. For shipped items and per-version detail see
[CHANGELOG.md](../../CHANGELOG.md) and [state.md](state.md) ("Recently
shipped").

## Outstanding work

The only open items. The 3.6 cyrius-native-TLS arc and most of the v3.7
perf cycle have shipped — see "Closed cycles" below + CHANGELOG.

> **3.8.0 — opened 2026-06-16 (housekeeping bookend to 3.7.x).** The
> `docs/development/issues/` folder is now **CLEAR** (all 12 archived): the
> Windows-entropy issue was archived after **wine/ProcessPrng runtime
> verification** (sigil-side done; `cass` + cyrius `tls_native` residual tracked
> below). 3.8.0 ships the **ChaCha20 + X25519 parallel-path banking** (the one
> real buildable Backlog item, now done + race-tested) and a **backlog-accuracy
> sweep**: the TDX/SGX in-quote PCK walk was found already-shipped (stale note →
> marked DONE), `bn_modexp` resolved (KEEP as the modexp test-oracle), and the
> scatter-store comb re-scoped as MOOT/parked (it guards a public value). The
> **3.7.x EC-squeeze perf cycle is closed** — all levers shipped, ≤ 10 ms not
> reached (~10.9 ms floor, parked; see below).

**Verification follow-up — Windows entropy (3.7.15)**

- [~] **Windows entropy fix (3.7.15) — runtime-VERIFIED via Windows-PE + wine
      (2026-06-16); only the `cass` formality + the cyrius-owned `tls_native`
      re-fold remain.** All entropy routes through `_sigil_random_fill` / stdlib
      `random_bytes` → ProcessPrng on Windows. **Proven by cross-compiling to
      Windows PE (`cyrius build --win`) and RUNNING under wine** (which implements
      bcryptprimitives.dll!ProcessPrng): `random.tcyr`, `ed25519.tcyr`, and the
      consumer-shape `programs/win_entropy_probe.cyr` (dist + opt-in libs) all
      exit 0 — fresh, unique entropy + working ed25519 keygen on the Windows
      binary; the same probe is green on Linux. **sigil-side is done & verified.**
      Residual (NOT sigil source work): a confirmation run on real Windows
      (**`cass`**) vs wine, and the `tls_native` client-nonce half (cyrius-owned —
      re-fold `lib/sigil.cyr` + re-verify the native-TLS handshake). Issue
      [`2026-06-15-sigil-windows-entropy-not-via-getrandom.md`](issues/archive/2026-06-15-sigil-windows-entropy-not-via-getrandom.md)
      stays **open** until `cass` + the downstream re-fold confirm.

**Tooling / process**

- [x] **Buried-deferral gate — DONE, superseded by `cyrlint`.** Instead of a
      sigil-local grep gate, the deferral-vocabulary check was built natively into
      **`cyrlint`** (the cyrius linter) — so it covers **every** AGNOS first-party
      repo, not just sigil, which is strictly better than a per-repo script.
      `cyrlint` flags any untracked deferral (`deferred` / `TODO` / `FIXME` / `XXX`
      / `HACK` / …) as `untracked '<token>' (cross-reference a
      CHANGELOG/issue/roadmap entry, or #skip-lint)` — exactly the "do the work,
      surface it, or skip it explicitly" behavior this gate intended, now enforced
      by the standard lint step (CLAUDE.md P(-1) §1 cleanliness). The two known
      `\uXXXX` false positives (`src/policy.cyr`, JSON unicode-escape notation, not
      a deferral) are suppressed at source with `#skip-lint`; `cyrlint src/*.cyr`
      reports **0 untracked deferrals**.

**v3.7 — perf (OPEN)**

- [ ] **EC scalar-mult — ≤ 10 ms P-256 squeeze.** The comb-G + windowed-Q
      speedup shipped in 3.7.8 (~2×); the **inversion lever (1, below) is now
      DONE** (3.7.16), bringing `ecdsa_p256_verify` to **11.37 ms** (clean
      A/B: generic-inverse 12.50 → 11.37, ~9%, cyrius 6.2.12). The **≤ 10 ms
      target is still open (11.37 ms)** — levers 2–3 remain, in rising risk:
      1. ~~**Inversion addition-chain** for `fn_p256_inv` (s⁻¹) and the
         `pt_to_affine` field inverse.~~ **DONE (3.7.16).** Field inverse
         `fp_p256_inv` → fixed `2^k-1`-block chain (~255 sq + 12 mul); scalar
         inverse `fn_p256_inv` → 4-bit fixed window (`n-2` is irregular, no clean
         optimal chain — but each saved mul avoids an expensive long-division
         `n_reduce`, the real cost). Generics retained as `_*_generic` KAT
         oracles; +7 differential/`a*inv≡1` assertions. (Closes the standalone
         "Scalar-inversion addition-chain" Backlog item too.) An optimal
         hand-derived `a^(n-2)` chain could squeeze a bit more than the window
         but was deemed too derivation-risky for this bite.
      2. **Mixed Jacobian+affine addition.** **Comb-G part DONE (3.7.16):**
         the fixed-base `u1·G` comb table is now affine and its 64 hot-path adds
         use `pt_add_mixed` (madd-2007-bl, ~7M+4S vs ~11M+5S); isolated A/B
         11.32 → 11.00 ms (~2.8%). KAT-gated (`pt_add_mixed == pt_add` over 24
         pairs + double / −Q edges). **Bounded by design** — verify is dominated
         by the `u2·Q` window's 256 doublings + the inversions, which mixed-add
         doesn't touch. **`u2·Q`-window part DONE (3.7.17):** the
         15-entry Q-table build uses `pt_add_mixed` (Q affine), a **Montgomery
         batch inversion** (1 field inv + ~3·14 muls) takes the table affine, and
         the 64-window loop uses `pt_add_mixed` + skips the identity nibble.
         **Net ~0.1 ms only** (~11.00 → ~10.89): the single batch field-inversion
         (~267 ops) nearly cancels the mixed-add savings (~316 ops) — the roadmap's
         earlier ~0.3–0.5 ms estimate was optimistic (it ignored that inversion
         overhead). Kept anyway (maintainer's call). KAT: `p256_scalarmul_var ==
         pt_scalarmul` over 16 random (k,Q). Neither sub-slice crosses 10 ms alone;
         lever 3 (Karatsuba) is what gets there.
      3. ~~**Karatsuba `u256_mul_full`**~~ **DONE (3.7.17).** The 256×256→512
         multiply under all 256-bit ECC (Ed25519/X25519/ECDSA) moved schoolbook →
         Karatsuba (12 × 64×64 via `z1=(aL+aH)(bL+bH)−z0−z2`). **But only ~3–4%**,
         not the hoped ~15–25%: at 256-bit, fast hardware 64×64 multiply means the
         carry/addition overhead caps Karatsuba's gain (it only pays off at much
         larger bignum sizes). Ed25519 verify 6.90 → 6.63 ms, P-256 verify ~11.58 →
         ~11.25 ms. Thread-safe (scalar-local, batch-path safe); schoolbook retained
         as the KAT oracle. Conclusively verified (KAT + full sig suite + 5-lens
         adversarial carry review, millions of differential cases). Audit:
         `docs/audit/2026-06-16-3.7.17-karatsuba-multiply-audit.md`.
      The shipped comb + inversion paths are **verify-only / non-CT** (public
      exponents/scalars); keep them off any secret path (pairs with the
      "scatter-store comb" backlog item if that ever changes).

      **STATUS (3.7.17): all known levers (1, 2a, 2b, 3) SHIPPED; ≤ 10 ms NOT
      reached.** `ecdsa_p256_verify` floored at **~10.9 ms** (12.50 → ~10.9, ~13%
      cumulative). The verify is doubling/inversion-bound and Karatsuba caps at
      ~3–4% at this size, so the known approaches are **exhausted**. Crossing 10 ms
      would need an exotic lever (hand-written asm multiply, an alternative point
      representation / batched-affine GLV-style scheme, or a redesigned doubling) —
      none scoped. **Decision for Robert: close the ≤ 10 ms item as "not reachable
      with current approaches" or open an exotic-lever investigation.** Not closed
      unilaterally.

- [x] **Re-run the full crypto bench suite — DONE (3.8.0 cycle close).** Full
      `tests/bcyr/*.bcyr` sweep captured, no regressions: `ecdsa_p256_verify`
      ~11.6 ms, `ecdsa_p384_verify` ~26.7 ms, `ed25519_verify` ~7.2 ms /
      sign ~1.2 ms, sha256-NI 545 ns, aes-gcm-1kb ~790 µs, fp_mul 970 ns,
      mldsa_ntt 11 µs. Healthy across primitives + verify paths.

**Backlog — unscheduled** (open; gated as noted)

The following were surfaced from in-source deferral comments in the 3.7.7
buried-deferral sweep (previously tracked only in code comments — now
promoted here so they are visible, not buried):

- [x] **ChaCha20 + X25519 parallel-path banking — DONE (3.8.0).** Both
      (`src/chacha20.cyr` st/ws/ks, `src/x25519.cyr` W/ub/base) are now
      per-worker banked via the 3.6 `cbank()` lane mechanism
      (`src/crypto_scratch.cyr`) — concurrent callers use disjoint lanes.
      Plain `var` + an explicit **per-lane** zeroize on exit (a `secret var`
      whole-array wipe would clobber a concurrent lane — that exact bug was
      caught by the new `tests/tcyr/banking_concurrent.tcyr` race-detector,
      which now confirms 4 concurrent workers (banks 1-4) match serial,
      5/5 runs). Defensive: still no in-tree concurrent caller, but the
      latent race is closed and validated.

- [x] **TDX / SGX in-quote PCK X.509 chain walk — DONE (already shipped 3.5,
      hardened 3.7.3; the backlog text was stale, carried forward unchecked by
      the 3.7.7 sweep).** `sgx_quote_verify_full` / `tdx_quote_verify_full`
      (+ the `_into` variants) do the COMPLETE in-quote walk internally:
      `pem_decode_certs_into` the embedded PCK chain → `x509_parse_into` →
      `x509_verify_chain` (in-window + CA + pathLen + per-link
      `_x509_verify_link`) → extract leaf PCK pubkey → `*_verify_with_pck`.
      End-to-end tested incl. a wrong-root rejection (`sgx_verify_full.tcyr`).
      The root CA stays **caller-supplied by design** (consumers own trust
      roots; kavach anchors on its keyring) — not a gap. The narrower
      `*_verify_with_pck` entry (pre-validated pubkey) also remains.

- [x] **Scalar-inversion addition-chain — DONE (3.7.16).** Both
      `src/ecdsa_p256.cyr` inversions moved off generic square-and-multiply:
      field `fp_p256_inv` → fixed `2^k-1`-block chain; scalar `fn_p256_inv` →
      4-bit window. Shipped together with EC-squeeze lever 1 above
      (`ecdsa_p256_verify` 12.50 → 11.37 ms). An optimal `a^(n-2)` chain could
      do marginally better than the window but was deemed too derivation-risky.

- [x] **`bn_modexp` dead-code decision — RESOLVED: KEEP (3.8.0).** `bn_modexp`
      (`src/bignum.cyr`) has no PRODUCTION call sites since 3.6.6, but is
      **retained as the independent differential oracle** that cross-checks the
      constant-time `bn_mont_modexp` (carrying live RSA) in
      `tests/tcyr/bignum.tcyr` (mont == schoolbook + 5 modexp KATs) and the
      schoolbook baseline in `tests/bcyr/rsa.bcyr`. Removing it would collapse a
      two-implementation cross-check into a self-check — a real loss for a
      trust-boundary lib. Comment reworded to "no production call sites — test
      oracle".

- [ ] **Retire the per-thread bank-indexing workaround** if cyrius gains
      a native thread-local *array* qualifier (`threadlocal var X[N]`).
      The 3.6 bank scheme (`src/crypto_scratch.cyr`) exists only because
      `var X[N]` is a static function-scope global and cyrius TLS is
      slot-based. If a true thread-local array qualifier lands, collapse
      the `[N*8]` banks back to `var X[N]` and drop the module. Check on
      each toolchain bump. *(6.0.62 added real per-thread TLS slots — not
      arrays — so this stays gated.)*

- [ ] **Scatter-store for the fixed-base comb** (cache-timing) — **parked;
      currently MOOT.** Would distribute the comb's affine entries (64 B since
      3.7.16, not the old 128) across cache lines so a same-host attacker can't
      recover the selected nibble. But `p256_scalarmul_base` only ever processes
      the **public** scalar `u1 = e·s⁻¹` (verify data); the secret signing nonce
      stays on the CT ladder `pt_scalarmul` and never touches the comb — so this
      protects an already-public value. Becomes relevant only if a secret scalar
      ever reaches the comb AND the deployment goes multi-tenant (neither holds
      for AGNOS). Kept parked, not dropped.

- [ ] **CLMUL-assisted GHASH** — gated on the cyrius `asm`-block
      global-symbol pseudo (filed upstream:
      [`asm-block-global-symbol-pseudo`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md)).
      AES-GCM 1 KB sits ~700 µs after AES-NI; GHASH (bit-by-bit
      GF(2^128) multiply) now dominates. PCLMULQDQ/VPCLMULQDQ closes the
      gap, same byte-encoding pattern as the SHA-NI/AES-NI dispatchers.

**Possible future surfaces** (consumer-demand-gated)

- [ ] **ML-KEM-768** (PQC KEM) — belongs in a sibling `kem.cyr` if an
      AGNOS consumer needs key agreement. (ML-DSA-65 PQC sign ships
      default-on since 3.7.6.)

**Open audit findings — NONE.** The audit floor was **cleared at 3.7.3**
(4 genuine per-call-drift LOWs resolved via the `_into` caller-scratch
API; 4 reclassified as correct init-once singletons). See state.md
"Audit floor".

## Closed cycles

Per-version detail in [CHANGELOG.md](../../CHANGELOG.md); per-cycle
audits in [`docs/audit/`](../audit/).

- [`3.0-scope.md`](3.0-scope.md) — 3.0 cycle.
- [`3.2-scope.md`](3.2-scope.md) / [`3.2-tee-arc.md`](3.2-tee-arc.md) —
  3.2.0 + the 3.2.x TEE attestation sub-arc.
- **3.4** — TEE attestation completion (PEM decoder, SGX/TDX/SEV-SNP
  `*_verify_full`, x509 P-384 SPKI).
- **3.5** — modern AEAD + key agreement + the first cyrius-native-TLS
  crypto: Poly1305 / ChaCha20 / ChaCha20-Poly1305 / X25519,
  HMAC-/HKDF-SHA384, AES-128-GCM, EC + Ed25519 private-key parsers,
  ECDSA P-256/P-384 deterministic signing.
- **3.6 — cyrius-native-TLS arc (CLOSED at 3.6.8)** — parallel batch
  verify (mutex drop via per-thread crypto banks, 3.42×); TLS 1.2 PRF;
  the full RSA PKCS#1 v1.5 **and PSS** surface on a new general
  bignum/modexp engine (constant-time Montgomery ladder + base blinding
  + CRT + verify-after-sign); RSA + P-384 x509 chain-link verify;
  Montgomery-on-verify (3.43×); `pem_decode_privkey`→RSAK; AES-128 seal
  keys. Closed out at 3.6.8 (Closeout Pass + the overdue 3.5.6 audit doc
  + un-burying three hidden deferrals). Issue cross-walk:
  [`issues/archive/2026-05-28-cyrius-tls-arc-full-audit.md`](issues/archive/2026-05-28-cyrius-tls-arc-full-audit.md)
  (all five line items delivered).
- **3.7 — perf + x509 (IN PROGRESS)** — Solinas reduction for P-256
  (3.7.0, verify 147→26 ms, 5.65×) and P-384 (3.7.1, 339→55 ms, 6.21×);
  AES-GCM arbitrary-length IVs (3.7.2, SP 800-38D §7.1); the
  caller-scratch `_into` API + **audit-floor clear (8 → 0)** (3.7.3);
  x509 off-diagonal ECDSA **parse**-side fix (3.7.4, SSL.com Root ECC
  class) and the **verify**-side closer (3.7.5, all four hash×curve
  combos — P1 complete); toolchain pin 6.0.62 → 6.0.87 (3.7.5);
  **PQC-default** — ML-DSA-65 default-on, gate dropped now the 6.0.87 cap
  allows it (3.7.6); the **buried-deferral sweep** — genuine deferrals
  surfaced to the Backlog, stale comments marked shipped, false positives
  reduced to a `\uXXXX` allowlist (3.7.7); the **cyrius-6.1.20 bundle-
  consumer SIGILL fix** — README now documents the four required opt-in
  stdlib includes (the real root cause), plus the belt-and-suspenders NI
  `param_load` structural fix + pin 6.0.87 → 6.1.20, **and the EC
  scalar-mult speedup** — fixed-base comb for `u1·G` + windowed `u2·Q`
  (verify-only), `ecdsa_p256_verify` 24.7 → 11.6 ms (2.13×) /
  `ecdsa_p384_verify` 54.6 → 26.3 ms (2.08×) (3.7.8); the **attestation
  cert-pointer-array byte-vs-slot OOB fix** + pin → 6.2.1 + `json`/`bigint`→`bayan`
  (3.7.13); a toolchain/dependency refresh, pin → 6.2.11 (3.7.14); and the
  **Windows-entropy single-boundary fix** — all keygen/nonce/blinding (6 sites,
  incl. AGNOS-only `tpm_random`) routed through `_sigil_random_fill` / stdlib
  `random_bytes`, fail-closed, pin → 6.2.12 (3.7.15). Remaining: the ≤ 10 ms
  P-256 squeeze (inversion-chain / mixed-add / Karatsuba), the
  and the full bench re-run (see Outstanding above); plus the Windows `cass`
  acceptance for 3.7.15 (verification-only). *(The buried-deferral gate is
  done — superseded by `cyrlint`'s native untracked-deferral check.)*

**Cyrius pin:** `6.2.12` (synced across `cyrius.cyml` and CI).

# Sigil Roadmap

Forward-looking work only. For shipped items and per-version detail see
[CHANGELOG.md](../../CHANGELOG.md) and [state.md](state.md) ("Recently
shipped").

## Outstanding work

The only open items. The 3.6 cyrius-native-TLS arc and most of the v3.7
perf cycle have shipped — see "Closed cycles" below + CHANGELOG.

**x509 — cert verification: COMPLETE.** The P1 off-diagonal ECDSA
chain-link verification **shipped in 3.7.5** — `_x509_verify_link` now
decouples hash-selection (child sig-algo OID) from curve-selection
(issuer key), verifying all four `{P-256, P-384} × {SHA-256, SHA-384}`
combos (FIPS 186-4 §6.4 leftmost-bits digest mapping; new
`_ecdsa_p{256,384}_verify_digest` cores), and `x509_parse_into` sizes
the stored `sig_len` by the issuer curve rather than the hash. See
CHANGELOG 3.7.5 + the now-resolved
`docs/development/issues/2026-06-06-x509-off-diagonal-ecdsa-verify.md`.

**Tooling / process — committed for the next release**

- [ ] **Buried-deferral gate.** A closeout/CI check that greps `src/`
      for deferral language in comments — `deferred`, `TODO`, `FIXME`,
      `XXX`, `HACK`, `follow-up`, `for now`, `not yet`, `later bite`,
      `a future bite`, `out of scope`, `defer-to-` — and **fails (or
      reports) any hit not cross-referenced by a roadmap entry**. This
      converts the recurring "scope cut buried in a source comment"
      failure mode (the hard rule's exact target — every deferral is
      Robert's call, never a silent comment) from a human-caught
      regression into a mechanical gate the next cycle can't ship past
      without either doing the work or surfacing it. Wire it into the
      CLAUDE.md Closeout Pass (and/or sigil's pre-release verification,
      e.g. `programs/check.cyr` if that's where it lands). Start in
      *report* mode, flip to *fail* once the vocabulary is tuned and the
      tree is clean. The grep vocabulary is the only repo-specific part —
      the check itself generalizes across the AGNOS first-party repos
      (worth lifting into the shared tooling once proven here). Extends
      the `docs/doc-health.md` "Programmatic gates (future)" family.

**v3.7 — perf (OPEN)**

- [ ] **EC scalar-mult speedup** — the next *perf* bite (the
      buried-deferral gate above is the committed next *release*;
      maintainer picks whether the gate ships as its own small tag ahead
      of this, or they ride together). Carries the **≤ 10 ms
      `ecdsa_p256_verify`** target that Solinas reduction alone did not
      reach (26 ms P-256 / 55 ms P-384): with the field reduction now
      fast, the double-and-add scalar multiplication (`u1·G + u2·Q`,
      ~6000 field-muls) and the schoolbook `u256_mul_full` dominate. A
      fixed-base comb for `G` (like ed25519 already uses) + a wNAF /
      windowed ladder for the variable `Q`, optionally Karatsuba
      `u256_mul_full`. Pairs with the "scatter-store comb" backlog item
      if the comb lands on a secret path.

- [ ] **Re-run the full crypto bench suite** at the cycle close —
      before/after rows for every verify-path bench; cross-check the
      transitive SEV-SNP / TDX deltas.

**Backlog — unscheduled** (open; gated as noted)

- [ ] **Retire the per-thread bank-indexing workaround** if cyrius gains
      a native thread-local *array* qualifier (`threadlocal var X[N]`).
      The 3.6 bank scheme (`src/crypto_scratch.cyr`) exists only because
      `var X[N]` is a static function-scope global and cyrius TLS is
      slot-based. If a true thread-local array qualifier lands, collapse
      the `[N*8]` banks back to `var X[N]` and drop the module. Check on
      each toolchain bump. *(6.0.62 added real per-thread TLS slots — not
      arrays — so this stays gated.)*

- [ ] **Scatter-store for the fixed-base comb** (cache-timing).
      Distribute the 128-byte point entries across cache lines so a
      same-host cache-timing attacker cannot recover which nibble was
      selected per window. Not needed for AGNOS's single-tenant
      deployment; queue if the threat model shifts to multi-tenant.
      Pairs with the 3.7.4 EC scalar-mult comb.

- [ ] **CLMUL-assisted GHASH** — gated on the cyrius `asm`-block
      global-symbol pseudo (filed upstream:
      [`asm-block-global-symbol-pseudo`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-21-asm-block-global-symbol-pseudo.md)).
      AES-GCM 1 KB sits ~700 µs after AES-NI; GHASH (bit-by-bit
      GF(2^128) multiply) now dominates. PCLMULQDQ/VPCLMULQDQ closes the
      gap, same byte-encoding pattern as the SHA-NI/AES-NI dispatchers.

- [ ] **NI dispatch structural fix** — same gate. Migrate
      `aes_ni.cyr` / `sha_ni.cyr` dispatchers off hardcoded `[rbp-N]`
      parameter loads when the asm pseudo lands. Keep the 3.2.0 runtime
      self-test gate as defence-in-depth even after the fix.

**Possible future surfaces** (consumer-demand-gated)

- [ ] **ML-KEM-768** (PQC KEM) — belongs in a sibling `kem.cyr` if an
      AGNOS consumer needs key agreement. (ML-DSA-65 PQC sign already
      ships behind `-D SIGIL_PQC`.)
- [ ] **PQC-default builds** — drop the `-D SIGIL_PQC` gate when cyrius
      raises the 1 MB preprocessor cap (CLAUDE.md quirk #8).

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
  [`issues/2026-05-28-cyrius-tls-arc-full-audit.md`](issues/2026-05-28-cyrius-tls-arc-full-audit.md)
  (all five line items delivered).
- **3.7 — perf + x509 (IN PROGRESS)** — Solinas reduction for P-256
  (3.7.0, verify 147→26 ms, 5.65×) and P-384 (3.7.1, 339→55 ms, 6.21×);
  AES-GCM arbitrary-length IVs (3.7.2, SP 800-38D §7.1); the
  caller-scratch `_into` API + **audit-floor clear (8 → 0)** (3.7.3);
  x509 off-diagonal ECDSA **parse**-side fix (3.7.4, SSL.com Root ECC
  class) and the **verify**-side closer (3.7.5, all four hash×curve
  combos — P1 complete); toolchain pin 6.0.62 → 6.0.87 (3.7.5).
  Remaining: the EC scalar-mult speedup + the bench re-run (see
  Outstanding above).

**Cyrius pin:** `6.0.87` (synced across `cyrius.cyml` and CI).

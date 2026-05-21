# sigil: `ed25519_verify` returns 1 for wrong public key on aarch64

**Filed:** 2026-05-10
**Reporter:** argonaut (AGNOS init system / service manager)
**Cyrius version at time of report:** 5.10.34 (pinned) / 5.10.40
(local cc5)
**Sigil versions affected:** at least 3.0.1 (current libro 2.6.2
transitive pin); not bisected against earlier 3.0.x.
**Affected target:** `cc5_aarch64` cross-build, exercised via
qemu-user 11.0.0-1 on x86_64 Linux. Native x86_64 path is clean.
**Severity:** **P1** for any consumer that uses sigil to verify a
trust boundary on aarch64 — a verify that accepts wrong keys
breaks the auth property the function exists to provide.
**Status:** **resolved (2026-05-21)** under cyrius 6.0.1 + sigil
3.1.2. Cyrius 6.0.0/6.0.1's aarch64 codegen overhaul (the cc6 cut
that landed the "REAL TYPE SYSTEM" annotation pass plus the two
stdlib-resolution path bug fixes) appears to have folded out the
constant-fold this issue's hypothesis #2 predicted. See "Resolution
verification" footer at the bottom of this file for the 2026-05-21
repro run.

## Summary

`ed25519_verify(pk, msg, msg_len, sig)` returns `1` (valid) when
called with the **wrong** public key on aarch64. Native x86_64
returns `0` correctly. Both targets correctly return `1` for the
right pk. The bug is in the verify path, not sign — signing
produces well-formed signatures that round-trip through native
verify with the correct pk → 1, wrong pk → 0. Only aarch64
verify mis-accepts.

Discovered during argonaut 1.5.4 cross-arch work: the
`audit_ext_sign_ed25519` test group's "wrong vk rejected"
assertion is the only signing assertion that fails on
aarch64 — `audit_log_verify_snapshot(proof, vk_wrong)` returns
1 where it should return 0. Snapshot-signing test composes
`merkle_build` + `sign_tree_head` + `verify_tree_head`; the
faulty link is `verify_tree_head` → `ed25519_verify(pk_wrong)`.

## Repro

Two forms — direct sigil call and downstream-of-libro.

### Direct sigil call

```cyrius
fn main() {
    alloc_init();
    fl_init();
    ed25519_init();

    secret var seed1[32];
    secret var seed2[32];
    random_bytes(&seed1, 32);
    random_bytes(&seed2, 32);

    var sk1 = alloc(64);  var pk1 = alloc(32);
    var sk2 = alloc(64);  var pk2 = alloc(32);
    ed25519_keypair(&seed1, sk1, pk1);
    ed25519_keypair(&seed2, sk2, pk2);

    var msg = "test message bytes";
    var sig = alloc(64);
    ed25519_sign(sk1, msg, 18, sig);

    var v_right = ed25519_verify(pk1, msg, 18, sig);
    var v_wrong = ed25519_verify(pk2, msg, 18, sig);

    print("verify with right pk (expect 1): "); println_int(v_right);
    print("verify with wrong pk (expect 0): "); println_int(v_wrong);
    return 0;
}
var r = main();
syscall(SYS_EXIT, r);
```

Build + run:

```
$ CYRIUS_DCE=1 cyrius build         /tmp/repro.cyr /tmp/repro_x86
$ CYRIUS_DCE=1 cyrius build --aarch64 /tmp/repro.cyr /tmp/repro_aa

$ /tmp/repro_x86
verify with right pk (expect 1): 1
verify with wrong pk (expect 0): 0          # ← correct

$ qemu-aarch64 /tmp/repro_aa
verify with right pk (expect 1): 1
verify with wrong pk (expect 0): 1          # ← BUG
```

### Downstream-of-libro (argonaut's discovery shape)

```cyrius
include "tests/test_header.cyr"

fn main() {
    alloc_init();
    audit_ext_init();
    var chain = chain_new();
    chain_append(chain, SEV_INFO, str_from("svc"),
        str_from("Started"), str_from("daimon"));

    var sk1 = signing_key_generate();
    var sk2 = signing_key_generate();
    var proof = proof_build_signed(chain, sk1);

    var pv1 = proof_verify_signed(proof,
        verifying_key_from_signing(sk1));
    var pv2 = proof_verify_signed(proof,
        verifying_key_from_signing(sk2));

    # pv layout: offset +0 = th_valid. native: pv1[0]=1, pv2[0]=0.
    # aarch64: pv1[0]=1, pv2[0]=1.
    print("aarch64 wrong-vk th_valid: "); println_int(load64(pv2));
    return 0;
}
```

## Root cause (speculation)

Two leading hypotheses, both unverified:

1. **NI-path dispatch on aarch64** — sigil's Ed25519 verify
   may dispatch to a CPU-feature accelerator path. The
   2026-05-10 stack-frame report
   (`2026-05-10-cyrius-510-asm-stack-frame-drift-breaks-ni-paths.md`)
   covered the x86_64 SIGILL class; the aarch64 path may have
   an analogous regression where the inline-asm comparison
   returns 1 unconditionally rather than faulting.

2. **`constant_time_eq_*` aarch64 codegen** — the final step of
   Ed25519 verify is comparing the recomputed R bytes against
   the signature's R. If cyrius 5.10's aarch64 codegen for the
   tight-loop XOR-accumulate ct compare always settles to 0
   (zero = equal under sigil's convention), verify reports
   "match" for every signature. The fact that **right-pk also
   returns 1** is consistent — if the compare always returns
   0/equal, both inputs pass.

The second is consistent with native x86_64 being clean (asm
inline differences) and with the symptom shape (false-positive
match, not false-negative crash).

## Proposed fix

Out of scope to triage from the argonaut side; flagging the
symptom and the two hypotheses for sigil-side investigation.
If hypothesis 2 holds, a side-channel-safe ct_eq aarch64 path
that the cyrius 5.10.x backend doesn't constant-fold is the
likely fix.

## Consumer-side workaround

Argonaut 1.5.4 ships aarch64 cross-build as **best-effort,
non-blocking** in CI. The `audit_extended.tcyr` "wrong vk
rejected" assertion is documented as a known-failure on aarch64
pending this fix; production deployments on aarch64 hardware
should not rely on sigil Ed25519 verify until upstream confirms
real-hardware behaviour (the issue may be qemu-user-specific,
though qemu-user usually emulates compute correctly).

If real-hardware aarch64 reproduces the same false-positive,
argonaut will gate the snapshot-signing verify path behind a
runtime arch check or pull the sign/verify dispatch back to
host-side (in argonaut's case the supervisor is always
single-arch — sign on the running arch, verify on the same
arch — so the bug doesn't escape into cross-arch trust paths).

## Affected consumers

- **argonaut** `tests/tcyr/audit_extended.tcyr` —
  `audit-ext-sign-ed25519` group, "wrong vk rejected"
  assertion. 26/28 aarch64 sweep with this as one of the two
  known-failures (other is `audit_findings.tcyr` qemu-user
  fork/setsid limit, unrelated).
- **libro** `proof_verify_signed` — by extension, every
  consumer that calls libro's signed-proof verify on aarch64
  inherits the false-positive class.

## Resolution verification (2026-05-21)

Repro from § "Direct sigil call" above, re-run against the
3.1.2 ship-cut (cyrius 5.11.4 → 6.0.1 bump, sakshi 2.2.3 →
2.2.5, agnosys 1.0.4 → 1.2.7, vendored lib refresh):

```
$ cyrius build --aarch64 --no-deps /tmp/ed25519_aarch_repro.cyr \
    /tmp/ed25519_aarch_repro
compile ... [aarch64] OK
$ qemu-aarch64 /tmp/ed25519_aarch_repro
1            # verify with right pk
0            # verify with wrong pk  ← FIXED
EXIT=0
```

Both halves now report the expected values: right-pk verify
returns 1, wrong-pk verify returns 0. Hypothesis #2 (cc5 aarch64
`constant_time_eq_*` codegen constant-folding to 0=equal) was the
load-bearing speculation; cycc 6's backend pass appears to have
broken that constant-fold pattern. Native x86_64 verify continued
to behave correctly across the same versions, so no regression
was introduced by the bump.

Downstream consumers (argonaut, libro) can drop the aarch64
"known-failure" gate on the `audit-ext-sign-ed25519` /
`wrong-vk-rejected` assertion under cyrius ≥ 6.0.1 + sigil ≥
3.1.2.

**Action items closed by this resolution:**

- The "Road to v3.1" P1 row for this issue (roadmap.md)
  collapses to a single-line "shipped under cyrius 6.0.1"
  historical note.
- Argonaut 1.5.4's "best-effort, non-blocking aarch64 CI"
  documentation can promote the aarch64 cross-build to a
  blocking gate when it bumps to sigil ≥ 3.1.2.

If the bug recurs against a future toolchain or hardware
(real-silicon aarch64, not qemu-user), re-open with the new
cyrius pin and a fresh repro.

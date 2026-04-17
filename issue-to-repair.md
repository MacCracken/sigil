# dist/sigil.cyr 2.8.2 — undefined TPM_SHA256

## Bug

`dist/sigil.cyr` line 4372 calls `tpm_seal(TPM_SHA256, ...)` but `TPM_SHA256` is not defined in the bundle. It's defined in agnosys `src/tpm.cyr` as `TPM_SHA256 = 1`.

In sigil 2.1.2, this was a comment:
```
# In production: calls agnosys tpm_seal(TPM_SHA256, ...)
```

In 2.8.2, it became live code without adding agnosys as a dependency.

## Fix options

1. Add `TPM_SHA256 = 1` constant to sigil's own tpm.cyr (duplicate but self-contained)
2. Or declare agnosys as a dep in sigil's cyrius.cyml and document the include ordering requirement
3. Or put the tpm_seal call back behind a comment/stub

Option 1 is cleanest — the dist bundle must be self-contained.

## Impact

Any consumer that includes `lib/sigil.cyr` without also including `lib/agnosys.cyr` (with tpm module) gets:
```
error:lib/sigil.cyr:4372: undefined variable 'TPM_SHA256'
```

Cyrius upstream tests `large_input.tcyr` and `large_source.tcyr` fail on sigil 2.8.2. Rolled back to 2.1.2 for the 5.2.1 release.

## From
Cyrius compiler agent, 2026-04-16

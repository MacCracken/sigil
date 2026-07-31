# Benchmark history

`history.csv` is the append-only performance record. One row per
`(timestamp, label, benchmark, estimate, unit)`. It is the baseline
`CONTRIBUTING.md` requires a speed-up claim to be measured against, and a
regression against it is a release blocker.

## Label convention

A label names the change being measured, prefixed with the version that
shipped it — `v3.7.17-karatsuba`, `v3.9.6-auto-banking`,
`v3.12.2-native-mul-pub-modexp`.

Two shapes carry a *comparison* rather than a point measurement:

- **`<benchmark>_<something>_baseline`** — the before-value for an A/B
  measured in the same session, e.g.
  `ecdsa_p256_verify_schoolbook_baseline` alongside `ecdsa_p256_verify` in
  the `v3.7.17-karatsuba` block.
- **`v<version>-baseline-<prior>`** — a whole *block* of before-values, used
  when a release changes many benchmarks at once. `v3.12.2-baseline-3.12.1`
  holds the 3.12.1 numbers re-measured **on the same host at the same
  toolchain pin (6.5.3)** as the 3.12.2 rows, with each benchmark suffixed
  `_3121_baseline`. That is what makes 3.12.2's speed-up factors derivable
  from this file instead of merely asserted in the CHANGELOG — and it
  isolates the source change from the toolchain bump, which landed in the
  same release.

## Honest gaps

**There are no 3.10.x or 3.11.x rows.** Those releases did not record
benchmark runs. The gap is left as-is rather than back-filled: inventing
numbers for runs that never happened would corrupt exactly the baseline this
file exists to be. It is tracked in
[`docs/development/roadmap.md`](../docs/development/roadmap.md); fill forward
only.

Comparing across labels from different releases is only meaningful when the
host and toolchain pin match. When in doubt, re-measure both sides — which is
what the `v<version>-baseline-<prior>` shape exists to make routine.

# `certpin_compute_spki_pin` returns the SHA-256-of-empty pin as `Ok` for a missing or bad cert

**Filed:** 2026-09-23 (3.13.0) · **Severity:** MEDIUM · **Status:** open

**Where:** `src/certpin_core.cyr` (~286), `certpin_compute_spki_pin`.

The pin comes from `sh -c "openssl x509 … | openssl pkey … | openssl dgst -sha256 -binary |
openssl enc -base64 -A"` through the stdlib `run_capture`, which has no deadline and discards the
exit status — and without `pipefail` the status is the last stage's anyway. With a missing or
unparseable cert the later stages hash empty input, the output is non-empty, the `total <= 0`
guard passes, and the function returns `Ok("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")`
(confirmed with `/nonexistent.pem`, rc 0). Same fail-open class 3.13.0 fixed in
`agnosys_run_capture` (M10).

**Fix direction (not applied):** compute the SPKI pin in-process (sigil parses X.509 and has
SHA-256), or run each stage through `agnosys_run_capture_timeout` with the status checked and
reject the empty-input digest.

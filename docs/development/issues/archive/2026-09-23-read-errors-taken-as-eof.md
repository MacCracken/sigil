# Two read loops still take a `read(2)` error as EOF

**Filed:** 2026-09-23 (3.13.0) · **Severity:** MEDIUM · **Status:** resolved (3.13.1)

The class 3.13.0 fixed in `hash_file*` and `ima_read_measurements` (M9), still present in:

- `src/sys_util.cyr` (~376) `agnosys_read_fd_to_str` — `if (n <= 0) { rgo = 0; }` returns the prefix
  as a complete Str. It backs the PAM-config and passwd readers.
- `src/ima_core.cyr` (~345) `ima_get_status` — a read error ends the newline count early and returns
  `Ok` with a too-low `measurement_count`.

**Fix direction (not applied):** `n < 0` → error, `n == 0` → EOF, as `_ima_read_log_fd` now does.

## Resolution (3.13.1)

`agnosys_read_fd_to_str` returns 0 on a read error; `ima_get_status` counts through
`_ima_count_lines_fd` and returns `Err` on a read error. Test group in
`tests/tcyr/capture_bounded.tcyr`.

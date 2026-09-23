# LUKS key file is never deleted — `luks_format` / `luks_open` leave the key in `/tmp` on every call — RESOLVED at 3.13.0

**Status:** ✅ **RESOLVED — 3.13.0 (2026-09-23).** Every `defer` in `src/` is gone (all 8 sat in
Result-returning fns, so none ever ran), and each fn releases what it acquired on every exit path.
The LUKS keyfile now has one lifecycle, `_luks_run_with_keyfile`, which removes it after the command
succeeds, after it fails, and when it never ran. Proven by the new `tests/tcyr/fd_hygiene.tcyr`
(37 assertions). A reduced copy of that file, run against the unfixed 3.12.18 code, failed **7 of 17**:
8 leaked fds from 8 keyfile writes, a failed write that left the keyfile behind, 16 leaked fds from
`secureboot_read_efi_variable`, and `tpm_seal` following a planted symlink and overwriting its target
with the plaintext. See **Resolution** below.
**Severity:** High — LUKS key material stays on disk after every `luks_format` and `luks_open`,
whether the call succeeds or fails.
**Affects:** sigil 3.12.18 and earlier 3.12.16+ (`src/luks.cyr`), built with cyrius 6.6.x. Reproduced
on sigil's pin (6.6.4) and on 6.6.6.
**Root cause:** a cyrius compiler defect. A `defer` block does not run when the enclosing fn returns
a value-form `Result` pair. It is filed with cyrius as
`docs/development/issues/2026-09-22-agnodrm-defer-skipped-on-value-form-result-return.md`, with a
repro in `repros/2026-09-22-defer-skipped-on-result-return.cyr`. The cyrius guide (§Defer) documents
that `defer` runs at function exit, so sigil's code is correct as written; the compiler does not
honour it. **Still open upstream** at 6.6.6. Until it is fixed, sigil's CLAUDE.md forbids `defer` in a
Result-returning fn (Rules, added 3.13.0).
**Reported by:** agnodrm's 1.6.2 review.

## What happens

`luks_format` and `luks_open` write the key to `/tmp/.agnos-luks-<pid>-<16 hex>` (mode 0600,
`O_EXCL|O_NOFOLLOW`) through `luks_write_keyfile`. They rely on a `defer` to delete it:

| Site | Code | Exits after the `defer` |
|---|---|---|
| `src/luks.cyr:445` (`luks_format`) | `defer { _sig_unlink(keyfile); }` | `return Err(cs_res);` (cryptsetup failed), `return Ok(loop_dev);` |
| `src/luks.cyr:514` (`luks_open`) | `defer { _sig_unlink(keyfile); }` | `return Err(cs_res);`, `return Ok(mapper);` |
| `src/luks.cyr:364` (`luks_write_keyfile`) | `defer { sys_close(fd); }` | `return sigil_err_syscall_failed(...)` (write failed), `return Ok(keyfile);` |

Every one of those exits is a Result return, so no `defer` ever runs:
- the key file stays in `/tmp` after every format and open, on the success path and on the
  cryptsetup-failure path;
- `luks_write_keyfile` leaks its fd on every call.

## Reproduction

`luks_format` / `luks_open` themselves were **not** run: they need root, `losetup` and
`cryptsetup`. The shape was reproduced standalone, mirroring the code above:

```cyr
fn write_keyfile(path): i64 {
    var fd = sys_open(path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 384);   # 0600
    if (fd < 0) { return Err(fd); }
    defer { sys_close(fd); }
    sys_write(fd, "KEY", 3);
    return Ok(path);
}

fn format_like(path, fail): i64 {
    var kt, kf = write_keyfile(path);
    if (is_err_result(kt) == 1) { return Err(kf); }
    defer { sys_unlink(kf); }
    if (fail == 1) { return Err(0 - 5); }      # the cryptsetup-failed path
    return Ok(1);                              # the success path
}
```

Result, identical under cyrius 6.6.4 and 6.6.6:

```
keyfile left after Ok: 1
keyfile left after Err: 1
next fd (3 if nothing leaked): 5
-rw------- 3 .../kf_err
-rw------- 3 .../kf_ok
```

Both key files survive with their 3 bytes, and each writer call leaks its fd.

## Notes

- Independent of the compiler defect: `luks_write_keyfile`'s write-failure path returns an error
  without removing the file it just created.
- sigil has 8 `defer` blocks in `src/`: 3 in `luks.cyr`, 3 in `ima_core.cyr`, 1 in
  `secureboot_core.cyr` and 1 in `tpm_core.cyr`. Only the three in `luks.cyr` were examined for this
  report. Any of the others inside a Result-returning fn is affected the same way.
- agnodrm hit the same defect in nine fns, and at 1.6.2 releases every resource explicitly on each
  exit path instead of using `defer`.

## Resolution (3.13.0)

All 8 `defer` blocks were removed. The Notes above were right that the other five are affected the same
way: every one sat in a Result-returning fn.

| Fn | Was | Now |
|---|---|---|
| `luks_write_keyfile` | `defer { sys_close(fd); }`, leaked 1 fd per call | Closes explicitly. A failed **or short** write, or a failed close, removes the file this call created. A failed *create* removes nothing, because under `O_EXCL` an existing path belongs to someone else. |
| `luks_format` / `luks_open` | `defer { _sig_unlink(keyfile); }`, so the key was left in `/tmp` on every call | Both go through the new `_luks_run_with_keyfile(pre, post, key, len)`. It stages the key, runs `pre ++ [keyfile] ++ post` (bounded and status-checked), and unlinks the keyfile before looking at the result. If the unlink fails with anything other than `ENOENT`, it returns `Err` even when cryptsetup succeeded, because a key left on disk must not be reported as a clean success. `luks_format` now also detaches its loop device when the *keyfile* cannot be written; before, that path returned without detaching. |
| `ima_get_status`, `ima_read_measurements`, `ima_write_policy` | `defer { sys_close(…) }`, 1 fd per call | Close on every exit, including the 32 MiB-cap error path inside the read loop. The policy write is a full write (short = `Err`). |
| `tpm_seal` | `defer { sys_close(ifd); }`, 1 fd per call | Closes explicitly. The staged **plaintext** file also received the approved audit-F-3 hardening. Any stale entry is removed first, then created `O_CREAT\|O_EXCL\|O_NOFOLLOW` at 0600. Before this, `O_TRUNC` without `O_NOFOLLOW` followed a planted symlink and overwrote its target with the secret. A failed or short write removes the partial file. |
| `secureboot_read_efi_variable` | `defer { file_close(fd); }`, 1 fd per call | Closed once, straight after the read, before any exit. |

Also, all in the same functions:
- **No raw file syscalls.** `sys_open` → `file_open`, `_sig_unlink` → `xunlink` (it was deleted: no
  callers remain, and `xunlink` also covers Windows). On agnos `sys_open` is `(name, namelen, flags)`,
  so the Linux-shaped calls passed the flags word as the name length.
- **Full writes.** The new `agnosys_write_all(fd, buf, len)` (`src/sys_util.cyr`) loops until every
  byte lands, and treats a zero-progress write as `-EIO`. A short `write(2)` is never reported as
  success.

### Verification

- `tests/tcyr/fd_hygiene.tcyr`, 37 assertions, runs unprivileged. `/bin/sh` stands in for cryptsetup
  and records the keyfile path it was handed, the bytes in the file and its trailing args. The test
  asserts the file is gone after both a successful and a failing run. Write failures are forced with
  an unreadable source buffer (`write(2)` → `-EFAULT`). fds are counted by the lowest free descriptor
  before and after.
- **Red before green:** the file minus its two new-API groups, run against the 3.12.18 code, gave
  `10 passed, 7 failed`. The same groups pass on 3.13.0, and the full suite is green.
- **Not exercised on the dev host:** the IMA paths need `/sys/kernel/security/ima`, and real
  `luks_format` / `luks_open` need root, `losetup` and `cryptsetup`. The IMA changes are covered by
  review. The LUKS keyfile lifecycle is covered through `_luks_run_with_keyfile`, the one code path
  both callers use.

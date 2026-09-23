# LUKS key file is never deleted — `luks_format` / `luks_open` leave the key in `/tmp` on every call — OPEN

**Status:** 🟡 **OPEN** — reported from agnodrm's 1.6.2 review. No code change has been made; this
file only records the finding.
**Severity:** High — LUKS key material stays on disk after every `luks_format` and `luks_open`,
whether the call succeeds or fails.
**Affects:** sigil 3.12.18 (`src/luks.cyr`), built with cyrius 6.6.x. Reproduced on sigil's pin
(6.6.4) and on 6.6.6.
**Root cause:** a cyrius compiler defect. A `defer` block does not run when the enclosing fn returns
a value-form `Result` pair. It is filed with cyrius as
`docs/development/issues/2026-09-22-agnodrm-defer-skipped-on-value-form-result-return.md`, with a
repro in `repros/2026-09-22-defer-skipped-on-result-return.cyr`. The cyrius guide (§Defer) documents
that `defer` runs at function exit, so sigil's code is correct as written; the compiler does not
honour it.

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

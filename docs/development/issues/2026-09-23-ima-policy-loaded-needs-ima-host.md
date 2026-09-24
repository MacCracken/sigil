# `ima_get_status`'s `policy_loaded` may read backwards on default kernels

**Filed:** 2026-09-23 (3.13.1, from LOW L23 of the 3.13.0 list) · **Severity:** LOW · **Status:** open

**Where:** `src/ima_core.cyr`, `ima_get_status` — `policy_loaded` is "the file
`/sys/kernel/security/ima/policy` exists".

On kernels built without `CONFIG_IMA_WRITE_POLICY`, the kernel removes that securityfs file once a
custom policy has been written, so on those kernels "exists" means *no* custom policy yet — the
flag reads backwards. With `CONFIG_IMA_WRITE_POLICY` / `CONFIG_IMA_READ_POLICY` the file stays.

**Needs:** a host with IMA enabled, to confirm the behaviour on each config before changing the
logic. It cannot be checked on a dev host without `/sys/kernel/security/ima`.

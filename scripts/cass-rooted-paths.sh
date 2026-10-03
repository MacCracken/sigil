#!/bin/sh
# cass-rooted-paths.sh — run tests/tcyr/rooted_paths.tcyr on a real Windows host, unplanted and
# planted (3.13.8).
#
#   sh scripts/cass-rooted-paths.sh [host]          (default host: cass)
#
# On Windows a rooted POSIX path is drive-relative ("/dev/tpmrm0" is C:\dev\tpmrm0), so every
# helper in tpm_core / ima_core / secureboot_core / dmverity / luks that probes, opens or spawns
# one asks agnosys_rooted_paths_untrusted() first and fails closed (CLAUDE.md "No rooted POSIX
# path on Windows"). An UNPLANTED run only notices a regression in that helper itself: with
# nothing at the drive root, a probe whose guard was dropped finds nothing and the row stays
# green. Only the PLANTED run — every probed path created at the root of the current drive
# first — catches a dropped per-site guard (measured: removing tpm_detect's guard alone leaves
# the unplanted run 22/0 and turns two planted rows red). So run this, and require it green,
# whenever any of those five modules changes.
#
# What it does: builds the test for PE with the pinned toolchain (`cyrius build --win`), copies
# it to C:\cyrius-tests\<per-run dir> on the host (Defender is excluded there), runs it from that
# directory, then maps a free drive letter onto <per-run dir>\drv with `subst`, runs it again
# from that drive's root with SIGIL_PLANT_ROOT=1, and removes the mapping and the directory.
# Nothing is ever planted on the system drive. Exit 0 only when both runs exit 0 with no failed
# assertion, the planted run actually planted (its count exceeds the unplanted one) and its
# plants are gone afterwards.

set -eu

HOST="${1:-cass}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sigil-rp-XXXXXX")"
ID="_sigil_rp_$(date +%s)_$$"
D="C:\\cyrius-tests\\$ID"
trap 'rm -rf "$WORK"' EXIT

(cd "$ROOT" && cyrius build --win tests/tcyr/rooted_paths.tcyr "$WORK/rp.exe") > "$WORK/build.log" 2>&1 || {
    cat "$WORK/build.log"
    echo "FAIL: rooted_paths.tcyr did not build for PE"
    exit 1
}

# The planted run, as a PowerShell file: a free letter, subst, the run from that drive's root,
# and the unmapping in a finally block, so an error cannot leave the mapping behind.
cat > "$WORK/planted.ps1" <<'PS1'
param([string]$D)
$L = [char[]]'PQRSTUVWXY' | Where-Object { -not (Test-Path ("{0}:\" -f $_)) } | Select-Object -First 1
if (-not $L) { 'rc=no-free-drive-letter'; exit 1 }
$drv = "{0}:" -f $L
subst $drv "$D\drv"
if ($LASTEXITCODE -ne 0) { 'rc=subst-failed'; exit 1 }
try {
    cmd /v /c "cd /d $drv\ && set SIGIL_PLANT_ROOT=1&& `"$D\rp.exe`" > `"$D\o2.txt`" 2>&1 & echo rc=!errorlevel!"
} finally {
    subst $drv /d
}
Get-Content "$D\o2.txt"
$left = @(Get-ChildItem -Recurse -Force -Name "$D\drv")
"left-behind=" + $left.Count
PS1

cleanup_remote() {
    ssh "$HOST" "Remove-Item -Recurse -Force $D -ErrorAction SilentlyContinue" > /dev/null 2>&1 || true
}
trap 'cleanup_remote; rm -rf "$WORK"' EXIT

ssh "$HOST" "New-Item -ItemType Directory -Force -Path $D\\drv | Out-Null" > /dev/null 2>&1
scp -q "$WORK/rp.exe" "$HOST:C:/cyrius-tests/$ID/rp.exe" 2> /dev/null
scp -q "$WORK/planted.ps1" "$HOST:C:/cyrius-tests/$ID/planted.ps1" 2> /dev/null

ssh "$HOST" "cmd /v /c \"cd /d $D && rp.exe > o1.txt 2>&1 & echo rc=!errorlevel! & type o1.txt\"" \
    > "$WORK/unplanted.txt" 2> /dev/null || true
ssh "$HOST" "powershell -NoProfile -ExecutionPolicy Bypass -File $D\\planted.ps1 -D $D" \
    > "$WORK/planted.txt" 2> /dev/null || true

tr -d '\r' < "$WORK/unplanted.txt" > "$WORK/u.txt"
tr -d '\r' < "$WORK/planted.txt" > "$WORK/p.txt"

ok=1
for run in u p; do
    f="$WORK/$run.txt"
    case $run in u) label=unplanted ;; p) label=planted ;; esac
    rc="$(sed -n 's/^rc=\([^ ]*\).*/\1/p' "$f" | head -1)"
    sum="$(grep -aoE '[0-9]+ passed, [0-9]+ failed' "$f" | tail -1 || true)"
    echo "$label: rc=${rc:-?} ${sum:-no summary}"
    grep -a 'FAIL' "$f" || true
    if [ "$rc" != 0 ]; then ok=0; fi
    case "$sum" in *" passed, 0 failed") ;; *) ok=0 ;; esac
done

up="$(grep -aoE '^[0-9]+ passed' "$WORK/u.txt" | tail -1 | cut -d' ' -f1)"
pp="$(grep -aoE '^[0-9]+ passed' "$WORK/p.txt" | tail -1 | cut -d' ' -f1)"
if [ -z "$up" ] || [ -z "$pp" ] || [ "$pp" -le "$up" ]; then
    echo "FAIL: the planted run did not run its plant rows (planted ${pp:-?} vs unplanted ${up:-?})"
    ok=0
fi
left="$(sed -n 's/^left-behind=//p' "$WORK/p.txt" | head -1)"
if [ "${left:-x}" != 0 ]; then
    echo "FAIL: the plants were not all removed (${left:-?} entries left under the scratch drive)"
    ok=0
fi

if [ "$ok" -eq 1 ]; then
    echo "rooted_paths on $HOST: OK"
    exit 0
fi
echo "rooted_paths on $HOST: FAILED"
exit 1

#!/bin/sh
# Full sigil audit: compile, test, bench, fuzz
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${CC:-cc3}"

pass=0
fail=0
total=0

check() {
    total=$((total + 1))
    if [ "$2" = "0" ]; then
        printf "  \033[32mPASS\033[0m: %s\n" "$1"
        pass=$((pass + 1))
    else
        printf "  \033[31mFAIL\033[0m: %s\n" "$1"
        fail=$((fail + 1))
    fi
}

echo "=== Sigil Audit ==="
echo ""

# ── 1. Test Suite ──
echo "── Test Suite ──"
for tfile in "$ROOT"/tests/tcyr/*.tcyr; do
    [ -f "$tfile" ] || continue
    name=$(basename "$tfile" .tcyr)
    tmpbin="/tmp/sigil_t_$$"
    printf "  %-20s " "$name"
    if cat "$tfile" | "$CC" > "$tmpbin" 2>/dev/null && chmod +x "$tmpbin"; then
        result=$(timeout 120 "$tmpbin" 2>&1 | strings | grep -E "passed.*failed" | tail -1)
        if echo "$result" | grep -q " 0 failed"; then
            echo "$result"
            check "$name" 0
        else
            echo "FAIL: $result"
            check "$name" 1
        fi
    else
        echo "COMPILE FAIL"
        check "$name" 1
    fi
    rm -f "$tmpbin"
done
echo ""

# ── 2. Benchmarks ──
echo "── Benchmarks ──"
for bfile in "$ROOT"/tests/bcyr/*.bcyr; do
    [ -f "$bfile" ] || continue
    name=$(basename "$bfile" .bcyr)
    tmpbin="/tmp/sigil_b_$$"
    if cat "$bfile" | "$CC" > "$tmpbin" 2>/dev/null && chmod +x "$tmpbin"; then
        timeout 300 "$tmpbin" 2>&1
        check "bench_$name" "$?"
    else
        echo "  COMPILE FAIL: $name"
        check "bench_$name" 1
    fi
    rm -f "$tmpbin"
done
echo ""

# ── 3. Fuzz (quick, 5s each) ──
echo "── Fuzz (5s each) ──"
for ffile in "$ROOT"/fuzz/*.fcyr; do
    [ -f "$ffile" ] || continue
    name=$(basename "$ffile" .fcyr)
    tmpbin="/tmp/sigil_f_$$"
    printf "  %-25s " "$name"
    if cat "$ffile" | "$CC" > "$tmpbin" 2>/dev/null && chmod +x "$tmpbin"; then
        timeout 5 "$tmpbin" >/dev/null 2>&1 || true
        rc=$?
        if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ]; then
            echo "OK"
            check "$name" 0
        else
            echo "CRASH (exit $rc)"
            check "$name" 1
        fi
    else
        echo "COMPILE FAIL"
        check "$name" 1
    fi
    rm -f "$tmpbin"
done
echo ""

# ── Summary ──
echo "═══════════════════════════════════"
printf "  %d passed, %d failed (%d total)\n" "$pass" "$fail" "$total"
echo "═══════════════════════════════════"
[ "$fail" -eq 0 ] || exit 1

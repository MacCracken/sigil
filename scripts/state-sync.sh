#!/bin/sh
# state-sync.sh — the state.md release hook (CLAUDE.md "State sync").
#
# docs/development/state.md repeats values that other files own: the version (VERSION), the
# toolchain pin (cyrius.cyml [package].cyrius), the release date (the CHANGELOG heading for
# VERSION), the sakshi / bayan versions that arrive with the toolchain snapshot (lib/), the
# .tcyr and fuzz file counts, and the assertion totals. CLAUDE.md has said since the 3.x
# restructure that a release post-hook keeps them current; until 3.13.2 no such hook existed
# (nothing in scripts/ or .github/ touched state.md), and the fields drifted three times —
# 3.9.0–3.9.5, 3.9.6–3.11.0, 3.12.0–3.12.1, with three versions asserted in one section.
#
#   sh scripts/state-sync.sh                  --check (default): exit 1 naming each stale field
#   sh scripts/state-sync.sh --write          rewrite the fields derivable from the repo
#   sh scripts/state-sync.sh --write --count  ...and run every .tcyr and fuzz harness to
#                                             rewrite the assertion totals (minutes, not seconds)
#
# A number is only ever written from a measurement: without --count the assertion and fuzz
# rows are left alone, and --check keeps failing until their @version tag names the current
# VERSION. Only the current value in each row is rewritten; the history after it (e.g.
# "(2433 @3.13.0)") is left for the release author. The prose — the Phase row, the "Recently shipped" row, the in-flight table — is
# not generated; --check fails until the Phase row and the top "Recently shipped" row name the
# current version, so it has to be written before a release goes out. CI runs --check.
#
# POSIX sh + awk only: CI runs this under dash and mawk (no gawk extensions, no regex
# intervals in awk).

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ROOT/docs/development/state.md"

mode=check
count=0
while [ $# -gt 0 ]; do
    case "$1" in
        --check) mode=check ;;
        --write) mode=write ;;
        --count) count=1 ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        *) echo "state-sync: unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
if [ "$count" -eq 1 ] && [ "$mode" != write ]; then
    echo "state-sync: --count only makes sense with --write" >&2
    exit 2
fi

# ── Values the repo owns ──

version=$(tr -d '[:space:]' < "$ROOT/VERSION")
pin=$(sed -n 's/^cyrius = "\(.*\)"$/\1/p' "$ROOT/cyrius.cyml" | head -1)
vre=$(printf '%s' "$version" | sed 's/\./\\./g')
date=$(grep -m1 "^## \[$vre\]" "$ROOT/CHANGELOG.md" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1 || true)

sakshi=""
bayan=""
if [ -f "$ROOT/lib/sakshi.cyr" ]; then
    sakshi=$(sed -n 's/^# Bundled distribution of sakshi v\([0-9][0-9.]*\).*/\1/p' "$ROOT/lib/sakshi.cyr" | head -1)
fi
if [ -f "$ROOT/lib/bayan.cyr" ]; then
    bayan=$(sed -n 's/^# Version: \([0-9][0-9.]*\).*/\1/p' "$ROOT/lib/bayan.cyr" | head -1)
fi

nfiles() {
    n=0
    for f in "$@"; do [ -f "$f" ] && n=$((n + 1)); done
    echo "$n"
}
ntcyr=$(nfiles "$ROOT"/tests/tcyr/*.tcyr)
nfcyr=$(nfiles "$ROOT"/fuzz/*.fcyr)

if [ -z "$version" ] || [ -z "$pin" ]; then
    echo "state-sync: could not read VERSION or the cyrius.cyml pin" >&2
    exit 2
fi
if [ -z "$date" ]; then
    echo "state-sync: CHANGELOG.md has no '## [$version]' heading with a date" >&2
    exit 2
fi

# ── --count: measure the assertion totals ──

assertions=""
fuzz_total=""
fuzz_each=""   # "name=N;name=N;" for the per-harness counts in the Fuzz row
if [ "$count" -eq 1 ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    assertions=0
    for t in "$ROOT"/tests/tcyr/*.tcyr; do
        name=$(basename "$t" .tcyr)
        if ! (cd "$ROOT" && cyrius test "$t") > "$tmp/$name.log" 2>&1; then
            echo "state-sync: $name failed — not writing counts from a red suite" >&2
            tail -5 "$tmp/$name.log" >&2
            exit 1
        fi
        p=$(grep -aoE '[0-9]+ passed, 0 failed' "$tmp/$name.log" | tail -1 | cut -d' ' -f1)
        if [ -z "$p" ]; then
            echo "state-sync: $name printed no 'N passed, 0 failed' summary" >&2
            exit 1
        fi
        assertions=$((assertions + p))
    done
    fuzz_total=0
    for f in "$ROOT"/fuzz/*.fcyr; do
        name=$(basename "$f" .fcyr)
        if ! (cd "$ROOT" && cyrius build "$f" "$tmp/$name") > "$tmp/$name.build" 2>&1; then
            echo "state-sync: fuzz $name did not build" >&2
            exit 1
        fi
        if ! "$tmp/$name" > "$tmp/$name.log" 2>&1; then
            echo "state-sync: fuzz $name failed" >&2
            tail -5 "$tmp/$name.log" >&2
            exit 1
        fi
        p=$(grep -aoE '[0-9]+ passed, 0 failed' "$tmp/$name.log" | tail -1 | cut -d' ' -f1)
        if [ -z "$p" ]; then
            echo "state-sync: fuzz $name printed no 'N passed, 0 failed' summary" >&2
            exit 1
        fi
        fuzz_total=$((fuzz_total + p))
        fuzz_each="$fuzz_each$name=$p;"
    done
fi

# ── --write: rewrite the rows in place ──
#
# Each rule is scoped to one table row by its label, and replaces only the FIRST match in
# that row (the rows carry history after the current value).

if [ "$mode" = write ]; then
    out=$(mktemp)
    awk -v version="$version" -v pin="$pin" -v date="$date" \
        -v sakshi="$sakshi" -v bayan="$bayan" -v ntcyr="$ntcyr" -v nfcyr="$nfcyr" \
        -v assertions="$assertions" -v fuzz_total="$fuzz_total" -v fuzz_each="$fuzz_each" '
        function bold(s, v) { sub(/\*\*[^*]*\*\*/, "**" v "**", s); return s }
        function vtag(s, v) { sub(/@[0-9]+\.[0-9]+\.[0-9]+/, "@" v, s); return s }
        index($0, "| Current version |") == 1      { $0 = bold($0, version) }
        index($0, "| Cyrius toolchain pin |") == 1 { $0 = bold($0, pin) }
        index($0, "| Last release date |") == 1    { $0 = "| Last release date | " date " |" }
        index($0, "| Dependencies |") == 1 {
            if (sakshi != "") sub(/sakshi \*\*[0-9.]+\*\*/, "sakshi **" sakshi "**")
            if (bayan != "")  sub(/bayan \*\*[0-9.]+\*\*/, "bayan **" bayan "**")
        }
        index($0, "| `.tcyr` test files |") == 1 { $0 = vtag(bold($0, ntcyr), version) }
        index($0, "| Total assertions |") == 1 && assertions != "" {
            $0 = vtag(bold($0, assertions), version)
            sub(/across all [0-9]+ files/, "across all " ntcyr " files")
        }
        index($0, "| Fuzz harnesses |") == 1 && fuzz_total != "" {
            sub(/\| Fuzz harnesses \| [0-9]+ /, "| Fuzz harnesses | " nfcyr " ")
            sub(/\*\*[0-9]+ \/ 0 failures @[0-9]+\.[0-9]+\.[0-9]+\*\*/, "**" fuzz_total " / 0 failures @" version "**")
            n = split(fuzz_each, kv, ";")
            for (i = 1; i <= n; i++) {
                if (split(kv[i], p, "=") == 2) {
                    re = "`" p[1] "` \\([0-9]+\\)"
                    sub(re, "`" p[1] "` (" p[2] ")")
                }
            }
        }
        { print }
    ' "$STATE" > "$out"
    cat "$out" > "$STATE"
    rm -f "$out"
fi

# ── Check (both modes end here) ──

row() { grep -m1 -F "| $1 |" "$STATE" || true; }
first_bold() { printf '%s\n' "$1" | sed -n 's/^[^*]*\*\*\([^*]*\)\*\*.*/\1/p'; }
first_vtag() { printf '%s\n' "$1" | grep -oE '@[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -c2-; }

stale=0
report() {
    echo "  stale: $1"
    stale=$((stale + 1))
}
expect() {   # field, state.md value, repo value
    if [ "$2" != "$3" ]; then report "$1 — state.md says '${2:-<missing>}', repo says '$3'"; fi
}

r=$(row "Current version");      expect "Current version" "$(first_bold "$r")" "$version"
r=$(row "Cyrius toolchain pin"); expect "Cyrius toolchain pin" "$(first_bold "$r")" "$pin"
r=$(row "Last release date")
expect "Last release date" "$(printf '%s\n' "$r" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)" "$date"
r=$(row "Dependencies")
if [ -n "$sakshi" ]; then
    expect "Dependencies (sakshi)" "$(printf '%s\n' "$r" | sed -n 's/.*sakshi \*\*\([0-9.]*\)\*\*.*/\1/p')" "$sakshi"
fi
if [ -n "$bayan" ]; then
    expect "Dependencies (bayan)" "$(printf '%s\n' "$r" | sed -n 's/.*bayan \*\*\([0-9.]*\)\*\*.*/\1/p')" "$bayan"
fi
r=$(row '`.tcyr` test files')
expect ".tcyr test files" "$(first_bold "$r")" "$ntcyr"
expect ".tcyr test files @version" "$(first_vtag "$r")" "$version"
r=$(row "Total assertions")
expect "Total assertions @version (run --write --count)" "$(first_vtag "$r")" "$version"
expect "Total assertions file count" "$(printf '%s\n' "$r" | sed -n 's/.*across all \([0-9]*\) files.*/\1/p' | head -1)" "$ntcyr"
r=$(row "Fuzz harnesses")
expect "Fuzz harnesses" "$(printf '%s\n' "$r" | sed -n 's/^| Fuzz harnesses | \([0-9]*\) .*/\1/p')" "$nfcyr"
expect "Fuzz harnesses @version (run --write --count)" "$(first_vtag "$r")" "$version"

# Prose: written by hand, but it must name the release it describes.
r=$(row "Phase")
phase_v=$(printf '%s\n' "$r" | grep -oE '\*\*[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -c3-)
expect "Phase row (write the release's paragraph by hand)" "$phase_v" "$version"
shipped=$(awk '/^## Recently shipped/ { on = 1; next }
               on && /^\| [0-9]+\.[0-9]+\.[0-9]+ \|/ { print; exit }' "$STATE")
expect "Recently shipped top row (add the release's row by hand)" \
    "$(printf '%s\n' "$shipped" | cut -d'|' -f2 | tr -d ' ')" "$version"
expect "Recently shipped top row date" \
    "$(printf '%s\n' "$shipped" | cut -d'|' -f3 | tr -d ' ')" "$date"

if [ "$stale" -ne 0 ]; then
    echo "state-sync: docs/development/state.md is stale ($stale field(s)) for $version"
    echo "  fix: sh scripts/state-sync.sh --write --count, then hand-write any prose row named above"
    exit 1
fi
echo "state-sync: docs/development/state.md matches $version (pin $pin, $date, $ntcyr .tcyr files)"

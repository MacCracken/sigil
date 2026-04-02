#!/usr/bin/env bash
# bench-history.sh — Run benchmarks and append results to CSV history.
#
# Usage: ./scripts/bench-history.sh [label]
#   label: optional tag for the run (e.g. "baseline", "post-streaming-hash")
#
# Output: benches/history.csv (appended)

set -euo pipefail

LABEL="${1:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}"
HISTORY="benches/history.csv"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Run benchmarks and capture output
OUTPUT=$(cargo bench 2>&1)

# Write CSV header if file doesn't exist or is empty
if [ ! -s "$HISTORY" ]; then
    echo "timestamp,label,benchmark,estimate,unit" > "$HISTORY"
fi

# Parse criterion output using awk.
# Criterion prints either:
#   bench_name           time:   [low est high]    (single line)
# or:
#   bench_name                                      (name on its own line)
#                        time:   [low est high]    (time on next line)
echo "$OUTPUT" | awk -v ts="$TIMESTAMP" -v label="$LABEL" '
/^[a-zA-Z_][a-zA-Z0-9_]*$/ {
    pending_name = $1
    next
}
/time:/ {
    if (/^[a-zA-Z_]/) {
        name = $1
    } else {
        name = pending_name
    }
    pending_name = ""
    # Remove brackets and extract fields
    gsub(/[\[\]]/, "")
    # Find "time:" then skip low, grab est and unit
    for (i = 1; i <= NF; i++) {
        if ($i == "time:") {
            # i+1=low_val, i+2=low_unit, i+3=est_val, i+4=est_unit, i+5=high_val, i+6=high_unit
            est = $(i+3)
            unit = $(i+4)
            if (name != "" && est != "") {
                print ts "," label "," name "," est "," unit
            }
            break
        }
    }
}
' >> "$HISTORY"

echo "Benchmarks recorded in ${HISTORY} (label: ${LABEL})"
echo ""
echo "Results:"
echo "$OUTPUT" | grep -B1 "time:" | grep -v "^--$" | grep -v "Benchmarking" || true

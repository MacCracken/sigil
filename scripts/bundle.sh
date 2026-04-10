#!/bin/sh
# Bundle sigil into a single distributable file for cyrius stdlib
# Usage: sh scripts/bundle.sh
# Output: dist/sigil.cyr

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(cat "$ROOT/VERSION" | tr -d '[:space:]')

mkdir -p "$ROOT/dist"

{
echo "# sigil.cyr — system-wide trust verification for AGNOS"
echo "# Bundled distribution of sigil v${VERSION}"
echo "# Source: https://github.com/MacCracken/sigil"
echo "# License: GPL-3.0-only"
echo "#"
echo "# Usage: include \"lib/sigil.cyr\""
echo "# Init:  alloc_init(); ed25519_init();"
echo ""
for f in src/types.cyr src/error.cyr src/sha256.cyr src/hex.cyr src/ct.cyr \
         src/hmac.cyr src/sha512.cyr src/bigint_ext.cyr src/ed25519.cyr \
         src/trust.cyr src/integrity.cyr src/policy.cyr src/audit.cyr \
         src/tpm.cyr src/verify.cyr; do
    echo ""
    echo "# --- $(basename "$f") ---"
    echo ""
    grep -v "^include " "$ROOT/$f"
done
} > "$ROOT/dist/sigil.cyr"

echo "dist/sigil.cyr: $(wc -l < "$ROOT/dist/sigil.cyr") lines (v${VERSION})"

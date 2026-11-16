#!/usr/bin/env bash
# fuzz.sh [seconds] — run every Go fuzz target for a short time. A crash
# writes a failing input under testdata/fuzz/; commit it as a regression.
set -euo pipefail
T=${1:-30}
status=0
for pkg in $(go list ./...); do
  for f in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
    echo "== $pkg $f (${T}s)"
    go test "$pkg" -run='^$' -fuzz="^${f}\$" -fuzztime="${T}s" || status=1
  done
done
exit $status

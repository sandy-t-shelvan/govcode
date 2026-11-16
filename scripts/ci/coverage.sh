#!/usr/bin/env bash
# coverage.sh <min-percent> — run tests with the race detector and a
# coverage profile; fail if total statement coverage is below the floor.
# Raise the floor as coverage improves; never lower it to get green.
set -euo pipefail
MIN=${1:?minimum coverage percent}
OUT=${COVERAGE_OUT:-coverage.out}
go test -race -count=1 -covermode=atomic -coverprofile="$OUT" ./...
TOTAL=$(go tool cover -func="$OUT" | awk '/^total:/ {sub("%","",$3); print $3}')
echo "total coverage: ${TOTAL}% (floor ${MIN}%)"
awk -v t="$TOTAL" -v m="$MIN" 'BEGIN { exit !(t+0 >= m+0) }' || { echo "coverage ${TOTAL}% is below the ${MIN}% floor" >&2; exit 1; }

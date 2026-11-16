#!/usr/bin/env bash
# build-release.sh — reproducible, offline release build.
#
#   scripts/build-release.sh <version> <release-signing.key>
#
# Produces dist/govcode-<version>/ containing the binary, SBOM, AI-BOM,
# model lock, deployment files, and a manifest of every file's SHA-256
# signed with the release key. The build:
#   - uses only the Go standard library (no module downloads: GOPROXY=off)
#   - is reproducible (-trimpath, -buildid=, CGO_ENABLED=0); the script
#     builds twice and fails if the two binaries differ
#   - links the Go Cryptographic Module in FIPS 140-3 mode (GOFIPS140)
set -euo pipefail
VERSION=${1:?version}; KEY=${2:?release signing key}
ROOT=$(cd "$(dirname "$0")/.." && pwd); cd "$ROOT"
OUT=dist/govcode-$VERSION
rm -rf "$OUT"; mkdir -p "$OUT/bin"

export CGO_ENABLED=0 GOOS=${GOOS:-linux} GOARCH=${GOARCH:-amd64}
export GOPROXY=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local GONOSUMDB= GOFIPS140=${GOFIPS140:-v1.0.0}
LDFLAGS="-s -w -buildid= -X github.com/sandy-t-shelvan/govcode/internal/supply.Version=$VERSION"

go vet ./...
go test -count=1 ./...
build() { go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$1" ./cmd/govcode; }
build "$OUT/bin/govcode"
build "$OUT/bin/.repro-check"
a=$(sha256sum "$OUT/bin/govcode" | cut -d' ' -f1); b=$(sha256sum "$OUT/bin/.repro-check" | cut -d' ' -f1)
rm -f "$OUT/bin/.repro-check"
[ "$a" = "$b" ] || { echo "build is not reproducible: $a != $b" >&2; exit 1; }
echo "reproducible binary sha256 $a"

mkdir -p "$OUT/models" "$OUT/deploy" "$OUT/docs"
cp models/models.lock.json "$OUT/models/"
cp -r deploy/* "$OUT/deploy/"
cp docs/*.md "$OUT/docs/" 2>/dev/null || true
cp LICENSE README.md "$OUT/"
"$OUT/bin/govcode" sbom -lock models/models.lock.json -o "$OUT/sbom.cdx.json"
"$OUT/bin/govcode" aibom -lock models/models.lock.json -o "$OUT/aibom.cdx.json"
"$OUT/bin/govcode" manifest -dir "$OUT" -version "$VERSION"
"$OUT/bin/govcode" sign -key "$KEY" "$OUT/manifest.json"
( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
echo "release: $OUT"

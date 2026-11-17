#!/usr/bin/env bash
# build-rpm.sh — package a signed release directory as RHEL 8/9 RPMs.
#
#   scripts/build-rpm.sh dist/govcode-<version> [out_dir]
#
# Run it on a RHEL (or Rocky/Alma) build host of the same major version you
# deploy to, with rpm-build and selinux-policy-devel installed. The binary is
# not rebuilt: the RPM carries the exact file listed in the signed manifest,
# and this script checks that after building.
set -euo pipefail
REL=${1:?release directory (dist/govcode-<version>)}; OUT=${2:-dist/rpm}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REL=$(cd "$REL" && pwd); NAME=$(basename "$REL"); VERSION=${NAME#govcode-}
RPMVER=${VERSION//-/\~}   # RPM versions cannot contain '-'
[ -f "$REL/manifest.json.sig" ] || { echo "$REL is not a signed release (no manifest.json.sig)" >&2; exit 1; }
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
TOP=$(mktemp -d); trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,RPMS,SRPMS} "$TOP/stage/$NAME"
cp -a "$REL/." "$TOP/stage/$NAME/"
cp -a "$ROOT/packaging/selinux" "$TOP/stage/$NAME/selinux"
tar -C "$TOP/stage" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf "$TOP/SOURCES/govcode-$VERSION.tar" "$NAME"
cp "$ROOT/packaging/rpm/govcode.spec" "$TOP/SPECS/"
rpmbuild -bb --define "_topdir $TOP" --define "gc_version $RPMVER" --define "gc_release $VERSION" \
  ${RPMBUILD_FLAGS:-} "$TOP/SPECS/govcode.spec"
find "$TOP/RPMS" -name '*.rpm' -exec cp {} "$OUT/" \;

# The packaged binary must be the signed one.
want=$(python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); print([f["sha256"] for f in m["files"] if f["path"]=="bin/govcode"][0])' "$REL/manifest.json")
x=$(mktemp -d); main=$(find "$OUT" -maxdepth 1 -name "govcode-$RPMVER-*.x86_64.rpm" | head -1)
[ -n "$main" ] || { echo "built RPM not found in $OUT" >&2; exit 1; }
( cd "$x" && rpm2cpio "$main" | cpio -idm --quiet ./usr/bin/govcode )
got=$(sha256sum "$x/usr/bin/govcode" | cut -d' ' -f1); rm -rf "$x"
[ "$got" = "$want" ] || { echo "packaged binary $got differs from signed manifest $want" >&2; exit 1; }
echo "rpm binary matches signed manifest: $got"
ls -1 "$OUT"/*.rpm

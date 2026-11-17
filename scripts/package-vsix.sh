#!/usr/bin/env bash
# package-vsix.sh <out.vsix> — build the VS Code extension package offline.
#
# A .vsix is a zip with an OPC content-types file, an extension.vsixmanifest
# and the extension under extension/. Built with zip only (no vsce, no npm
# install, no network). Reproducible: fixed timestamps (SOURCE_DATE_EPOCH)
# and sorted entries, so the same source gives the same SHA-256.
set -euo pipefail
OUT=$(realpath -m "${1:?output .vsix}")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=$ROOT/vscode
VERSION=$(node -e "process.stdout.write(require('$SRC/package.json').version)")
EPOCH=${SOURCE_DATE_EPOCH:-1767225600}   # 2026-01-01T00:00:00Z
STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/extension"
# Shipped files only: no tests, no mocks.
for f in package.json extension.js README.md LICENSE.txt lib media; do cp -r "$SRC/$f" "$STAGE/extension/"; done

cat > "$STAGE/[Content_Types].xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension=".json" ContentType="application/json"/><Default Extension=".js" ContentType="application/javascript"/><Default Extension=".md" ContentType="text/markdown"/><Default Extension=".txt" ContentType="text/plain"/><Default Extension=".css" ContentType="text/css"/><Default Extension=".svg" ContentType="image/svg+xml"/><Default Extension=".vsixmanifest" ContentType="text/xml"/></Types>
XML

cat > "$STAGE/extension.vsixmanifest" <<XML
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="govcode" Version="$VERSION" Publisher="govcode-local" />
    <DisplayName>govcode</DisplayName>
    <Description xml:space="preserve">Air-gapped coding agent for legacy code: local model, sandboxed tools, signed audit log, two-person approval.</Description>
    <Tags></Tags>
    <Categories>Other</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.85.0" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
      <Property Id="Microsoft.VisualStudio.Code.LocalizedLanguages" Value="" />
    </Properties>
    <License>extension/LICENSE.txt</License>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="extension/LICENSE.txt" Addressable="true" />
  </Assets>
</PackageManifest>
XML

find "$STAGE" -exec touch -h -d "@$EPOCH" {} +
rm -f "$OUT"
( cd "$STAGE" && find . -type f | sed 's#^\./##' | LC_ALL=C sort | zip -q -X -D -9 "$OUT" -@ )
echo "$OUT ($(sha256sum "$OUT" | cut -d' ' -f1))"

#!/usr/bin/env bash
# vscode-real.sh — run the extension inside a REAL VS Code (GOV-43).
#
#   scripts/e2e/vscode-real.sh <vscode-dir> [govcode-binary]
#
# <vscode-dir> is an unpacked VS Code for linux-x64 (the directory holding
# the `code` executable). Pin and verify it on the low side; 1.95.3 is
# what this was validated with:
#   sha256 881c6dce9f9b18bdeaa0020197501be3808c6e23c26baa0ba905b0bc84175b46
#   (update.code.visualstudio.com/api/versions/1.95.3/linux-x64/stable)
# Runs headless under xvfb-run. The workspace is a scratch git repo (eval task
# 01) with a dev policy; the real `govcode serve --stdio` talks to the
# replayed model in scripts/e2e/fake_model.py on 127.0.0.1. The extension
# test suite is vscode/test/real/index.js.
set -euo pipefail
VSC=$(cd "${1:?unpacked VS Code dir}" && pwd); GC=$(command -v "${2:-govcode}")
ROOT=$(cd "$(dirname "$0")/../.." && pwd); PORT=${PORT:-18095}
T=$(mktemp -d); REPO=$T/repo; export HOME=$T/home; mkdir -p "$HOME" "$REPO"
cp -r "$ROOT/eval/tasks/01-c-buffer-overflow/repo/." "$REPO/"
git -C "$REPO" init -q -b main && git -C "$REPO" add -A && git -C "$REPO" -c user.name=t -c user.email=t@t commit -qm baseline
export GOVCODE_KEY=$T/me.key GOVCODE_POLICY=$T/policy.json
(cd "$REPO" && "$GC" init -o "$GOVCODE_POLICY" >/dev/null && "$GC" keygen --register -o "$GOVCODE_KEY" >/dev/null)
python3 -I - "$GOVCODE_POLICY" "$PORT" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
d["model"].update({"backend": "openai", "endpoint": f"http://127.0.0.1:{sys.argv[2]}/v1", "served_name": "fake-coder", "num_ctx": 16384})
d["tests"] = {"command": "make -s test", "timeout_seconds": 120, "require_pass": True}
d["max_turns"] = 12
json.dump(d, open(p, "w"), indent=2)
PY
mkdir -p "$T/user/User"
cat > "$T/user/User/settings.json" <<JSON
{"govcode.binaryPath": "$GC", "govcode.policyPath": "$GOVCODE_POLICY",
 "telemetry.telemetryLevel": "off", "update.mode": "none", "extensions.autoUpdate": false,
 "extensions.autoCheckUpdates": false, "workbench.startupEditor": "none", "security.workspace.trust.enabled": false}
JSON
python3 -I "$ROOT/scripts/e2e/fake_model.py" "$ROOT/scripts/e2e/session.json" "$PORT" & FAKE=$!
trap 'kill $FAKE 2>/dev/null; rm -rf "$T"' EXIT
sleep 1
export GOVCODE_VSC_RESULT=$T/result.txt
NOSANDBOX=(); [ "$(id -u)" = 0 ] && NOSANDBOX=(--no-sandbox)
set +e
xvfb-run -a "$VSC/code" "${NOSANDBOX[@]}" --disable-gpu --disable-workspace-trust --skip-welcome --skip-release-notes \
  --user-data-dir "$T/user" --extensions-dir "$T/ext" --disable-extensions \
  --extensionDevelopmentPath="$ROOT/vscode" --extensionTestsPath="$ROOT/vscode/test/real/index.js" \
  "$REPO" > "$T/vscode.log" 2>&1
rc=$?
set -e
cat "$GOVCODE_VSC_RESULT" 2>/dev/null || { echo "no results; VS Code log:"; tail -40 "$T/vscode.log"; }
pass=$(grep -c '^PASS' "$GOVCODE_VSC_RESULT" 2>/dev/null || true); fail=$(grep -c '^FAIL' "$GOVCODE_VSC_RESULT" 2>/dev/null || true)
echo "vscode-real: ${pass:-0} passed, ${fail:-0} failed (VS Code exit $rc)"
[ "$rc" = 0 ] && [ "${fail:-0}" = 0 ] && [ "${pass:-0}" -gt 0 ]

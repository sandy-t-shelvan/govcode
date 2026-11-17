#!/usr/bin/env bash
# run.sh — time govcode's own cost on a large repository (GOV-42).
#
#   scripts/scale/run.sh <git-repo> [govcode-binary]
#
# Uses a development policy and the deterministic replayed model
# (scripts/e2e/fake_model.py) driving scripts/scale/session.json, so only
# govcode and git are timed. session.json targets the Linux source tree
# (kernel/sched/core.c, drivers/net, README); edit it for another repo.
# `govcode init` puts the dev policy and audit state in
# <repo>/../.govcode-state/<name>/ and the run adds one proposal branch;
# use a scratch copy of the repository.
set -euo pipefail
REPO=$(cd "${1:?git repo}" && pwd); GC=${2:-govcode}
HERE=$(cd "$(dirname "$0")" && pwd); PORT=${PORT:-18090}
T=$(mktemp -d); export HOME=$T/home; mkdir -p "$HOME"
cd "$REPO"
"$GC" init >/dev/null
P=$(ls "$(dirname "$REPO")"/.govcode-state/"$(basename "$REPO")"/policy.json)
export GOVCODE_POLICY=$P
python3 -I - "$P" "$PORT" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
d["model"].update({"backend": "openai", "endpoint": f"http://127.0.0.1:{sys.argv[2]}/v1", "served_name": "fake-coder"})
d["tests"] = {"command": "true", "timeout_seconds": 60, "require_pass": True}
d["max_turns"] = 20
json.dump(d, open(p, "w"), indent=2)
PY
"$GC" keygen --register >/dev/null
python3 -I "$HERE/../e2e/fake_model.py" "$HERE/session.json" "$PORT" & FAKE=$!
trap 'kill $FAKE 2>/dev/null' EXIT
sleep 1
start=$(date +%s.%N)
out=$("$GC" run -non-interactive "scale test: exercise the tools on a large repository" 2>&1)
end=$(date +%s.%N)
echo "$out" | grep -E "Proposal|Stop reason" || true
ID=$(grep -oE 'Proposal p[0-9a-f-]+' <<<"$out" | awk '{print $2}')
python3 -I - "$(dirname "$P")/audit/log.jsonl" "$ID" <<'PY'
import datetime, json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
rows = [r for r in rows if r.get("session") == sys.argv[2]]
ts = lambda r: datetime.datetime.fromisoformat(r["ts"][:26].rstrip("Z"))
first = next(r for r in rows if r["kind"] == "model_response")
print(f"setup before first model turn: {(ts(first) - ts(rows[0])).total_seconds():.1f}s")
prev, n = None, 0
for r in rows:
    if r["kind"] == "model_response":
        prev = ts(r)
    elif r["kind"] == "tool_result" and prev:
        n += 1
        print(f"tool call {n:2d}: {(ts(r) - prev).total_seconds():6.2f}s")
PY
echo "wall: $(python3 -c "print(round($end-$start,1))")s"

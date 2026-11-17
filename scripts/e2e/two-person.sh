#!/usr/bin/env bash
# two-person.sh — end-to-end acceptance test of the approval and audit
# controls with REAL OS users. Run as root in a DISPOSABLE VM/container:
# it creates the users alice, bob and carol and a group govcode-e2e.
#
#   scripts/e2e/two-person.sh <release-dir> <release.key>
#
# alice = proposer, bob = approver, carol = valid user who is not an approver.
# Uses a strict root-owned policy, a chattr +a audit log, bubblewrap, and a
# deterministic fake model on 127.0.0.1 (scripts/e2e/fake_model.py).
set -uo pipefail
REL=$(cd "${1:?release dir}" && pwd); RELKEY=${2:?release key}
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
W=$(mktemp -d /tmp/govcode-e2e.XXXXXX); chmod 755 "$W"
G=govcode-e2e; PORT=18080
pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
expect_ok()   { local d=$1; shift; if out=$("$@" 2>&1); then ok "$d"; else bad "$d"; echo "$out" | tail -15 | sed 's/^/        /'; fi; }
expect_fail() { local d=$1 pat=$2; shift 2; if out=$("$@" 2>&1); then bad "$d (unexpectedly succeeded)"; echo "$out" | tail -5 | sed 's/^/        /'; elif grep -q -- "$pat" <<<"$out"; then ok "$d"; else bad "$d (wrong error)"; echo "$out" | tail -5 | sed 's/^/        /'; fi; }
as() { local u=$1; shift; runuser -u "$u" -- env -i HOME=/home/$u PATH=/usr/local/bin:/usr/bin:/bin GOVCODE_POLICY=$W/etc/policy.json bash -c "cd $W/repo && $*"; }
approve_tty() { # user id [extra]: drive the typed confirmation through a pty
  printf 'approve\n' | runuser -u "$1" -- env -i HOME=/home/$1 PATH=/usr/bin:/bin GOVCODE_POLICY=$W/etc/policy.json \
    script -qec "cd $W/repo && $GC approve $2 ${3:-}" /dev/null; }
cleanup() { [ -n "${FAKE:-}" ] && kill "$FAKE" 2>/dev/null; chattr -a "$W/state/audit/log.jsonl" 2>/dev/null; }
trap cleanup EXIT

echo "== setup in $W"
groupadd -f $G
for u in alice bob carol; do id $u >/dev/null 2>&1 || useradd -m -s /bin/bash $u; usermod -aG $G $u; done
mkdir -p $W/opt/bin $W/etc/trust $W/keys $W/state/audit $W/models $W/repo
cp "$REL/bin/govcode" $W/opt/bin/govcode; chmod 755 $W/opt/bin/govcode
# The ISSO installs trust material world-readable, as in DEPLOYMENT.md;
# govcode writes its own files under umask 007, so cp would leave them 0640.
install -m 644 "$REL/manifest.json" "$REL/manifest.json.sig" $W/etc/trust/
install -m 644 "${RELKEY%.key}.pub" $W/etc/trust/release.pub
GC=$W/opt/bin/govcode

$GC keygen -o $W/etc/trust/models.key >/dev/null
cat > $W/models/models.lock.json <<JSON
{"schema":"govcode.models.lock/v1","models":[{"id":"fake-coder","default":true,"name":"fake-coder","license":"MIT","publisher":"test",
 "upstream":{"repo":"none","revision":"none","files":[]},"artifact":{"format":"gguf","files":[]},
 "serve":{"ollama_name":"","num_ctx":16384,"max_tokens":2048,"temperature":0,"vllm_tool_call_parser":"","ollama_manifest_digest":""}}]}
JSON
$GC sign -key $W/etc/trust/models.key $W/models/models.lock.json >/dev/null
chmod 644 $W/etc/trust/models.pub $W/models/models.lock.json*

cp -r "$ROOT/eval/tasks/01-c-buffer-overflow/repo/." $W/repo/
git -C $W/repo init -q -b main && git -C $W/repo config core.sharedRepository group
git -C $W/repo add -A && git -C $W/repo -c user.name=root -c user.email=root@localhost commit -qm baseline
chgrp -R $G $W/repo && chmod -R g+rwX $W/repo && find $W/repo -type d -exec chmod g+s {} +
for u in alice bob carol; do runuser -u $u -- git config --global --add safe.directory $W/repo; done

chgrp $G $W/state $W/state/audit && chmod 2770 $W/state $W/state/audit
install -m 660 -g $G /dev/null $W/state/audit/log.jsonl
chattr +a $W/state/audit/log.jsonl

for u in alice bob carol; do
  as $u "$GC keygen" >/dev/null
  install -m 644 /home/$u/.config/govcode/signing.pub $W/keys/$u.pub   # ISSO installs, root-owned
done

cat > $W/etc/policy.json <<JSON
{
  "schema": "govcode.policy/v1",
  "classification": "UNCLASSIFIED//E2E-TEST",
  "repo_root": "$W/repo",
  "state_dir": "$W/state",
  "target_branch": "main",
  "sensitive": true,
  "two_person_rule": true,
  "approvers": ["bob"],
  "max_turns": 12,
  "model": {"backend": "openai", "endpoint": "http://127.0.0.1:$PORT/v1", "lock": "$W/models/models.lock.json",
            "id": "fake-coder", "served_name": "fake-coder", "num_ctx": 16384, "max_tokens": 2048, "temperature": 0},
  "tests": {"command": "make -s test", "timeout_seconds": 120, "require_pass": true},
  "commands": {"allowlist": ["make", "cc"], "prompt_for_others": false},
  "sandbox": {"mode": "required"},
  "trust": {"enforce": "strict", "release_keys": ["$W/etc/trust/release.pub"], "release_manifest": "$W/etc/trust/manifest.json",
            "model_keys": ["$W/etc/trust/models.pub"], "keyring_dir": "$W/keys"},
  "audit": {"require_append_only": true},
  "analysis": {"required": true, "analyzers": [{"name": "gcc-c89", "extensions": [".c", ".h"],
               "command": "gcc -fsyntax-only -std=c89 -pedantic -Wall -Wextra", "fail_on": ": (error|warning):"}]}
}
JSON
chmod 644 $W/etc/policy.json

python3 -I "$HERE/fake_model.py" "$HERE/session.json" $PORT & FAKE=$!
sleep 1

echo "== preflight"
expect_ok "alice: all strict preflight checks pass" as alice "$GC verify"

echo "== propose"
out=$(as alice "$GC run --non-interactive 'track_init overruns the callsign buffer for long callsigns; truncate and NUL-terminate.'" 2>&1)
ID=$(grep -oE 'Proposal p[0-9-]+[0-9a-f]+' <<<"$out" | head -1 | awk '{print $2}')
if [ -n "$ID" ] && grep -q ": ready" <<<"$out"; then ok "alice: run produced ready proposal $ID"; else bad "no ready proposal"; echo "$out" | tail -20; fi
grep -q "sandbox=true" <<<"$out" && ok "agent commands ran under bubblewrap" || bad "sandbox not active"
[ "$(git -C $W/repo log --format=%s -1 main)" = "baseline" ] && ok "target branch untouched after run" || bad "main changed without approval"

echo "== access control"
expect_fail "alice cannot approve her own proposal" "two-person rule" as alice "$GC approve $ID"
expect_fail "carol (not an approver) cannot approve" "not an approver" as carol "$GC approve $ID"
expect_fail "alice cannot edit the root-owned policy" "Permission denied" as alice "echo x >> $W/etc/policy.json"
expect_fail "alice cannot rewrite the append-only audit log" "Operation not permitted" as alice "echo x > $W/state/audit/log.jsonl"
expect_fail "approval without a terminal confirmation is refused" "not confirmed" as bob "$GC approve $ID < /dev/null"

echo "== review and approve"
expect_ok "bob: review verifies proposer signature and diff integrity" as bob "$GC review $ID --stat"
out=$(approve_tty bob "$ID" "-m 'LGTM'" 2>&1)
grep -q "Landed $ID" <<<"$out" && ok "bob: approved and landed" || { bad "approve failed"; echo "$out" | tail -10; }
msg=$(git -C $W/repo log -1 --format=%B main)
for t in "Govcode-Proposal" "Govcode-Proposed-By: alice" "Govcode-Approved-By: bob" "Govcode-Audit-Anchor" "Govcode-Classification"; do
  grep -q "$t" <<<"$msg" && ok "landed commit has '$t'" || bad "missing trailer $t"
done
[ "$(git -C $W/repo log -1 --format='%an|%cn' main)" = "alice|bob" ] && ok "author=proposer, committer=approver" || bad "author/committer wrong"
expect_ok "landed code passes the hidden checker" bash -c "git clone -q $W/repo $W/chk && cp $ROOT/eval/tasks/01-c-buffer-overflow/check/* $W/chk/ && make -s -C $W/chk test"
expect_fail "a decided proposal cannot be approved twice" "already" approve_tty bob "$ID"

echo "== audit"
expect_ok "audit verify: chain, signatures, objects, anchors" as bob "$GC audit verify"
as bob "$GC audit show -session $ID -n 500" > $W/trail.txt
for k in task model_response tool_result proposal approval landed; do grep -q " $k" $W/trail.txt && ok "trail has $k" || bad "trail missing $k"; done
# An attacker with root edits the log and restores the append-only flag, so
# preflight still passes and only the hash chain and anchors can catch it.
L=$W/state/audit/log.jsonl; cp $L $W/log.bak
chattr -a $L; sed -i '0,/"kind":"model_response"/s//"kind":"model_respons3"/' $L; chattr +a $L
grep -q model_respons3 $L || bad "tamper step did not modify the log"
expect_fail "modified audit entry is detected" "content does not match" as bob "$GC audit verify --no-objects"
chattr -a $L; head -n 4 $W/log.bak > $L; chattr +a $L
expect_fail "truncated audit log is detected via commit anchor" "missing from the log" as bob "$GC audit verify --no-objects"
chattr -a $L; cat $W/log.bak > $L; chattr +a $L

echo "== integrity of a second proposal"
# The fake model replays the same fix, so put the defect back on main first.
git -C $W/repo -c user.name=root -c user.email=root@localhost revert --no-edit -m 1 HEAD >/dev/null
out=$(as alice "$GC run --non-interactive 'same fix, second attempt'" 2>&1)
ID2=$(grep -oE 'Proposal p[0-9-]+[0-9a-f]+' <<<"$out" | head -1 | awk '{print $2}')
if [ -n "$ID2" ]; then
  as alice "git update-ref refs/heads/govcode/proposal/$ID2 main~1"
  expect_fail "branch altered after signing is refused" "moved" approve_tty bob "$ID2"
  expect_ok "bob can reject it with a reason" as bob "$GC reject $ID2 -m 'branch tampered'"
else
  bad "second proposal not created"; echo "$out" | tail -10
fi

echo "== supply chain"
cp $GC $W/opt/bin/govcode-tampered && printf '\0' >> $W/opt/bin/govcode-tampered && chmod 755 $W/opt/bin/govcode-tampered
expect_fail "tampered binary refuses to run in strict mode" "not in the signed release manifest" as alice "$W/opt/bin/govcode-tampered verify"
cp $W/models/models.lock.json $W/models/lock.bak; sed -i 's/16384/16385/' $W/models/models.lock.json
expect_fail "tampered model lock is refused" "does not verify" as alice "$GC verify"
cp $W/models/lock.bak $W/models/models.lock.json
mkdir -p $W/other && git -C $W/other init -q
expect_fail "govcode refuses a second repository" "grants access only to" runuser -u alice -- env -i HOME=/home/alice PATH=/usr/bin:/bin GOVCODE_POLICY=$W/etc/policy.json bash -c "cd $W/other && $GC verify"

echo
echo "e2e: $pass passed, $fail failed  (workspace $W)"
[ $fail -eq 0 ]

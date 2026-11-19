package app

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/analysis"
	"github.com/sandy-t-shelvan/govcode/internal/audit"
	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/policy"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
	"github.com/sandy-t-shelvan/govcode/internal/supply"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

// world builds a repo, a SECRET-level dev policy, a registered key, and
// returns an opened App.
func world(t *testing.T) *App {
	t.Helper()
	a, checks, err := openWorld(t, nil)
	if err != nil {
		t.Fatalf("Open: %v %+v", err, checks)
	}
	return a
}

// openWorld is world with a hook to adjust the policy before Open.
func openWorld(t *testing.T, tweak func(*policy.Policy)) (*App, []Check, error) {
	t.Helper()
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	os.MkdirAll(repo, 0o755)
	os.WriteFile(filepath.Join(repo, "cfg.c"), []byte("int port = 1;\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "Makefile"), []byte("test:\n\t@true\n"), 0o644)
	for _, a := range [][]string{{"init", "-q", "-b", "main"}, {"add", "-A"}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base"}} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, a...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", a, out)
		}
	}
	u, _ := identity.Current()
	p := policy.Dev(repo, filepath.Join(base, "state"), u.Username)
	p.Classification = "SECRET//NOFORN"
	p.Tests.Command = "make -s test"
	if tweak != nil {
		tweak(p)
	}
	b, _ := json.Marshal(p)
	pol := filepath.Join(base, "policy.json")
	os.WriteFile(pol, b, 0o644)
	key := filepath.Join(base, "me.key")
	pub, err := sign.GenerateKeyFiles(strings.TrimSuffix(key, ".key"))
	if err != nil {
		t.Fatal(err)
	}
	keyring.Register(filepath.Join(base, "state", "keys"), u, pub)
	t.Setenv("GOVCODE_KEY", key)
	wd, _ := os.Getwd()
	os.Chdir(repo)
	t.Cleanup(func() { os.Chdir(wd) })
	return Open(pol, io.Discard, true)
}

func edit(newText string) *llm.Scripted {
	args, _ := json.Marshal(map[string]any{"path": "cfg.c", "old_text": "int port = 1;", "new_text": newText})
	return &llm.Scripted{Responses: []llm.Response{
		{ToolCalls: []llm.ToolCall{{Name: "edit_file", Args: args, Source: llm.SourceNative}}},
		{ToolCalls: []llm.ToolCall{{Name: "run_tests", Args: json.RawMessage(`{}`), Source: llm.SourceNative}}},
		{ToolCalls: []llm.ToolCall{{Name: "finish", Args: json.RawMessage(`{"summary":"done"}`), Source: llm.SourceNative}}},
	}}
}

func TestRunCleanProposalIsReady(t *testing.T) {
	a := world(t)
	p, err := a.Run(context.Background(), RunOptions{Task: "set port to 2", Backend: edit("int port = 2;")})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != proposal.StatusReady || len(p.Blocked) != 0 || len(p.Files) != 1 {
		t.Fatalf("proposal %+v", p)
	}
	main, _ := a.Repo.RevParse("refs/heads/main")
	if main != p.Base {
		t.Fatal("target branch moved during run")
	}
	r, _ := a.Log.Verify(a.Keyring, nil, true)
	if !r.OK() {
		t.Fatalf("audit: %v", r.Problems)
	}
}

func TestRunWithSecretIsBlocked(t *testing.T) {
	a := world(t)
	p, err := a.Run(context.Background(), RunOptions{Task: "add the db password", Backend: edit(`int port = 1;
static const char *db_password = "Tr0ub4dor&3x";`)})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != proposal.StatusBlocked || len(p.Blocked) != 1 || !strings.Contains(p.Blocked[0], "password assignment at cfg.c:2") {
		t.Fatalf("proposal %+v", p)
	}
	if strings.Contains(strings.Join(p.Blocked, ""), "Tr0ub4dor") {
		t.Fatal("secret value leaked into the proposal record")
	}
	if _, err := a.Store.Approve(a.Repo, proposal.Rules{}, p, identity.User{UID: 99999, Username: "other"}, a.Signer, "", nil, nil); err == nil {
		t.Fatal("blocked proposal approved")
	}
}

func TestRunRefusesOverClassifiedTask(t *testing.T) {
	a := world(t)
	_, err := a.Run(context.Background(), RunOptions{Task: "TOP SECRET//SI\nfix the tracker", Backend: edit("x")})
	if err == nil || !strings.Contains(err.Error(), "TOP SECRET marking") {
		t.Fatalf("over-classified task accepted: %v", err)
	}
	var kinds []string
	a.Log.Each(func(e *audit.Entry, _ []byte) error { kinds = append(kinds, e.Kind); return nil })
	if strings.Join(kinds, ",") != "spillage_blocked" {
		t.Fatalf("audit kinds %v", kinds)
	}
	ids, _ := a.Store.List()
	if len(ids) != 0 {
		t.Fatal("proposal created for refused task")
	}
}

func TestPreProposalHookBlocks(t *testing.T) {
	a := world(t)
	a.Policy.Hooks.PreProposal = []string{"! grep -q 'port = 9' cfg.c"}
	p, err := a.Run(context.Background(), RunOptions{Task: "set port 9", Backend: edit("int port = 9;")})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != proposal.StatusBlocked || len(p.Blocked) != 1 || !strings.Contains(p.Blocked[0], "site check failed") {
		t.Fatalf("proposal %+v", p)
	}
}

func TestMemoryInPromptAndAudited(t *testing.T) {
	a := world(t)
	os.WriteFile(filepath.Join(a.Repo.Root, "GOVCODE.md"), []byte("All ports are odd numbers."), 0o644)
	exec.Command("git", "-C", a.Repo.Root, "add", "GOVCODE.md").Run()
	exec.Command("git", "-C", a.Repo.Root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "mem").Run()
	m := edit("int port = 3;")
	if _, err := a.Run(context.Background(), RunOptions{Task: "set port", Backend: m}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Seen[0][1].Content, "All ports are odd numbers.") {
		t.Fatalf("GOVCODE.md not in task prompt: %q", m.Seen[0][1].Content)
	}
	found := false
	a.Log.Each(func(e *audit.Entry, _ []byte) error {
		if e.Kind == "memory_loaded" {
			found = true
		}
		return nil
	})
	if !found {
		t.Fatal("memory load not audited")
	}
}

type autoPlan struct{ n int }

func (r *autoPlan) ReviewPlan([]string, string) (bool, string) { r.n++; return true, "" }

func TestPolicyCanRequirePlanMode(t *testing.T) {
	a := world(t)
	a.Policy.RequirePlanApproval = true
	if _, err := a.Run(context.Background(), RunOptions{Task: "x", Backend: edit("x")}); err == nil {
		t.Fatal("required plan mode ran without a reviewer")
	}
	plan, _ := json.Marshal(map[string]any{"steps": []string{"set port"}, "summary": "s"})
	m := edit("int port = 5;")
	m.Responses = append([]llm.Response{{ToolCalls: []llm.ToolCall{{Name: "propose_plan", Args: plan, Source: llm.SourceNative}}}}, m.Responses...)
	rv := &autoPlan{}
	p, err := a.Run(context.Background(), RunOptions{Task: "set port", Backend: m, PlanReviewer: rv})
	if err != nil || rv.n != 1 || p.Status != proposal.StatusReady {
		t.Fatalf("err=%v reviews=%d proposal=%+v", err, rv.n, p)
	}
}

func TestSIEMExportCarriesNoContent(t *testing.T) {
	a := world(t)
	sock := filepath.Join(t.TempDir(), "log")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skip("unixgram unavailable")
	}
	defer l.Close()
	a.Policy.SIEM = policy.SIEM{Syslog: true, Socket: sock}
	if _, err := a.Run(context.Background(), RunOptions{Task: "add the db password", Backend: edit(`int port = 1;
static const char *db_password = "Tr0ub4dor&3x";`)}); err != nil {
		t.Fatal(err)
	}
	var got []string
	buf := make([]byte, 8192)
	for {
		l.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, err := l.ReadFromUnix(buf)
		if err != nil {
			break
		}
		got = append(got, string(buf[:n]))
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{`event="task"`, `event="secret_found"`, `kind="password assignment"`, `event="proposal"`, `status="blocked"`, `classification="SECRET//NOFORN"`} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %s in SIEM stream:\n%s", want, all)
		}
	}
	if strings.Contains(all, "Tr0ub4dor") || strings.Contains(all, "add the db password") {
		t.Fatalf("SIEM stream leaked content:\n%s", all)
	}
}

// repoLock is resolved at start-up because openWorld changes directory.
var repoLock, _ = filepath.Abs("../../models/models.lock.json")

func useRepoLock(id string) func(*policy.Policy) {
	return func(p *policy.Policy) {
		lock := repoLock
		p.Model.Lock, p.Model.ID = lock, id
		p.Model.DeniedOrigins = []string{"CN"}
	}
}

func TestDeniedModelOriginIsFatalEvenInWarnMode(t *testing.T) {
	_, checks, err := openWorld(t, useRepoLock("qwen3-coder-30b-a3b"))
	if err == nil || !strings.Contains(err.Error(), "model origin") || !strings.Contains(err.Error(), "origin CN is denied") {
		t.Fatalf("want origin failure, got %v %+v", err, checks)
	}
}

func TestAllowedModelOriginPasses(t *testing.T) {
	a, checks, err := openWorld(t, useRepoLock("devstral-small-24b"))
	if err != nil {
		t.Fatalf("%v %+v", err, checks)
	}
	if !hasCheck(checks, "model origin", "PASS") || a.OriginException != nil {
		t.Fatalf("%+v", checks)
	}
}

func TestOriginExceptionIsWarnedAndAudited(t *testing.T) {
	exc := func(expires string) func(*policy.Policy) {
		return func(p *policy.Policy) {
			useRepoLock("qwen3-coder-30b-a3b")(p)
			p.Model.OriginException = &policy.OriginException{ModelID: "qwen3-coder-30b-a3b", AuthorizedBy: "AO Smith", Reference: "memo-117", Expires: expires}
		}
	}
	if _, _, err := openWorld(t, exc("2020-01-01")); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired exception accepted: %v", err)
	}
	a, checks, err := openWorld(t, exc(time.Now().AddDate(0, 1, 0).Format("2006-01-02")))
	if err != nil {
		t.Fatalf("%v %+v", err, checks)
	}
	if !hasCheck(checks, "model origin", "WARN") || a.OriginException == nil {
		t.Fatalf("%+v", checks)
	}
	if _, err := a.Run(context.Background(), RunOptions{Task: "set port to 2", Backend: edit("int port = 2;")}); err != nil {
		t.Fatal(err)
	}
	found := false
	a.Log.Each(func(e *audit.Entry, _ []byte) error {
		if e.Kind == "task" {
			found = true
			b, _ := json.Marshal(e.Summary)
			if !strings.Contains(string(b), `"model_origin":"CN"`) || !strings.Contains(string(b), `"reference":"memo-117"`) {
				t.Errorf("task entry lacks origin exception: %s", b)
			}
		}
		return nil
	})
	if !found {
		t.Fatal("no task entry")
	}
}

func hasCheck(cs []Check, name, status string) bool {
	for _, c := range cs {
		if c.Name == name && c.Status == status {
			return true
		}
	}
	return false
}

func TestBuildProvenancePreflight(t *testing.T) {
	self, err := supply.SelfSHA256()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mk := func(name string, subjectSHA string) (bundle, pub string) {
		base := filepath.Join(dir, name)
		if _, err := sign.GenerateKeyFiles(base); err != nil {
			t.Fatal(err)
		}
		s, _ := sign.LoadSigner(base + ".key")
		st := &supply.Statement{Type: supply.StatementType, PredicateType: supply.SLSAProvenanceType,
			Predicate: json.RawMessage(`{"buildDefinition":{"externalParameters":{"commit":"c0ffee","source":"git+file:///src"}},"runDetails":{"builder":{"id":"host://b"}}}`),
			Subject:   []supply.Subject{{Name: "bin/govcode", Digest: map[string]string{"sha256": subjectSHA}}}}
		line, _ := supply.SignStatement(s, st)
		bundle = base + ".intoto.jsonl"
		os.WriteFile(bundle, line, 0o644)
		return bundle, base + ".pub"
	}
	good, goodPub := mk("good", self)
	other, _ := mk("other", strings.Repeat("0", 64))
	trust := func(bundle, pub string) func(*policy.Policy) {
		return func(p *policy.Policy) { p.Trust.ReleaseProvenance, p.Trust.ReleaseKeys = bundle, []string{pub} }
	}
	_, checks, err := openWorld(t, trust(good, goodPub))
	if err != nil || !hasCheck(checks, "build provenance", "PASS") {
		t.Fatalf("good provenance: %v %+v", err, checks)
	}
	if _, _, err := openWorld(t, trust(other, goodPub)); err == nil || !strings.Contains(err.Error(), "build provenance") {
		t.Fatalf("provenance signed by another key accepted: %v", err)
	}
	wrongSubject, _ := mk("wrong", strings.Repeat("0", 64))
	otherPub := filepath.Join(dir, "wrong.pub")
	if _, _, err := openWorld(t, trust(wrongSubject, otherPub)); err == nil || !strings.Contains(err.Error(), "not a subject") {
		t.Fatalf("provenance without this binary accepted: %v", err)
	}
}

func TestLandWritesVerifiableEvidence(t *testing.T) {
	a := world(t)
	p, err := a.Run(context.Background(), RunOptions{Task: "set port to 2 SECRETTASKTEXT", Backend: edit("int port = 2;")})
	if err != nil {
		t.Fatal(err)
	}
	if p.ModelInfo == nil || p.AuditTaskHash == "" || len(p.Checks) == 0 {
		t.Fatalf("proposal lacks evidence inputs: %+v", p)
	}
	res, err := a.Land(p, proposal.Rules{Classification: a.Policy.Classification}, "looks right")
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := a.Repo.Git("log", "-1", "--format=%B", res.Commit)
	if !strings.Contains(msg, "Govcode-Evidence: "+res.Evidence) {
		t.Fatalf("no evidence trailer:\n%s", msg)
	}
	v, err := a.VerifyEvidence(res.Commit)
	if err != nil {
		t.Fatal(err)
	}
	r := v.Record
	if r.Proposal != p.ID || r.TaskSHA256 != p.TaskSHA256 || r.DiffSHA256 != p.DiffSHA256 || r.Audit.LastSeq <= r.Audit.FirstSeq {
		t.Fatalf("%+v", r)
	}
	var names []string
	for _, c := range r.Checks {
		names = append(names, c.Name+"="+c.Result)
	}
	if got := strings.Join(names, ","); !strings.Contains(got, "secret_scan=pass") || !strings.Contains(got, "spillage_guard=pass") || !strings.Contains(got, "tests=pass") {
		t.Errorf("checks %s", got)
	}
	raw, _ := os.ReadFile(filepath.Join(a.Evidence.Dir, p.ID+".json"))
	if strings.Contains(string(raw), "SECRETTASKTEXT") || strings.Contains(string(raw), "int port") {
		t.Fatal("evidence record contains task text or code")
	}
	if _, err := a.VerifyEvidence(p.ID); err != nil {
		t.Errorf("by proposal id: %v", err)
	}
	// Replacing the record (even with a validly signed one) breaks the trailer binding.
	f := filepath.Join(a.Evidence.Dir, p.ID+".json")
	os.Chmod(f, 0o644)
	os.WriteFile(f, append(raw, ' '), 0o644)
	if _, err := a.VerifyEvidence(res.Commit); err == nil || !strings.Contains(err.Error(), "trailer says") {
		t.Errorf("altered evidence accepted: %v", err)
	}
	if _, err := a.VerifyEvidence("main~1"); err == nil {
		t.Error("commit without evidence trailer accepted")
	}
}

func withGCC(unanalyzedOK ...string) func(*policy.Policy) {
	return func(p *policy.Policy) {
		p.Analysis = policy.Analysis{Required: true, UnanalyzedOK: unanalyzedOK, Analyzers: []analysis.Analyzer{
			{Name: "gcc-syntax", Extensions: []string{".c", ".h"}, Command: "gcc -fsyntax-only -Wall", FailOn: "error"}}}
	}
}

func TestStaticAnalysisGate(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not installed")
	}
	a, checks, err := openWorld(t, withGCC())
	if err != nil || !hasCheck(checks, "static analysis", "PASS") {
		t.Fatalf("%v %+v", err, checks)
	}
	p, err := a.Run(context.Background(), RunOptions{Task: "set port", Backend: edit("int port = 2;")})
	if err != nil || p.Status != proposal.StatusReady {
		t.Fatalf("clean change: %v %+v", err, p)
	}
	found := false
	for _, c := range p.Checks {
		if c.Name == "analysis: gcc-syntax" && c.Result == "pass" && strings.Contains(c.Detail, "sha256") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no analysis evidence: %+v", p.Checks)
	}

	p, err = a.Run(context.Background(), RunOptions{Task: "break it", Backend: edit("int port = ;")})
	if err != nil || p.Status != proposal.StatusBlocked || !strings.Contains(strings.Join(p.Blocked, ";"), "static analysis: gcc-syntax failed") {
		t.Fatalf("broken change not blocked: %v %+v", err, p)
	}
}

func TestUnanalyzedFileBlocksWhenRequired(t *testing.T) {
	mk := func() *llm.Scripted {
		args, _ := json.Marshal(map[string]any{"path": "Makefile", "old_text": "\t@true", "new_text": "\t@true # ok"})
		return &llm.Scripted{Responses: []llm.Response{
			{ToolCalls: []llm.ToolCall{{Name: "edit_file", Args: args, Source: llm.SourceNative}}},
			{ToolCalls: []llm.ToolCall{{Name: "run_tests", Args: json.RawMessage(`{}`), Source: llm.SourceNative}}},
			{ToolCalls: []llm.ToolCall{{Name: "finish", Args: json.RawMessage(`{"summary":"done"}`), Source: llm.SourceNative}}},
		}}
	}
	a, _, err := openWorld(t, withGCC())
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Run(context.Background(), RunOptions{Task: "touch Makefile", Backend: mk()})
	if err != nil || p.Status != proposal.StatusBlocked || !strings.Contains(strings.Join(p.Blocked, ";"), "no analyzer covers Makefile") {
		t.Fatalf("uncovered file not blocked: %v %+v", err, p)
	}
	a, _, err = openWorld(t, withGCC("Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := a.Run(context.Background(), RunOptions{Task: "touch Makefile", Backend: mk()}); err != nil || p.Status != proposal.StatusReady {
		t.Fatalf("exempt file blocked: %v %+v", err, p)
	}
}

func TestMissingAnalyzerFailsPreflight(t *testing.T) {
	_, _, err := openWorld(t, func(p *policy.Policy) {
		p.Analysis = policy.Analysis{Required: true, Analyzers: []analysis.Analyzer{{Name: "x", Extensions: []string{".c"}, Command: "no-such-analyzer-xyz"}}}
	})
	if err == nil || !strings.Contains(err.Error(), "static analysis") {
		t.Fatalf("missing analyzer accepted: %v", err)
	}
}

func TestPickleLockEntryAndDirtyScanFailPreflight(t *testing.T) {
	write := func(m map[string]any) string {
		b, _ := json.Marshal(map[string]any{"schema": "govcode.models.lock/v1", "models": []any{m}})
		p := filepath.Join(t.TempDir(), "lock.json")
		os.WriteFile(p, b, 0o644)
		return p
	}
	base := func() map[string]any {
		return map[string]any{"id": "m", "name": "M", "publisher": "P", "origin": "FR",
			"upstream": map[string]any{"repo": "r", "revision": "x", "files": []any{}},
			"artifact": map[string]any{"format": "gguf", "files": []any{map[string]any{"path": "m.gguf"}}},
			"serve":    map[string]any{"num_ctx": 32768}}
	}
	use := func(lock string) func(*policy.Policy) {
		return func(p *policy.Policy) { p.Model.Lock, p.Model.ID = lock, "m" }
	}
	pickle := base()
	pickle["upstream"] = map[string]any{"repo": "r", "revision": "x", "files": []any{map[string]any{"path": "pytorch_model.bin"}}}
	if _, _, err := openWorld(t, use(write(pickle))); err == nil || !strings.Contains(err.Error(), "model format") {
		t.Fatalf("pickle lock entry accepted: %v", err)
	}
	dirty := base()
	dirty["staging_scan"] = map[string]any{"scanner": "clamscan", "version": "1.4", "result": "Win.Trojan.X FOUND", "scanned_at": "2026-11-17T00:00:00Z"}
	if _, _, err := openWorld(t, use(write(dirty))); err == nil || !strings.Contains(err.Error(), "model scan") {
		t.Fatalf("dirty scan accepted: %v", err)
	}
	clean := base()
	clean["staging_scan"] = map[string]any{"scanner": "clamscan", "version": "1.4", "result": "clean", "scanned_at": "2026-11-17T00:00:00Z"}
	_, checks, err := openWorld(t, use(write(clean)))
	if err != nil || !hasCheck(checks, "model scan", "PASS") || !hasCheck(checks, "model format", "PASS") {
		t.Fatalf("%v %+v", err, checks)
	}
}

// Outside any work tree govcode falls back to the policy's repository, but a
// work tree git refuses to open (another owner, a broken .git) is refused,
// never silently swapped for the granted repository.
func TestOpenDoesNotSwapAnUnopenableRepo(t *testing.T) {
	a, _, err := openWorld(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	pol, granted := a.Policy.Path, a.Repo.Root
	base := t.TempDir()

	plain := filepath.Join(base, "plain")
	os.MkdirAll(plain, 0o755)
	os.Chdir(plain)
	b, _, err := Open(pol, io.Discard, true)
	if err != nil {
		t.Fatalf("outside a work tree: %v", err)
	}
	if b.Repo.Root != granted {
		t.Fatalf("fallback repo %s, want %s", b.Repo.Root, granted)
	}

	other := filepath.Join(base, "other")
	os.MkdirAll(filepath.Join(other, "sub"), 0o755)
	os.WriteFile(filepath.Join(other, ".git"), []byte("gitdir: /nonexistent\n"), 0o644)
	os.Chdir(filepath.Join(other, "sub"))
	if _, _, err := Open(pol, io.Discard, true); err == nil || !strings.Contains(err.Error(), "grants access only to") {
		t.Fatalf("unopenable repo: err = %v, want a refusal", err)
	}
}

// A real run wires read rules into the command sandbox (GOV-47): with
// read_file(keys/**) denied, `cat` and `git show` through run_command must not
// hand the protected file to the model.
func TestRunHidesReadProtectedFilesFromCommands(t *testing.T) {
	a, _, err := openWorld(t, func(p *policy.Policy) {
		p.Permissions.Deny = append(p.Permissions.Deny, "read_file(keys/**)")
		p.Permissions.Allow = append(p.Permissions.Allow, "run_command(cat *)", "run_command(git show *)")
	})
	if err != nil {
		t.Fatal(err)
	}
	probe, perr := tools.NewRunner(tools.SandboxBestEffort, a.Repo.Root, nil, nil)
	if perr != nil || !probe.Sandboxed() {
		skipNoBwrap(t)
	}
	root := a.Repo.Root
	os.MkdirAll(filepath.Join(root, "keys"), 0o755)
	os.WriteFile(filepath.Join(root, "keys", "creds.h"), []byte("int secret = 4242;\n"), 0o644)
	for _, g := range [][]string{{"add", "-A"}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "keys"}} {
		if out, err := exec.Command("git", append([]string{"-C", root}, g...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", g, out)
		}
	}
	cmd := func(c string) llm.Response {
		args, _ := json.Marshal(map[string]any{"command": c})
		return llm.Response{ToolCalls: []llm.ToolCall{{Name: "run_command", Args: args, Source: llm.SourceNative}}}
	}
	be := &llm.Scripted{Responses: []llm.Response{
		cmd("cat keys/creds.h"),
		cmd("git show HEAD:keys/creds.h"),
		{ToolCalls: []llm.ToolCall{{Name: "finish", Args: json.RawMessage(`{"summary":"looked"}`), Source: llm.SourceNative}}},
	}}
	if _, err := a.Run(context.Background(), RunOptions{Task: "look at the keys", Backend: be}); err != nil && !strings.Contains(err.Error(), "no changes") {
		t.Logf("run: %v", err)
	}
	if len(be.Seen) < 3 {
		t.Fatalf("model saw %d turns", len(be.Seen))
	}
	for _, m := range be.Seen[len(be.Seen)-1] {
		if strings.Contains(m.Content, "4242") {
			t.Fatalf("a command returned protected content to the model:\n%s", m.Content)
		}
	}
}

// Analyzers and site checks run in the sandbox, so they cannot see a file the
// read rules hide. A change to such a file must block, not pass unchecked.
func TestChangeToHiddenFileBlocksChecks(t *testing.T) {
	a, _, err := openWorld(t, func(p *policy.Policy) {
		p.Permissions.Deny = append(p.Permissions.Deny, "read_file(keys/**)")
		p.Analysis.Required = true
		p.Analysis.Analyzers = []analysis.Analyzer{{Name: "true", Extensions: []string{".h", ".c"}, Command: "true"}}
	})
	if err != nil {
		t.Fatal(err)
	}
	probe, _ := tools.NewRunner(tools.SandboxBestEffort, a.Repo.Root, nil, nil)
	if probe == nil || !probe.Sandboxed() {
		skipNoBwrap(t)
	}
	create, _ := json.Marshal(map[string]any{"path": "keys/new.h", "content": "int planted;\n"})
	be := &llm.Scripted{Responses: []llm.Response{
		{ToolCalls: []llm.ToolCall{{Name: "create_file", Args: create, Source: llm.SourceNative}}},
		{ToolCalls: []llm.ToolCall{{Name: "run_tests", Args: json.RawMessage(`{}`), Source: llm.SourceNative}}},
		{ToolCalls: []llm.ToolCall{{Name: "finish", Args: json.RawMessage(`{"summary":"added"}`), Source: llm.SourceNative}}},
	}}
	p, err := a.Run(context.Background(), RunOptions{Task: "add a header", Backend: be})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != proposal.StatusBlocked || !strings.Contains(strings.Join(p.Blocked, "\n"), "checks cannot see keys/new.h") {
		t.Fatalf("status=%s blocked=%v", p.Status, p.Blocked)
	}
}

// verify reports whether protected files can be hidden from commands, so a
// site finds a too-old bubblewrap at acceptance rather than at first use.
func TestPreflightReportsSandboxHiding(t *testing.T) {
	_, checks, err := openWorld(t, func(p *policy.Policy) {
		p.Permissions.Deny = append(p.Permissions.Deny, "read_file(keys/**)")
	})
	if err != nil {
		t.Fatal(err)
	}
	probe, _ := tools.NewRunner(tools.SandboxBestEffort, t.TempDir(), nil, nil)
	want := "FAIL"
	if probe != nil && probe.CanHide() {
		want = "PASS"
	}
	for _, c := range checks {
		if c.Name == "sandbox hiding" {
			if c.Status != want {
				t.Fatalf("sandbox hiding = %s, want %s (%s)", c.Status, want, c.Detail)
			}
			return
		}
	}
	t.Fatal("no sandbox hiding check with read rules in the policy")
}

// skipNoBwrap skips a sandbox test when bubblewrap is unusable, unless
// GOVCODE_REQUIRE_BWRAP=1 (set in CI), where a skip would turn the
// sandbox security tests into silent no-ops: then it fails instead.
func skipNoBwrap(t *testing.T) {
	t.Helper()
	if os.Getenv("GOVCODE_REQUIRE_BWRAP") == "1" {
		t.Fatal("bubblewrap is not usable here, but GOVCODE_REQUIRE_BWRAP=1 requires the sandbox tests to run")
	}
	t.Skip("bubblewrap not available")
}

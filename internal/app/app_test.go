package app

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/audit"
	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/policy"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

// world builds a repo, a SECRET-level dev policy, a registered key, and
// returns an opened App.
func world(t *testing.T) *App {
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
	a, checks, err := Open(pol, io.Discard, true)
	if err != nil {
		t.Fatalf("Open: %v %+v", err, checks)
	}
	return a
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
	if _, err := a.Store.Approve(a.Repo, proposal.Rules{}, p, identity.User{UID: 99999, Username: "other"}, a.Signer, "", nil); err == nil {
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

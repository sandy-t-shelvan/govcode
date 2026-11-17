package proposal

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/gitx"
	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

type world struct {
	repo         *gitx.Repo
	store        Store
	kr           *keyring.Keyring
	alice, bob   identity.User
	aliceS, bobS sign.Signer
	anchors      []string
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func setup(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.c"), []byte("int a = 1;\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.c"), []byte("int b = 1;\n"), 0o644)
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-qm", "base")
	repo, err := gitx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	me, _ := identity.Current()
	// alice is the real current user (so her key can be ownership-bound in
	// the keyring); bob is a synthetic second identity.
	alice := me
	bob := identity.User{UID: me.UID + 1000, Username: "bob", Host: me.Host}
	_, ak, _ := ed25519.GenerateKey(rand.Reader)
	_, bk, _ := ed25519.GenerateKey(rand.Reader)
	krDir := filepath.Join(t.TempDir(), "keys")
	keyring.Register(krDir, alice, ak.Public().(ed25519.PublicKey))
	kr, _ := keyring.Load(krDir)
	return &world{repo: repo, store: Store{Dir: filepath.Join(t.TempDir(), "proposals")}, kr: kr,
		alice: alice, bob: bob, aliceS: sign.NewSigner(ak), bobS: sign.NewSigner(bk)}
}

func (w *world) anchor(kind string, _ map[string]any) (string, error) {
	a := strings.Repeat("ab", 32)
	w.anchors = append(w.anchors, kind)
	return "7:" + a, nil
}

// propose makes a branch with one change, like `govcode run` does.
func (w *world) propose(t *testing.T, file, content string) *Proposal {
	t.Helper()
	id := NewID()
	br := BranchFor(id)
	base, _ := w.repo.RevParse("refs/heads/main")
	wt := filepath.Join(t.TempDir(), "wt")
	if err := w.repo.AddWorktree(wt, br, base); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(wt, file), []byte(content), 0o644)
	head, err := gitx.CommitAll(wt, "change", gitx.Author{Name: "alice", Email: "a@x"}, gitx.Author{Name: "govcode", Email: "g@x"})
	if err != nil {
		t.Fatal(err)
	}
	w.repo.RemoveWorktree(wt)
	diff, _ := w.repo.Diff(base, head)
	p := &Proposal{ID: id, Task: "fix " + file, Proposer: w.alice, Target: "main", Branch: br, Base: base, Head: head,
		DiffSHA256: DiffHash(diff), Files: []string{file}, Status: StatusReady, Model: "test"}
	if err := w.store.Save(p, diff, w.aliceS); err != nil {
		t.Fatal(err)
	}
	loaded, err := w.store.Load(id, w.kr)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

var rules = Rules{TwoPersonRule: true, Approvers: []string{"bob"}, Classification: "TEST"}

func TestSelfApprovalRefused(t *testing.T) {
	w := setup(t)
	p := w.propose(t, "a.c", "int a = 2;\n")
	_, err := w.store.Approve(w.repo, Rules{TwoPersonRule: true, Approvers: []string{"bob", w.alice.Username}}, p, w.alice, w.aliceS, "", w.anchor, nil)
	if !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	if len(w.anchors) != 0 {
		t.Fatal("audit anchor written for a refused approval")
	}
}

func TestNonApproverRefused(t *testing.T) {
	w := setup(t)
	p := w.propose(t, "a.c", "int a = 2;\n")
	carol := identity.User{UID: 9999, Username: "carol"}
	if _, err := w.store.Approve(w.repo, rules, p, carol, w.bobS, "", w.anchor, nil); err == nil || !strings.Contains(err.Error(), "not an approver") {
		t.Fatalf("carol: %v", err)
	}
}

func TestApproveLandsWithProvenance(t *testing.T) {
	w := setup(t)
	p := w.propose(t, "a.c", "int a = 2;\n")
	before, _ := w.repo.RevParse("refs/heads/main")
	res, err := w.store.Approve(w.repo, rules, p, w.bob, w.bobS, "LGTM", w.anchor, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := w.repo.RevParse("refs/heads/main")
	if after != res.Commit || before == after {
		t.Fatal("main not updated")
	}
	msg := git(t, w.repo.Root, "log", "-1", "--format=%B", "main")
	for _, want := range []string{"Govcode-Proposal: " + p.ID, "Govcode-Approved-By: bob", "Govcode-Audit-Anchor: 7:", "Govcode-Diff-SHA256: " + p.DiffSHA256, "Reviewer: LGTM"} {
		if !strings.Contains(msg, want) {
			t.Errorf("commit message missing %q:\n%s", want, msg)
		}
	}
	if got := git(t, w.repo.Root, "log", "-1", "--format=%an|%cn", "main"); got != w.alice.Username+"|bob" {
		t.Errorf("author|committer = %s", got)
	}
	if got := git(t, w.repo.Root, "show", "main:a.c"); got != "int a = 2;" {
		t.Errorf("content %q", got)
	}
	anc, _ := Anchors(w.repo, []string{"main"})
	if anc[7] != strings.Repeat("ab", 32) {
		t.Errorf("anchor not recoverable from history: %v", anc)
	}
	if w.anchors[0] != "approval" {
		t.Error("approval not recorded before landing")
	}
	// decided exactly once
	p2, _ := w.store.Load(p.ID, w.kr)
	if _, err := w.store.Approve(w.repo, rules, p2, w.bob, w.bobS, "", w.anchor, nil); err == nil {
		t.Fatal("approved twice")
	}
}

func TestTamperedBranchRefused(t *testing.T) {
	w := setup(t)
	p := w.propose(t, "a.c", "int a = 2;\n")
	// proposer sneaks another commit onto the branch after signing
	wt := filepath.Join(t.TempDir(), "wt")
	git(t, w.repo.Root, "worktree", "add", "-q", wt, p.Branch)
	os.WriteFile(filepath.Join(wt, "b.c"), []byte("int b = 666;\n"), 0o644)
	git(t, wt, "commit", "-qam", "sneaky")
	if _, err := w.store.Approve(w.repo, rules, p, w.bob, w.bobS, "", w.anchor, nil); err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("tampered branch: %v", err)
	}
}

func TestForgedProposalRecordRefused(t *testing.T) {
	w := setup(t)
	p := w.propose(t, "a.c", "int a = 2;\n")
	path := filepath.Join(w.store.Dir, p.ID, "proposal.json")
	os.Chmod(path, 0o644)
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), `"status": "ready"`, `"status": "ready" `, 1)), 0o644)
	if _, err := w.store.Load(p.ID, w.kr); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("forged record loaded: %v", err)
	}
}

func TestOnlyReadyProposalsLand(t *testing.T) {
	w := setup(t)
	p := w.propose(t, "a.c", "int a = 2;\n")
	p.Status = StatusTestsFailed
	if _, err := w.store.Approve(w.repo, rules, p, w.bob, w.bobS, "", w.anchor, nil); err == nil {
		t.Fatal("tests_failed proposal approved")
	}
}

func TestTargetMovedCleanMergeAndConflict(t *testing.T) {
	w := setup(t)
	p1 := w.propose(t, "a.c", "int a = 2;\n")
	p2 := w.propose(t, "b.c", "int b = 2;\n") // independent file
	p3 := w.propose(t, "a.c", "int a = 3;\n") // conflicts with p1
	if _, err := w.store.Approve(w.repo, rules, p1, w.bob, w.bobS, "", w.anchor, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.store.Approve(w.repo, rules, p2, w.bob, w.bobS, "", w.anchor, nil); err != nil {
		t.Fatalf("clean merge onto moved target failed: %v", err)
	}
	if got := git(t, w.repo.Root, "show", "main:a.c") + git(t, w.repo.Root, "show", "main:b.c"); got != "int a = 2;int b = 2;" {
		t.Errorf("merged content %q", got)
	}
	if _, err := w.store.Approve(w.repo, rules, p3, w.bob, w.bobS, "", w.anchor, nil); err == nil || !strings.Contains(err.Error(), "no longer merges") {
		t.Fatalf("conflicting proposal: %v", err)
	}
}

func TestRejectAndWithdraw(t *testing.T) {
	w := setup(t)
	p := w.propose(t, "a.c", "int a = 2;\n")
	if err := w.store.Reject(rules, p, w.alice, w.aliceS, "withdrawn", w.anchor); err != nil {
		t.Fatalf("proposer withdraw: %v", err)
	}
	p, _ = w.store.Load(p.ID, w.kr)
	if p.Status != StatusRejected {
		t.Fatal("status not rejected")
	}
	if _, err := w.store.Approve(w.repo, rules, p, w.bob, w.bobS, "", w.anchor, nil); err == nil {
		t.Fatal("rejected proposal approved")
	}
}

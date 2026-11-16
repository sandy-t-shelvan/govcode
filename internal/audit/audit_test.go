package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

type fixture struct {
	log  *Log
	kr   *keyring.Keyring
	me   identity.User
	sess *Session
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	me, err := identity.Current()
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := sign.NewSigner(priv)
	krDir := filepath.Join(dir, "keys")
	if _, err := keyring.Register(krDir, me, s.Public()); err != nil {
		t.Fatal(err)
	}
	kr, err := keyring.Load(krDir)
	if err != nil || len(kr.Skipped) > 0 {
		t.Fatalf("keyring: %v %v", err, kr.Skipped)
	}
	l := &Log{Dir: filepath.Join(dir, "audit"), Classification: "UNCLASSIFIED//TEST", Repo: "repo"}
	if err := l.Open(); err != nil {
		t.Fatal(err)
	}
	return &fixture{l, kr, me, &Session{Log: l, Signer: s, Actor: me, ID: "s1"}}
}

func (f *fixture) write(t *testing.T, n int) {
	for i := 0; i < n; i++ {
		if err := f.sess.Record("tool_result", map[string]any{"tool": "edit_file", "args": map[string]any{"path": "a.c"}, "output": strings.Repeat("x", i)}); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) verify(t *testing.T, anchors map[uint64]string) *Report {
	r, err := f.log.Verify(f.kr, anchors, true)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCleanChainVerifies(t *testing.T) {
	f := setup(t)
	f.write(t, 20)
	r := f.verify(t, nil)
	if !r.OK() || r.Entries != 20 || r.Head.Seq != 19 {
		t.Fatalf("%+v", r)
	}
	if r.Head.Classification != "UNCLASSIFIED//TEST" || r.Head.Summary["path"] != "a.c" {
		t.Errorf("head %+v", r.Head)
	}
}

func lines(t *testing.T, f *fixture) [][]byte {
	b, _ := os.ReadFile(f.log.LogPath())
	return bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
}

func rewrite(t *testing.T, f *fixture, ls [][]byte) {
	os.WriteFile(f.log.LogPath(), append(bytes.Join(ls, []byte("\n")), '\n'), 0o660)
}

func TestModifiedEntryDetected(t *testing.T) {
	f := setup(t)
	f.write(t, 5)
	ls := lines(t, f)
	ls[2] = bytes.Replace(ls[2], []byte(`"path":"a.c"`), []byte(`"path":"b.c"`), 1)
	rewrite(t, f, ls)
	r := f.verify(t, nil)
	if r.OK() || !strings.Contains(strings.Join(r.Problems, "\n"), "seq 2: content does not match") {
		t.Fatalf("tamper not detected: %v", r.Problems)
	}
}

func TestDeletedEntryDetected(t *testing.T) {
	f := setup(t)
	f.write(t, 5)
	ls := lines(t, f)
	rewrite(t, f, append(ls[:2], ls[3:]...))
	r := f.verify(t, nil)
	if r.OK() {
		t.Fatal("deletion not detected")
	}
}

func TestTailTruncationNeedsAnchor(t *testing.T) {
	f := setup(t)
	f.write(t, 5)
	head, _ := f.log.Head()
	anchors := map[uint64]string{head.Seq: head.Hash}
	ls := lines(t, f)
	rewrite(t, f, ls[:3])
	if r := f.verify(t, nil); !r.OK() {
		t.Fatalf("truncated prefix should be self-consistent: %v", r.Problems)
	}
	r := f.verify(t, anchors)
	if r.OK() || !strings.Contains(r.Problems[0], "missing from the log") {
		t.Fatalf("truncation not caught by anchor: %v", r.Problems)
	}
}

func TestImpersonationDetected(t *testing.T) {
	f := setup(t)
	f.write(t, 1)
	fake := f.me
	fake.Username, fake.UID = "someone-else", 4242
	s2 := &Session{Log: f.log, Signer: f.sess.Signer, Actor: fake, ID: "s2"}
	s2.Record("approval", map[string]any{"decision": "approve"})
	r := f.verify(t, nil)
	if r.OK() || !strings.Contains(strings.Join(r.Problems, "\n"), "impersonation") {
		t.Fatalf("impersonation not detected: %v", r.Problems)
	}
}

func TestUnknownKeyDetected(t *testing.T) {
	f := setup(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &Session{Log: f.log, Signer: sign.NewSigner(priv), Actor: f.me, ID: "x"}
	s.Record("task", map[string]any{"x": 1})
	r := f.verify(t, nil)
	if r.OK() || !strings.Contains(r.Problems[0], "not in the keyring") {
		t.Fatalf("%v", r.Problems)
	}
}

func TestObjectTamperDetected(t *testing.T) {
	f := setup(t)
	f.write(t, 1)
	head, _ := f.log.Head()
	id := head.Objects["payload"]
	p := filepath.Join(f.log.Dir, "objects", id[:2], id[2:])
	os.Chmod(p, 0o644)
	os.WriteFile(p, []byte(`{"tool":"edit_file","output":"forged"}`), 0o644)
	r := f.verify(t, nil)
	if r.OK() || !strings.Contains(r.Problems[0], "corrupt") {
		t.Fatalf("%v", r.Problems)
	}
}

func TestConcurrentAppend(t *testing.T) {
	f := setup(t)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			// separate Session per goroutine, like separate processes
			s := &Session{Log: f.log, Signer: f.sess.Signer, Actor: f.me, ID: "g"}
			for i := 0; i < 25; i++ {
				s.Record("tick", map[string]any{"g": g, "i": i})
			}
		}(g)
	}
	wg.Wait()
	r := f.verify(t, nil)
	if !r.OK() || r.Entries != 100 {
		t.Fatalf("entries=%d problems=%v", r.Entries, r.Problems)
	}
}

func TestKeyringOwnershipBinding(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to chown")
	}
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := filepath.Join(dir, "root.pub")
	sign.WritePublic(p, priv.Public().(ed25519.PublicKey))
	// a key claiming to be root's but owned by nobody must be rejected
	if err := exec.Command("chown", "nobody", p).Run(); err != nil {
		t.Skip("chown unavailable")
	}
	kr, _ := keyring.Load(dir)
	if len(kr.ForUser("root")) != 0 || len(kr.Skipped) != 1 {
		t.Fatalf("foreign-owned key accepted: %v", kr.Skipped)
	}
}

func TestAppendOnlyFlag(t *testing.T) {
	f := setup(t)
	ok, err := AppendOnlyFlag(f.log.LogPath())
	if err != nil {
		t.Skipf("filesystem has no inode flags: %v", err)
	}
	if ok {
		t.Fatal("fresh file reported append-only")
	}
	if exec.Command("chattr", "+a", f.log.LogPath()).Run() != nil {
		t.Skip("chattr not permitted here")
	}
	defer exec.Command("chattr", "-a", f.log.LogPath()).Run()
	if ok, _ := AppendOnlyFlag(f.log.LogPath()); !ok {
		t.Fatal("chattr +a not detected")
	}
	f.write(t, 2) // appends still work
	if err := os.WriteFile(f.log.LogPath(), []byte("rewritten\n"), 0o660); err == nil {
		t.Fatal("append-only file was rewritten")
	}
	if r := f.verify(t, nil); !r.OK() {
		t.Fatal(r.Problems)
	}
}

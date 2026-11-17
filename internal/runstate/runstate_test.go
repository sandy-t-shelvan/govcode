package runstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

func TestSaveLoadOwnershipAndLock(t *testing.T) {
	dir := t.TempDir()
	u, _ := identity.Current()
	base := filepath.Join(dir, "me")
	pub, _ := sign.GenerateKeyFiles(base)
	s, _ := sign.LoadSigner(base + ".key")
	keyring.Register(filepath.Join(dir, "keys"), u, pub)
	kr, _ := keyring.Load(filepath.Join(dir, "keys"))
	st := Store{Dir: filepath.Join(dir, "runs")}

	in := &State{ID: "p1", Proposer: u, Task: "t", Messages: []llm.Message{{Role: "system", Content: "s"}, {Role: "user", Content: "u"}},
		CheckpointMsgs: map[int]int{1: 2}, Status: StatusInterrupted}
	if err := st.Save(in, s); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load("p1", kr, u)
	if err != nil || got.Task != "t" || len(got.Messages) != 2 || got.CheckpointMsgs[1] != 2 {
		t.Fatalf("%v %+v", err, got)
	}
	other := u
	other.UID++
	if _, err := st.Load("p1", kr, other); err == nil || !strings.Contains(err.Error(), "only its proposer") {
		t.Errorf("another uid loaded the run: %v", err)
	}
	if _, err := st.Load("../x", kr, u); err == nil {
		t.Error("path traversal id accepted")
	}

	unlock, err := st.Lock("p1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Lock("p1"); err == nil {
		t.Error("second lock on an active run succeeded")
	}
	unlock()
	u2, err := st.Lock("p1")
	if err != nil {
		t.Fatal("lock not released")
	}
	u2()

	if ls, _ := st.List(); len(ls) != 1 || ls[0].Checkpoints != 1 {
		t.Errorf("list %+v", ls)
	}
	st.DiscardIfEmpty("p1")
	if _, err := os.Stat(filepath.Join(st.Dir, "p1", "state.json")); err != nil {
		t.Error("DiscardIfEmpty removed a saved run")
	}
	st.Delete("p1")
	if ls, _ := st.List(); len(ls) != 0 {
		t.Error("delete left the run")
	}
}

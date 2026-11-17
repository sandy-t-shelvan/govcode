package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

var h64 = strings.Repeat("ab", 32)

func prop() *proposal.Proposal {
	return &proposal.Proposal{ID: "p1", Classification: "SECRET", Target: "main", Base: "b", Head: "h",
		TaskSHA256: "t", DiffSHA256: "d", Files: []string{"a.c"}, AuditSession: "p1", AuditTaskSeq: 3, AuditTaskHash: h64,
		Created: "2026-11-17T00:00:00Z", Proposer: identity.User{Username: "alice", UID: 1001},
		ModelInfo: &proposal.ModelInfo{ID: "devstral-small-24b", Origins: []string{"FR"}, NumCtx: 32768},
		Checks:    []proposal.Check{{Name: "tests", Result: "pass"}, {Name: "secret_scan", Result: "pass"}}}
}

func setup(t *testing.T) (Store, *keyring.Keyring, sign.Signer, identity.User) {
	t.Helper()
	dir := t.TempDir()
	u, _ := identity.Current()
	base := filepath.Join(dir, "me")
	pub, err := sign.GenerateKeyFiles(base)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := sign.LoadSigner(base + ".key")
	if _, err := keyring.Register(filepath.Join(dir, "keys"), u, pub); err != nil {
		t.Fatal(err)
	}
	kr, err := keyring.Load(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	return Store{Dir: filepath.Join(dir, "evidence")}, kr, s, u
}

func TestBuildSaveLoad(t *testing.T) {
	st, kr, s, u := setup(t)
	if _, err := Build(prop(), u, s.KeyID(), "tip", "bad", false, time.Now()); err == nil {
		t.Error("bad anchor accepted")
	}
	np := prop()
	np.ModelInfo = nil
	if _, err := Build(np, u, s.KeyID(), "tip", "9:"+h64, false, time.Now()); err == nil {
		t.Error("record without model info built")
	}
	r, err := Build(prop(), u, s.KeyID(), "tip", "9:"+h64, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.Checks[0].Name != "secret_scan" || r.Audit.FirstSeq != 3 || r.Audit.LastSeq != 9 || !r.ReviewNotes {
		t.Fatalf("%+v", r)
	}
	sum, err := st.Save(r, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Save(r, s); err == nil {
		t.Error("second record for the same proposal was written")
	}
	v, err := st.Load("p1", kr, sum)
	if err != nil || v.SHA256 != sum || v.Record.Model.ID != "devstral-small-24b" {
		t.Fatalf("load: %v %+v", err, v)
	}
	if _, err := st.Load("p1", kr, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "trailer says") {
		t.Errorf("trailer mismatch accepted: %v", err)
	}
	ids, _ := st.List()
	if strings.Join(ids, ",") != "p1" {
		t.Errorf("list %v", ids)
	}

	// Tampering with the record breaks the approver's signature.
	p := filepath.Join(st.Dir, "p1.json")
	data, _ := os.ReadFile(p)
	os.Chmod(p, 0o644)
	os.WriteFile(p, []byte(strings.Replace(string(data), "devstral-small-24b", "qwen3-coder-30b-a3b", 1)), 0o644)
	if _, err := st.Load("p1", kr, ""); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("tampered record accepted: %v", err)
	}
}

func TestRecordSignedByOtherKeyIsRefused(t *testing.T) {
	st, kr, _, u := setup(t)
	other := filepath.Join(t.TempDir(), "other")
	sign.GenerateKeyFiles(other)
	os2, _ := sign.LoadSigner(other + ".key")
	// The impostor key is not in the keyring for this user.
	r, _ := Build(prop(), u, os2.KeyID(), "tip", "9:"+h64, false, time.Now())
	if _, err := st.Save(r, os2); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load("p1", kr, ""); err == nil {
		t.Error("record signed by a key outside the keyring accepted")
	}
}

func TestCheckAudit(t *testing.T) {
	r := &Record{Audit: AuditRange{FirstSeq: 3, FirstHash: h64, LastSeq: 9, LastHash: h64}}
	log := map[uint64]string{3: h64, 9: h64}
	at := func(s uint64) (string, bool) { h, ok := log[s]; return h, ok }
	if err := CheckAudit(r, at); err != nil {
		t.Fatal(err)
	}
	log[9] = strings.Repeat("cd", 32)
	if err := CheckAudit(r, at); err == nil {
		t.Error("hash mismatch accepted")
	}
	delete(log, 9)
	if err := CheckAudit(r, at); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("missing entry accepted: %v", err)
	}
}

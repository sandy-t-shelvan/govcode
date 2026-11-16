package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, p *Policy) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "policy.json")
	b, _ := json.Marshal(p)
	os.WriteFile(f, b, 0o644)
	return f
}

func TestDevPolicyLoadsInWarnMode(t *testing.T) {
	repo := t.TempDir()
	p := Dev(repo, filepath.Join(t.TempDir(), "state"), "alice")
	if _, _, err := Load(write(t, p)); err != nil {
		t.Fatal(err)
	}
}

func TestRejections(t *testing.T) {
	repo := t.TempDir()
	cases := map[string]func(*Policy){
		"non-loopback":      func(p *Policy) { p.Model.Endpoint = "http://10.0.0.8:11434" },
		"num_ctx":           func(p *Policy) { p.Model.NumCtx = 0 },
		"state in repo":     func(p *Policy) { p.StateDir = filepath.Join(repo, ".govcode") },
		"sensitive no 2PR":  func(p *Policy) { p.Sensitive = true },
		"2PR no approvers":  func(p *Policy) { p.TwoPersonRule = true; p.Approvers = nil },
		"strict w/o trust":  func(p *Policy) { p.Trust.Enforce = "strict" },
		"no classification": func(p *Policy) { p.Classification = "" },
		"strict sandbox off": func(p *Policy) {
			p.Trust = Trust{Enforce: "strict", ReleaseKeys: []string{"k"}, ReleaseManifest: "m", ModelKeys: []string{"k"}}
			p.Model.Lock = "l"
			p.Sandbox.Mode = "off"
		},
	}
	for name, mut := range cases {
		p := Dev(repo, "/var/lib/govcode/x", "alice")
		mut(p)
		if _, _, err := Load(write(t, p)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStrictRequiresRootOwnedPolicy(t *testing.T) {
	p := Dev(t.TempDir(), "/var/lib/govcode/x", "alice")
	p.Trust = Trust{Enforce: "strict", ReleaseKeys: []string{"k"}, ReleaseManifest: "m", ModelKeys: []string{"k"}}
	p.Model.Lock = "l"
	f := write(t, p)
	os.Chmod(f, 0o666)
	if _, _, err := Load(f); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("world-writable strict policy accepted: %v", err)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	f := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(f, []byte(`{"schema":"govcode.policy/v1","aprovers":["eve"]}`), 0o644)
	if _, _, err := Load(f); err == nil {
		t.Fatal("typo'd field accepted silently")
	}
}

func TestCheckRepo(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	p := &Policy{RepoRoot: a}
	if p.CheckRepo(a) != nil || p.CheckRepo(b) == nil {
		t.Fatal("repo restriction wrong")
	}
}

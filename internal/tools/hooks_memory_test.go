package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/permissions"
)

func TestPostEditHookFailureReported(t *testing.T) {
	e := repo(t, map[string]string{"a.c": "int x = 1;\n"})
	// a site check that rejects the literal 2 and echoes the changed file
	e.PostEditHooks = []string{`echo "checking $GOVCODE_CHANGED_FILES at $GOVCODE_HOOK"; ! grep -n "= 2" $GOVCODE_CHANGED_FILES`}
	evs := collect(e)
	out, err := call(t, NewSet(e), "edit_file", map[string]any{"path": "a.c", "old_text": "= 1", "new_text": "= 2"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Site check") || !strings.Contains(out, "checking a.c at post_edit") || e.HookFailures != 1 {
		t.Fatalf("hook failure not reported to model: %q", out)
	}
	out, _ = call(t, NewSet(e), "edit_file", map[string]any{"path": "a.c", "old_text": "= 2", "new_text": "= 3"})
	if strings.Contains(out, "Site check") {
		t.Fatalf("passing hook reported as failure: %q", out)
	}
	n := 0
	for _, ev := range evs() {
		if ev.Kind == "hook" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("hook events %d", n)
	}
}

func TestHookRunsInSandbox(t *testing.T) {
	e := repo(t, map[string]string{"a.c": "x\n"})
	if !e.Runner.Sandboxed() {
		skipNoBwrap(t)
	}
	rep := e.RunHooks(context.Background(), "pre_proposal", []string{"getent hosts example.com"}, nil)
	if rep == "" {
		t.Fatal("hook resolved DNS: sandbox not applied to hooks")
	}
}

func TestSubdirectoryMemoryLoadedOnce(t *testing.T) {
	e := repo(t, map[string]string{
		"GOVCODE.md":         "root rules",
		"src/GOVCODE.md":     "Use K&R braces in src.",
		"src/pay/GOVCODE.md": "Amounts are PIC 9(7)V99.",
		"src/pay/CALC.cbl":   "       PROCEDURE DIVISION.\n",
		"src/pay/OTHER.cbl":  "       PROCEDURE DIVISION.\n",
		"lib/x.c":            "int x;\n",
		"secret/GOVCODE.md":  "/* TOP SECRET//SI */ rules",
		"secret/y.c":         "int y;\n",
	})
	e.MemoryBudget = 4096
	e.MemoryLoaded = map[string]bool{".": true} // root is in the task prompt
	s := NewSet(e)
	out, _ := call(t, s, "read_file", map[string]any{"path": "src/pay/CALC.cbl"})
	if !strings.Contains(out, "K&R braces") || !strings.Contains(out, "PIC 9(7)V99") || strings.Contains(out, "root rules") {
		t.Fatalf("memory not loaded as expected:\n%s", out)
	}
	out, _ = call(t, s, "read_file", map[string]any{"path": "src/pay/OTHER.cbl"})
	if strings.Contains(out, "Conventions from") {
		t.Fatalf("memory loaded twice:\n%s", out)
	}
	if out, _ := call(t, s, "read_file", map[string]any{"path": "lib/x.c"}); strings.Contains(out, "Conventions") {
		t.Fatal("phantom memory")
	}
	e.MaxLevel = 2 // SECRET
	if out, _ := call(t, s, "read_file", map[string]any{"path": "secret/y.c"}); strings.Contains(out, "rules") {
		t.Fatalf("over-classified memory file reached the model:\n%s", out)
	}
}

// GOVCODE.md is shown to the model, so read_file rules and the jail apply
// to it. A denied conventions file, a symlink to a denied file, a symlink
// to .git, and a symlink out of the repository must not be loaded.
func TestMemoryHonorsReadRulesAndJail(t *testing.T) {
	e := repo(t, map[string]string{
		"src/a.c":        "int x;\n",
		"src/GOVCODE.md": "hidden conventions",
		"src/notes.txt":  "visible convention",
		"keys/creds.h":   "SECRET-KEY-MATERIAL",
		"ok/main.c":      "int y;\n",
	})
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("OUTSIDE-SECRET-MATERIAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := func(dir, target string) {
		t.Helper()
		p := filepath.Join(e.Jail.Root, dir, "GOVCODE.md")
		os.Remove(p)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	e.Perms, _ = permissions.Parse(nil, nil, []string{"read_file(src/GOVCODE.md)", "read_file(keys/**)"})
	e.MemoryBudget = 4096
	e.MemoryLoaded = map[string]bool{".": true}
	evs := collect(e)

	out, err := call(t, NewSet(e), "read_file", map[string]any{"path": "src/a.c"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "hidden conventions") {
		t.Fatalf("denied conventions file reached the model:\n%s", out)
	}
	if !strings.Contains(out, "int x;") {
		t.Fatalf("allowed file was not read:\n%s", out)
	}

	link("ok", "../keys/creds.h")
	out, err = call(t, NewSet(e), "read_file", map[string]any{"path": "ok/main.c"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "SECRET-KEY-MATERIAL") {
		t.Fatalf("symlink to a denied file reached the model:\n%s", out)
	}

	e.MemoryLoaded = map[string]bool{".": true}
	link("ok", "../.git/config")
	out, err = call(t, NewSet(e), "read_file", map[string]any{"path": "ok/main.c"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "repositoryformatversion") {
		t.Fatalf("symlink to .git reached the model:\n%s", out)
	}

	e.MemoryLoaded = map[string]bool{".": true}
	link("ok", outside)
	out, err = call(t, NewSet(e), "read_file", map[string]any{"path": "ok/main.c"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "OUTSIDE-SECRET-MATERIAL") {
		t.Fatalf("symlink out of the repository reached the model:\n%s", out)
	}

	// A directory symlink must be judged by the directory it points at.
	// keys/GOVCODE.md is the protected text; keys/main.c is ordinary so a
	// read through the link still returns the source file.
	if err := os.WriteFile(filepath.Join(e.Jail.Root, "keys", "GOVCODE.md"), []byte("DIRECTORY-LINK-SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.Jail.Root, "keys", "main.c"), []byte("int z;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../keys", filepath.Join(e.Jail.Root, "src", "via")); err != nil {
		t.Fatal(err)
	}
	e.MemoryLoaded = map[string]bool{".": true}
	out, err = call(t, NewSet(e), "read_file", map[string]any{"path": "src/via/main.c"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "DIRECTORY-LINK-SECRET") {
		t.Fatalf("directory symlink loaded a denied conventions file:\n%s", out)
	}

	// A symlink to an allowed file is still loaded, at the target's bytes.
	e.MemoryLoaded = map[string]bool{".": true}
	link("ok", "../src/notes.txt")
	out, err = call(t, NewSet(e), "read_file", map[string]any{"path": "ok/main.c"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "visible convention") {
		t.Fatalf("symlink to an allowed file was dropped:\n%s", out)
	}

	// The root conventions file is the same check the task prompt uses.
	os.Remove(filepath.Join(e.Jail.Root, "GOVCODE.md"))
	if err := os.Symlink(outside, filepath.Join(e.Jail.Root, "GOVCODE.md")); err != nil {
		t.Fatal(err)
	}
	if data, err := e.ReadForModel("GOVCODE.md"); err == nil && strings.Contains(string(data), "OUTSIDE-SECRET-MATERIAL") {
		t.Fatalf("root symlink returned outside bytes: %q", data)
	}
	os.Remove(filepath.Join(e.Jail.Root, "GOVCODE.md"))
	if err := os.Symlink("keys/creds.h", filepath.Join(e.Jail.Root, "GOVCODE.md")); err != nil {
		t.Fatal(err)
	}
	if data, err := e.ReadForModel("GOVCODE.md"); err == nil && strings.Contains(string(data), "SECRET-KEY-MATERIAL") {
		t.Fatalf("root symlink to a denied file returned its bytes: %q", data)
	}

	// An ask rule with nobody to ask is a denial, not a silent allow.
	e2 := repo(t, map[string]string{"src/a.c": "int x;\n", "src/GOVCODE.md": "ask me first"})
	e2.Perms, _ = permissions.Parse(nil, []string{"read_file(**/GOVCODE.md)"}, nil)
	e2.MemoryBudget = 4096
	e2.MemoryLoaded = map[string]bool{".": true}
	out, err = call(t, NewSet(e2), "read_file", map[string]any{"path": "src/a.c"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ask me first") {
		t.Fatalf("ask rule with no approver loaded conventions:\n%s", out)
	}
	ap := &approveAll{}
	e2.Approver = ap
	e2.MemoryLoaded = map[string]bool{".": true}
	out, err = call(t, NewSet(e2), "read_file", map[string]any{"path": "src/a.c"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ask me first") || len(ap.asked) != 1 || ap.asked[0] != "read_file(src/GOVCODE.md)" {
		t.Fatalf("approved conventions not loaded, asked %v:\n%s", ap.asked, out)
	}

	// Refusal is audited, and the audit record does not carry the bytes.
	var refused bool
	for _, ev := range evs() {
		if ev.Kind != "memory_refused" {
			continue
		}
		refused = true
		b := ev.Data.(map[string]any)
		blob := b["path"].(string) + b["error"].(string)
		if strings.Contains(blob, "SECRET-KEY-MATERIAL") || strings.Contains(blob, "OUTSIDE-SECRET-MATERIAL") || strings.Contains(blob, "hidden conventions") {
			t.Fatalf("memory refusal carries file content: %v", b)
		}
	}
	if !refused {
		t.Fatal("no memory_refused event")
	}
}

func TestMemoryBudget(t *testing.T) {
	e := repo(t, map[string]string{"a/GOVCODE.md": strings.Repeat("x", 100), "a/b/GOVCODE.md": "never", "a/b/f.c": "int f;\n"})
	e.MemoryBudget = 50
	out, _ := call(t, NewSet(e), "read_file", map[string]any{"path": "a/b/f.c"})
	if strings.Count(out, "x") > 50 || strings.Contains(out, "never") {
		t.Fatalf("budget exceeded:\n%s", out)
	}
}

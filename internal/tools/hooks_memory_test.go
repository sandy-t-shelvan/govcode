package tools

import (
	"context"
	"strings"
	"testing"
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

func TestMemoryBudget(t *testing.T) {
	e := repo(t, map[string]string{"a/GOVCODE.md": strings.Repeat("x", 100), "a/b/GOVCODE.md": "never", "a/b/f.c": "int f;\n"})
	e.MemoryBudget = 50
	out, _ := call(t, NewSet(e), "read_file", map[string]any{"path": "a/b/f.c"})
	if strings.Count(out, "x") > 50 || strings.Contains(out, "never") {
		t.Fatalf("budget exceeded:\n%s", out)
	}
}

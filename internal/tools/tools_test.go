package tools

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func repo(t *testing.T, files map[string]string) *Env {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), []byte(c), 0o644)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}, {"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	j, _ := NewJail(dir)
	r, _ := NewRunner(SandboxBestEffort, j.Root, nil, nil)
	return &Env{Jail: j, Runner: r, Changed: map[string]bool{}}
}

func call(t *testing.T, s *Set, name string, args map[string]any) (string, error) {
	t.Helper()
	tool, ok := s.Get(name)
	if !ok {
		t.Fatalf("no tool %s", name)
	}
	return tool.Run(context.Background(), args)
}

func TestJail(t *testing.T) {
	e := repo(t, map[string]string{"a.c": "x"})
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(e.Jail.Root, "escape"))
	for _, bad := range []string{"../x", "/etc/passwd", ".git/config", "src/../../x", "escape/secret", ".govcode/policy.json", "sub/.git/hooks/pre-commit"} {
		if _, err := e.Jail.Resolve(bad); err == nil {
			t.Errorf("Resolve(%q) allowed", bad)
		}
	}
	for _, ok := range []string{"a.c", "new/dir/file.c", filepath.Join(e.Jail.Root, "a.c"), "./a.c"} {
		if _, err := e.Jail.Resolve(ok); err != nil {
			t.Errorf("Resolve(%q): %v", ok, err)
		}
	}
}

const cobol = "       IDENTIFICATION DIVISION.\n       PROGRAM-ID. PAYCALC.\n       DATA DIVISION.\n       WORKING-STORAGE SECTION.\n       01  WS-RATE        PIC 9V99 VALUE 0.05.\n       PROCEDURE DIVISION.\n       MAIN-PARA.\n           DISPLAY WS-RATE.\n           STOP RUN.\n"

func TestEditPreservesCobolColumns(t *testing.T) {
	e := repo(t, map[string]string{"PAY.cbl": cobol})
	s := NewSet(e)
	_, err := call(t, s, "edit_file", map[string]any{"path": "PAY.cbl",
		"old_text": "       01  WS-RATE        PIC 9V99 VALUE 0.05.",
		"new_text": "       01  WS-RATE        PIC 9V9999 VALUE 0.0525."})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(e.Jail.Root, "PAY.cbl"))
	if !strings.Contains(string(got), "\n       01  WS-RATE        PIC 9V9999 VALUE 0.0525.\n") {
		t.Fatalf("bad edit:\n%s", got)
	}
	if e.EditGen != 1 || !e.Changed["PAY.cbl"] {
		t.Error("edit not tracked")
	}
}

func TestEditWhitespaceNearMiss(t *testing.T) {
	e := repo(t, map[string]string{"PAY.cbl": cobol})
	_, err := call(t, NewSet(e), "edit_file", map[string]any{"path": "PAY.cbl",
		"old_text": "01 WS-RATE PIC 9V99 VALUE 0.05.", "new_text": "x"})
	if err == nil || !strings.Contains(err.Error(), "line(s) 5") {
		t.Fatalf("expected near-miss hint at line 5, got %v", err)
	}
}

func TestEditStripsLineNumbers(t *testing.T) {
	e := repo(t, map[string]string{"m.c": "int main(void) {\n    return 1;\n}\n"})
	out, err := call(t, NewSet(e), "edit_file", map[string]any{"path": "m.c", "old_text": "2|     return 1;", "new_text": "2|     return 0;"})
	if err != nil || !strings.Contains(out, "prefixes were removed") {
		t.Fatalf("%v %s", err, out)
	}
	got, _ := os.ReadFile(filepath.Join(e.Jail.Root, "m.c"))
	if !strings.Contains(string(got), "    return 0;") {
		t.Fatalf("got %s", got)
	}
}

func TestEditCRLF(t *testing.T) {
	e := repo(t, map[string]string{"w.c": "int a;\r\nint b;\r\n"})
	if _, err := call(t, NewSet(e), "edit_file", map[string]any{"path": "w.c", "old_text": "int a;\nint b;", "new_text": "int a;\nlong b;"}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(e.Jail.Root, "w.c"))
	if string(got) != "int a;\r\nlong b;\r\n" {
		t.Fatalf("CRLF not preserved: %q", got)
	}
}

func TestEditAmbiguous(t *testing.T) {
	e := repo(t, map[string]string{"d.c": "x = 1;\nx = 1;\n"})
	if _, err := call(t, NewSet(e), "edit_file", map[string]any{"path": "d.c", "old_text": "x = 1;", "new_text": "x = 2;"}); err == nil || !strings.Contains(err.Error(), "lines 1, 2") {
		t.Fatalf("want ambiguity error, got %v", err)
	}
}

func TestOutline(t *testing.T) {
	e := repo(t, map[string]string{
		"PAY.cbl": cobol,
		"nav.adb": "package body Nav is\n   procedure Update (X : in out Integer) is\n   begin\n      null;\n   end Update;\n   function Speed return Float is (1.0);\nend Nav;\n",
		"io.c":    "#define MAXBUF 512\nstatic int\nparse_line(char *s, int n)\n{\n  if (n) return 0;\n}\nstruct rec {\n int a;\n};\n",
	})
	s := NewSet(e)
	for path, want := range map[string][]string{
		"PAY.cbl": {"program-id PAYCALC", "section    WORKING-STORAGE", "paragraph  MAIN-PARA", "data       WS-RATE"},
		"nav.adb": {"package body Nav", "procedure  Update", "function   Speed"},
		"io.c":    {"macro      MAXBUF", "function   parse_line", "struct     rec"},
	} {
		out, err := call(t, s, "outline", map[string]any{"path": path})
		if err != nil {
			t.Fatal(err)
		}
		norm := strings.Join(strings.Fields(out), " ")
		for _, w := range want {
			if !strings.Contains(norm, strings.Join(strings.Fields(w), " ")) {
				t.Errorf("%s outline missing %q:\n%s", path, w, out)
			}
		}
		if strings.Contains(out, "DISPLAY") || strings.Contains(out, " if") {
			t.Errorf("%s outline has false positive:\n%s", path, out)
		}
	}
}

func TestSearchAndList(t *testing.T) {
	e := repo(t, map[string]string{"src/a.adb": "Speed := 0;\n", "src/b.c": "speed = 0;\n", "doc.txt": "Speed"})
	s := NewSet(e)
	out, _ := call(t, s, "search", map[string]any{"pattern": "speed", "ignore_case": true, "glob": "*.adb"})
	if !strings.Contains(out, "src/a.adb:1:") || strings.Contains(out, "b.c") {
		t.Fatalf("search: %s", out)
	}
	out, _ = call(t, s, "list_files", map[string]any{"pattern": "src/**/*.c"})
	if strings.TrimSpace(out) != "src/b.c" {
		t.Fatalf("list: %q", out)
	}
}

func TestFinishGate(t *testing.T) {
	e := repo(t, map[string]string{"Makefile": "test:\n\t@false\n", "a.c": "int x;\n"})
	e.TestCommand, e.RequireTest = "make test", true
	s := NewSet(e)
	call(t, s, "edit_file", map[string]any{"path": "a.c", "old_text": "int x;", "new_text": "int y;"})
	if _, err := call(t, s, "finish", map[string]any{"summary": "done"}); err == nil {
		t.Fatal("finish allowed without tests")
	}
	out, _ := call(t, s, "run_tests", nil)
	if !strings.Contains(out, "FAILED") {
		t.Fatalf("run_tests: %s", out)
	}
	if _, err := call(t, s, "finish", map[string]any{"summary": "done"}); err == nil {
		t.Fatal("finish allowed after failing tests")
	}
	os.WriteFile(filepath.Join(e.Jail.Root, "Makefile"), []byte("test:\n\t@true\n"), 0o644)
	call(t, s, "run_tests", nil)
	if _, err := call(t, s, "finish", map[string]any{"summary": "done"}); err != nil {
		t.Fatalf("finish refused after passing tests: %v", err)
	}
}

type denyAll struct{ asked []string }

func (d *denyAll) Approve(c string) (bool, string) {
	d.asked = append(d.asked, c)
	return false, "tester"
}

func TestAllowlistCannotBeChained(t *testing.T) {
	e := repo(t, map[string]string{"a": "x"})
	d := &denyAll{}
	e.Allowlist, e.Approver = []string{"make", "gnatmake"}, d
	s := NewSet(e)
	if out, err := call(t, s, "run_command", map[string]any{"command": "make --version"}); err != nil || !strings.Contains(out, "exit 0") {
		t.Fatalf("allowlisted command blocked: %v %s", err, out)
	}
	for _, c := range []string{"make; rm -rf /", "make && cat /etc/shadow", "make $(id)", "make `id`", "make | tee x", "makefoo", "rm -rf ."} {
		if _, err := call(t, s, "run_command", map[string]any{"command": c}); err == nil {
			t.Errorf("%q ran without approval", c)
		}
	}
	if len(d.asked) != 7 {
		t.Errorf("approver asked %d times, want 7", len(d.asked))
	}
}

func TestSandboxIsolation(t *testing.T) {
	e := repo(t, map[string]string{"a": "x"})
	if !e.Runner.Sandboxed() {
		skipNoBwrap(t)
	}
	home, _ := os.UserHomeDir()
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("TOPSECRET"), 0o644)
	cases := map[string]string{
		"cat " + secret: "TOPSECRET", // other dirs invisible
		"ls " + home:    "",          // home not mounted
		"ip -o link 2>/dev/null | wc -l; cat /sys/class/net/*/operstate 2>/dev/null; getent hosts example.com || echo nodns": "nodns",
	}
	for c, forbidden := range cases {
		r := e.Runner.Run(context.Background(), c, 10*time.Second)
		if forbidden != "" && forbidden != "nodns" && strings.Contains(r.Output, forbidden) {
			t.Errorf("sandbox leaked: %q -> %s", c, r.Output)
		}
		if forbidden == "nodns" && !strings.Contains(r.Output, "nodns") {
			t.Errorf("sandbox has network/DNS: %s", r.Output)
		}
	}
	r := e.Runner.Run(context.Background(), "echo hi > out.txt && cat out.txt", 10*time.Second)
	if r.ExitCode != 0 || !strings.Contains(r.Output, "hi") {
		t.Fatalf("worktree not writable: %+v", r)
	}
	r = e.Runner.Run(context.Background(), "touch /usr/x", 10*time.Second)
	if r.ExitCode == 0 {
		t.Error("/usr writable in sandbox")
	}
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	e := repo(t, map[string]string{"a": "x"})
	start := time.Now()
	r := e.Runner.Run(context.Background(), "sleep 30 & sleep 30; wait", time.Second)
	if !r.TimedOut || time.Since(start) > 10*time.Second {
		t.Fatalf("timeout not enforced: %+v after %s", r, time.Since(start))
	}
}

package analysis

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

type fakeRunner struct {
	cmds []string
	res  tools.ExecResult
}

func (f *fakeRunner) RunWith(_ context.Context, cmd string, _ time.Duration, extra []string) tools.ExecResult {
	f.cmds = append(f.cmds, cmd+" |"+strings.Join(extra, ";"))
	return f.res
}

func tree(t *testing.T, files ...string) string {
	dir := t.TempDir()
	for _, f := range files {
		p := filepath.Join(dir, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("x\n"), 0o644)
	}
	return dir
}

var cAn = Analyzer{Name: "cc", Extensions: []string{".c", ".H"}, Command: "cc-check -q", FailOn: `error:`, Finding: `(error|warning):`}

func TestCoverageAndExemptions(t *testing.T) {
	dir := tree(t, "a.c", "b.h", "docs/x.md", "LEDGER.cbl")
	f := &fakeRunner{}
	rep := Run(context.Background(), f, dir, []Analyzer{cAn}, []Tool{{Name: "cc"}}, []string{"docs/**"},
		[]string{"a.c", "b.h", "docs/x.md", "LEDGER.cbl", "deleted.c"}, time.Minute)
	if len(rep.Results) != 1 || strings.Join(rep.Results[0].Files, ",") != "a.c,b.h" {
		t.Fatalf("%+v", rep.Results)
	}
	if strings.Join(rep.Uncovered, ",") != "LEDGER.cbl" || strings.Join(rep.Exempt, ",") != "docs/x.md" {
		t.Fatalf("uncovered %v exempt %v", rep.Uncovered, rep.Exempt)
	}
	if rep.Passed() {
		t.Error("report with uncovered file passed")
	}
	if !strings.Contains(f.cmds[0], "cc-check -q 'a.c' 'b.h' |GOVCODE_FILES=a.c b.h") {
		t.Errorf("command %q", f.cmds[0])
	}
}

func TestFindingsAndFailures(t *testing.T) {
	dir := tree(t, "a.c")
	for name, tc := range map[string]struct {
		res              tools.ExecResult
		pass             bool
		finding, blocked int
	}{
		"clean":          {tools.ExecResult{}, true, 0, 0},
		"warnings only":  {tools.ExecResult{Output: "a.c:1: warning: x\na.c:2: warning: y"}, true, 2, 0},
		"error":          {tools.ExecResult{Output: "a.c:1: warning: x\na.c:2: error: y"}, false, 2, 1},
		"nonzero exit":   {tools.ExecResult{ExitCode: 2}, false, 0, 0},
		"timed out":      {tools.ExecResult{TimedOut: true}, false, 0, 0},
		"error but ok 0": {tools.ExecResult{Output: "error: z"}, false, 1, 1},
	} {
		rep := Run(context.Background(), &fakeRunner{res: tc.res}, dir, []Analyzer{cAn}, nil, nil, []string{"a.c"}, time.Minute)
		r := rep.Results[0]
		if r.Passed != tc.pass || r.Findings != tc.finding || r.Blocking != tc.blocked || rep.Passed() != tc.pass {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, a := range []Analyzer{
		{Name: "x", Command: "c"},
		{Name: "x", Command: "c", Extensions: []string{"c"}},
		{Name: "x", Command: "c", Extensions: []string{".c"}, FailOn: "("},
	} {
		if a.Validate() == nil {
			t.Errorf("%+v accepted", a)
		}
	}
	if err := cAn.Validate(); err != nil {
		t.Error(err)
	}
}

func TestResolve(t *testing.T) {
	tl, err := Resolve(Analyzer{Name: "t", Command: "true --anything", Extensions: []string{".c"}})
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(tl.Path) || len(tl.SHA256) != 64 || tl.Version == "" {
		t.Fatalf("%+v", tl)
	}
	if _, err := Resolve(Analyzer{Name: "m", Command: "no-such-analyzer-xyz"}); err == nil {
		t.Error("missing analyzer resolved")
	}
}

// Real analyzers over the eval fixtures: the shipped C and Ada code is clean,
// and a broken edit is a blocking finding. File names are passed safely.
func TestRealAnalyzersOnEvalFixtures(t *testing.T) {
	copyDir := func(src string) string {
		dst := t.TempDir()
		if out, err := exec.Command("cp", "-r", src+"/.", dst).CombinedOutput(); err != nil {
			t.Fatalf("%s", out)
		}
		return dst
	}
	cases := []struct {
		bin, fixture, file, breakWith string
		an                            Analyzer
	}{
		{"gcc", "01-c-buffer-overflow", "track.c", "int broken( {\n",
			Analyzer{Name: "gcc-syntax", Extensions: []string{".c", ".h"}, Command: "gcc -fsyntax-only -Wall -std=c89", FailOn: `error`}},
		{"gnatmake", "06-ada-constraint-error", "nav.adb", "procedure Broken is begin null end;\n",
			Analyzer{Name: "gnat-check", Extensions: []string{".adb", ".ads"}, Command: "gcc -c -gnatc -gnatwa", FailOn: `error`}},
	}
	for _, c := range cases {
		if _, err := exec.LookPath(c.bin); err != nil {
			t.Logf("skip %s: %s not installed", c.fixture, c.bin)
			continue
		}
		dir := copyDir(filepath.Join("..", "..", "eval", "tasks", c.fixture, "repo"))
		run, err := tools.NewRunner("off", dir, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		tl, err := Resolve(c.an)
		if err != nil {
			t.Fatal(err)
		}
		rep := Run(context.Background(), run, dir, []Analyzer{c.an}, []Tool{tl}, nil, []string{c.file}, time.Minute)
		if !rep.Passed() {
			t.Fatalf("%s: clean fixture failed: %+v\n%s", c.fixture, rep.Results, rep.Results[0].Output)
		}
		os.WriteFile(filepath.Join(dir, c.file), []byte(c.breakWith), 0o644)
		rep = Run(context.Background(), run, dir, []Analyzer{c.an}, []Tool{tl}, nil, []string{c.file}, time.Minute)
		if rep.Passed() || rep.Results[0].Blocking == 0 {
			t.Fatalf("%s: broken file passed: %+v", c.fixture, rep.Results[0])
		}
	}
	// A hostile file name is one argument, not shell syntax.
	dir := tree(t, "x'; touch PWNED; '.c")
	run, _ := tools.NewRunner("off", dir, nil, nil)
	rep := Run(context.Background(), run, dir, []Analyzer{{Name: "ls", Extensions: []string{".c"}, Command: "ls --"}}, nil, nil, []string{"x'; touch PWNED; '.c"}, time.Minute)
	if !rep.Passed() {
		t.Fatalf("%+v %s", rep.Results, rep.Results[0].Output)
	}
	if _, err := os.Stat(filepath.Join(dir, "PWNED")); err == nil {
		t.Fatal("file name was executed as shell")
	}
}

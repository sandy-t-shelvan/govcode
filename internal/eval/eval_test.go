package eval

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The scoring is only trustworthy if the reference solutions pass and the
// untouched baselines fail. These two runs prove both for every task whose
// toolchain is installed.
func TestOracleScoresAllAndNullScoresNone(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles every task")
	}
	ctx := context.Background()
	oracle, err := Run(ctx, Config{TasksDir: "../../eval/tasks", Oracle: true, Log: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	null, err := Run(ctx, Config{TasksDir: "../../eval/tasks", Null: true, Log: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if oracle.Totals.Tasks != 10 {
		t.Fatalf("expected 10 tasks, found %d", oracle.Totals.Tasks)
	}
	for i, r := range oracle.Results {
		if r.Skipped != "" {
			t.Logf("%s skipped: %s", r.ID, r.Skipped)
			continue
		}
		if !r.Passed {
			t.Errorf("%s: reference solution fails checker: %s", r.ID, r.CheckOut)
		}
		if null.Results[i].Passed {
			t.Errorf("%s: unmodified baseline passes checker; the task tests nothing", r.ID)
		}
	}
}

func TestMatchOnly(t *testing.T) {
	cases := []struct {
		id, only string
		want     bool
	}{
		{"01-c-buffer-overflow", "", true},
		{"01-c-buffer-overflow", "01", true},
		{"01-c-buffer-overflow", "02", false},
		{"06-java-x", "03, 06", true},
		{"05-y", "03,06", false},
		{"05-y", ",", false},
	}
	for _, c := range cases {
		if got := matchOnly(c.id, c.only); got != c.want {
			t.Errorf("matchOnly(%q, %q) = %v, want %v", c.id, c.only, got, c.want)
		}
	}
}

// A long eval that is interrupted must keep the tasks it finished: the report
// is on disk after every task and marked incomplete.
func TestReportSavedWhenInterrupted(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles a task")
	}
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := Run(ctx, Config{TasksDir: "../../eval/tasks", Only: "01,02", Oracle: true, OutDir: dir, Log: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete || len(rep.Results) != 1 {
		t.Fatalf("complete=%v results=%d, want incomplete after 1 task", rep.Complete, len(rep.Results))
	}
	b, err := os.ReadFile(rep.Path)
	if err != nil {
		t.Fatal(err)
	}
	var disk Report
	if err := json.Unmarshal(b, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.Complete || disk.Totals.Tasks != 1 {
		t.Fatalf("on disk: complete=%v tasks=%d", disk.Complete, disk.Totals.Tasks)
	}
	if _, err := os.Stat(rep.Path + ".tmp"); err == nil {
		t.Fatal("temp file left behind")
	}

	full, err := Run(context.Background(), Config{TasksDir: "../../eval/tasks", Only: "01,02", Oracle: true, OutDir: t.TempDir(), Log: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if !full.Complete || full.Totals.Tasks != 2 {
		t.Fatalf("full run: complete=%v tasks=%d", full.Complete, full.Totals.Tasks)
	}
}

// probe checks, when the second task's result line is logged, that the
// first task's report is already on disk.
type probe struct {
	dir  string
	seen int
	ok   bool
}

func (p *probe) Write(b []byte) (int, error) {
	if strings.Contains(string(b), "passed=") {
		p.seen++
		if p.seen == 2 {
			m, _ := filepath.Glob(filepath.Join(p.dir, "*.json"))
			if len(m) == 1 {
				if b, err := os.ReadFile(m[0]); err == nil {
					var r Report
					p.ok = json.Unmarshal(b, &r) == nil && len(r.Results) == 1 && !r.Complete
				}
			}
		}
	}
	return len(b), nil
}

func TestReportSavedAfterEachTask(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles tasks")
	}
	p := &probe{dir: t.TempDir()}
	if _, err := Run(context.Background(), Config{TasksDir: "../../eval/tasks", Only: "01,02", Oracle: true, OutDir: p.dir, Log: p}); err != nil {
		t.Fatal(err)
	}
	if !p.ok {
		t.Fatal("first task's report was not on disk before the second finished")
	}
}

func TestPrintQualifiesUnreportedTokens(t *testing.T) {
	var b strings.Builder
	r := &Report{Model: "m", Totals: Totals{Turns: 10, PromptTokens: 500, OutputTokens: 40, UsageUnreported: 4, ParsedBy: map[string]int{}}}
	r.Print(&b)
	if !strings.Contains(b.String(), "500 prompt, 40 output (lower bound: the server reported no usage for 4 of 10 turns)") {
		t.Fatalf("token line:\n%s", b.String())
	}
	b.Reset()
	r.Totals.UsageUnreported = 0
	r.Print(&b)
	if strings.Contains(b.String(), "lower bound") {
		t.Fatal("qualified although every turn reported usage")
	}
}

package eval

import (
	"context"
	"io"
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

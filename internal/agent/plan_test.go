package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

type reviewer struct {
	decisions []bool
	seen      [][]string
}

func (r *reviewer) ReviewPlan(steps []string, _ string) (bool, string) {
	r.seen = append(r.seen, steps)
	ok := r.decisions[0]
	r.decisions = r.decisions[1:]
	if !ok {
		return false, "also keep the loop C89-compatible"
	}
	return true, ""
}

func TestPlanModeGatesEdits(t *testing.T) {
	env := fixture(t)
	fix := map[string]any{"path": "sum.c", "old_text": "i <= n", "new_text": "i < n"}
	model := &llm.Scripted{Responses: []llm.Response{
		{ToolCalls: []llm.ToolCall{native("read_file", map[string]any{"path": "sum.c"})}},
		{ToolCalls: []llm.ToolCall{native("edit_file", fix)}}, // refused: plan not approved
		{ToolCalls: []llm.ToolCall{native("propose_plan", map[string]any{"steps": []string{"fix bound"}, "summary": "off by one"})}},
		{ToolCalls: []llm.ToolCall{native("propose_plan", map[string]any{"steps": []string{"fix bound", "keep C89"}, "summary": "off by one"})}},
		{ToolCalls: []llm.ToolCall{native("edit_file", fix)}},
		{ToolCalls: []llm.ToolCall{native("run_tests", nil)}},
		{ToolCalls: []llm.ToolCall{native("finish", map[string]any{"summary": "fixed"})}},
	}}
	rv := &reviewer{decisions: []bool{false, true}}
	a := &Agent{Backend: model, Tools: tools.NewSet(env), Cfg: Config{PlanMode: true}, PlanReviewer: rv}
	res, err := a.Run(context.Background(), "fix sum", RepoContext{TestCommand: env.TestCommand})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Metrics.Finished || res.Metrics.PlanRevisions != 1 || len(rv.seen) != 2 {
		t.Fatalf("metrics %+v reviews %v", res.Metrics, rv.seen)
	}
	got, _ := os.ReadFile(filepath.Join(env.Jail.Root, "sum.c"))
	if !strings.Contains(string(got), "i < n") {
		t.Fatal("approved edit not applied")
	}
	// The approved plan is pinned into the task message for later turns.
	last := model.Seen[len(model.Seen)-1]
	if !strings.Contains(last[1].Content, "APPROVED PLAN") || !strings.Contains(last[1].Content, "keep C89") {
		t.Fatalf("plan not pinned: %q", last[1].Content)
	}
	// Edit attempted before approval was refused, so exactly one edit counted.
	if env.EditGen != 1 {
		t.Fatalf("EditGen %d: an edit ran before plan approval", env.EditGen)
	}
}

func TestPlanModeRequiresReviewer(t *testing.T) {
	env := fixture(t)
	a := &Agent{Backend: &llm.Scripted{}, Tools: tools.NewSet(env), Cfg: Config{PlanMode: true}}
	if _, err := a.Run(context.Background(), "x", RepoContext{}); err == nil {
		t.Fatal("plan mode ran with no reviewer")
	}
}

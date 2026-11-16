package tools

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
)

// Tool is one capability exposed to the model.
type Tool interface {
	Spec() llm.ToolSpec
	Run(ctx context.Context, args map[string]any) (string, error)
}

// CommandApprover decides whether a non-allowlisted command may run. In
// interactive mode this prompts the human on the terminal.
type CommandApprover interface {
	ApproveCommand(command string) (bool, string)
}

// Env is the shared state the tools operate on.
type Env struct {
	Jail        *Jail
	Runner      *Runner
	TestCommand string
	TestTimeout time.Duration
	Allowlist   []string // command prefixes that run without a prompt
	Approver    CommandApprover
	RequireTest bool // finish is refused until tests pass after the last edit

	Plan         []string
	EditGen      int // incremented on every successful edit
	TestedGen    int // EditGen at the last test run
	LastTestPass bool
	TestRuns     int
	Finished     bool
	Summary      string
	Changed      map[string]bool
	Events       chan<- Event // optional, for audit/UI
}

// Event lets the caller audit tool side effects (commands run, files changed).
type Event struct {
	Kind string
	Data any
}

func (e *Env) emit(kind string, data any) {
	if e.Events != nil {
		e.Events <- Event{kind, data}
	}
}

// Set is an ordered tool registry.
type Set struct {
	Env   *Env
	order []string
	tools map[string]Tool
}

func NewSet(env *Env) *Set {
	if env.Changed == nil {
		env.Changed = map[string]bool{}
	}
	s := &Set{Env: env, tools: map[string]Tool{}}
	for _, t := range []Tool{
		&listFiles{env}, &search{env}, &readFile{env}, &outline{env},
		&editFile{env}, &createFile{env},
		&runTests{env}, &runCommand{env}, &updatePlan{env}, &finish{env},
	} {
		s.Add(t)
	}
	return s
}

func (s *Set) Add(t Tool) {
	n := t.Spec().Name
	if _, ok := s.tools[n]; !ok {
		s.order = append(s.order, n)
	}
	s.tools[n] = t
}

func (s *Set) Get(name string) (Tool, bool) { t, ok := s.tools[name]; return t, ok }

func (s *Set) Specs() []llm.ToolSpec {
	var out []llm.ToolSpec
	for _, n := range s.order {
		out = append(out, s.tools[n].Spec())
	}
	return out
}

func (s *Set) Names() []string {
	n := append([]string{}, s.order...)
	sort.Strings(n)
	return n
}

// ---- argument helpers ----

func str(a map[string]any, k string) string {
	if v, ok := a[k].(string); ok {
		return v
	}
	return ""
}

func integer(a map[string]any, k string, def int) int {
	switch v := a[k].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return def
}

func boolean(a map[string]any, k string) bool {
	v, _ := a[k].(bool)
	return v
}

func p(t, d string) llm.Property { return llm.Property{Type: t, Description: d} }

// ---- update_plan ----

type updatePlan struct{ e *Env }

func (t *updatePlan) Spec() llm.ToolSpec {
	return llm.ToolSpec{Name: "update_plan",
		Description: "Record or revise your step-by-step plan. Call this after exploring and before editing.",
		Properties: map[string]llm.Property{
			"steps": {Type: "array", Description: "Short imperative steps", Items: &llm.Property{Type: "string"}},
		}, Required: []string{"steps"}}
}

func (t *updatePlan) Run(_ context.Context, a map[string]any) (string, error) {
	raw, _ := a["steps"].([]any)
	t.e.Plan = nil
	for _, s := range raw {
		t.e.Plan = append(t.e.Plan, fmt.Sprint(s))
	}
	if len(t.e.Plan) == 0 {
		return "", fmt.Errorf("steps must be a non-empty list")
	}
	t.e.emit("plan", t.e.Plan)
	var b strings.Builder
	b.WriteString("Plan recorded:\n")
	for i, s := range t.e.Plan {
		fmt.Fprintf(&b, "%d. %s\n", i+1, s)
	}
	return b.String(), nil
}

// ---- finish ----

type finish struct{ e *Env }

func (t *finish) Spec() llm.ToolSpec {
	return llm.ToolSpec{Name: "finish",
		Description: "Call when the task is complete and tests pass. Give a short summary of what you changed and why.",
		Properties:  map[string]llm.Property{"summary": p("string", "What changed and why")},
		Required:    []string{"summary"}}
}

func (t *finish) Run(_ context.Context, a map[string]any) (string, error) {
	if t.e.RequireTest && t.e.TestCommand != "" {
		if t.e.EditGen > 0 && t.e.TestedGen != t.e.EditGen {
			return "", fmt.Errorf("not finished: you edited files after the last test run. Call run_tests first")
		}
		if t.e.TestRuns > 0 && !t.e.LastTestPass {
			return "", fmt.Errorf("not finished: the last run_tests failed. Read the output, fix the code, and run_tests again")
		}
		if t.e.EditGen > 0 && t.e.TestRuns == 0 {
			return "", fmt.Errorf("not finished: call run_tests to verify your change")
		}
	}
	t.e.Finished = true
	t.e.Summary = str(a, "summary")
	return "Finished. The change will be submitted as a proposal for human review.", nil
}

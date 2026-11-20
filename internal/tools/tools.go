package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/marking"
	"github.com/sandy-t-shelvan/govcode/internal/permissions"
)

// Tool is one capability exposed to the model.
type Tool interface {
	Spec() llm.ToolSpec
	Run(ctx context.Context, args map[string]any) (string, error)
}

// Approver asks a human whether an action that policy marks "ask" may
// proceed (for example a command outside the allowlist). In interactive
// mode this prompts on the terminal or in the editor.
type Approver interface {
	Approve(action string) (ok bool, who string)
}

// Env is the shared state the tools operate on.
type Env struct {
	Jail        *Jail
	Runner      *Runner
	TestCommand string
	TestTimeout time.Duration
	Allowlist   []string           // legacy command prefixes; folded into Perms
	Perms       *permissions.Rules // allow/ask/deny rules; nil = built from Allowlist
	Approver    Approver
	// MaxLevel is the repository's accredited classification. Content
	// marked above it is withheld from the model and blocks proposals.
	// The zero value is UNCLASSIFIED, the strictest setting, so an
	// unconfigured Env fails safe. marking.Unknown disables the guard.
	MaxLevel marking.Level
	// PostEditHooks are site checks (from the root-owned policy only) run
	// in the sandbox after every successful edit, with the changed path in
	// GOVCODE_CHANGED_FILES. A failure is reported back to the model.
	PostEditHooks []string
	HookFailures  int
	// Memory: GOVCODE.md files already loaded, and the remaining byte budget.
	MemoryLoaded map[string]bool
	MemoryBudget int
	RequireTest  bool // finish is refused until tests pass after the last edit

	Plan         []string
	EditGen      int // incremented on every successful edit
	TestedGen    int // EditGen at the last test run
	LastTestPass bool
	TestRuns     int
	Finished     bool
	Summary      string
	Changed      map[string]bool
	Events       chan<- Event // optional, for audit/UI
	// OnEdit is called after every successful edit with the changed path
	// (repo-relative), before post-edit hooks; used for checkpoints.
	OnEdit func(rel string)
}

// Event lets the caller audit tool side effects (commands run, files changed).
type Event struct {
	Kind string
	Data any
}

func (e *Env) rules() *permissions.Rules {
	if e.Perms == nil {
		e.Perms, _ = permissions.Parse(permissions.FromAllowlist(e.Allowlist), nil, nil)
	}
	return e.Perms
}

// authorizePath applies tool's rules to the path the caller named and, when
// that path is a symlink, to the file that will actually be opened. Checking
// only the link name would let an allowed path such as src/alias.h read a
// file the policy denies, because the open follows the link. Checking only
// the target would let a denied path through when the link's target is
// allowed. Both must pass. opened is the absolute path Resolve returned.
func (e *Env) authorizePath(tool, requested, opened string) error {
	lexAbs, err := e.Jail.cleanAbs(requested)
	if err != nil {
		return err
	}
	lex := e.Jail.Rel(lexAbs)
	if err := e.authorize(tool, lex); err != nil {
		return err
	}
	if real := e.Jail.Rel(opened); real != lex {
		if err := e.authorize(tool, real); err != nil {
			return err
		}
	}
	return nil
}

// authorize applies the permission rules to one action. It is called by
// every tool that acts on a path or runs a command, so no caller can skip it.
func (e *Env) authorize(tool, subject string) error {
	d, rule := e.rules().Decide(tool, subject)
	who := "policy"
	if d == permissions.Ask {
		if e.Approver == nil {
			d, rule = permissions.Deny, rule+" (ask, but no human approver is attached)"
		} else if ok, by := e.Approver.Approve(fmt.Sprintf("%s(%s)", tool, subject)); ok {
			d, who = permissions.Allow, by
		} else {
			d, who = permissions.Deny, by
		}
	}
	e.emit("permission", map[string]any{"tool": tool, "subject": clip(subject, 300), "decision": d.String(), "rule": rule, "by": who})
	if d == permissions.Deny {
		if who != "policy" {
			return fmt.Errorf("the human reviewer denied %s(%s). Try another approach", tool, subject)
		}
		return fmt.Errorf("%s(%s) is denied by policy rule %s", tool, subject, rule)
	}
	return nil
}

// spill reports whether text carries a marking above MaxLevel. If it does,
// a spillage event is emitted with location and level only, never content.
func (e *Env) spill(where, text string) bool {
	if e.MaxLevel == marking.Unknown {
		return false
	}
	fs := marking.Above(text, e.MaxLevel)
	if len(fs) == 0 {
		return false
	}
	lines := make([]int, 0, len(fs))
	for _, f := range fs {
		lines = append(lines, f.Line)
	}
	e.emit("spillage_blocked", map[string]any{"where": where, "lines": lines, "level": marking.Highest(fs).String(), "repository_level": e.MaxLevel.String()})
	return true
}

// Spill is the exported check used by the agent on model output and by
// the run flow on the task text.
func (e *Env) Spill(where, text string) bool { return e.spill(where, text) }

func withheld(where string, e *Env) string {
	return fmt.Sprintf("[govcode: %s withheld: it contains a classification marking above this repository's level (%s). The event has been reported. Do not try to read it another way.]", where, e.MaxLevel)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// RunHooks runs each hook with GOVCODE_HOOK and GOVCODE_CHANGED_FILES set.
// It returns a report of failures ("" when all pass).
func (e *Env) RunHooks(ctx context.Context, stage string, hooks []string, changed []string) string {
	var b strings.Builder
	for _, h := range hooks {
		r := e.Runner.RunWith(ctx, h, 5*time.Minute, []string{"GOVCODE_HOOK=" + stage, "GOVCODE_CHANGED_FILES=" + strings.Join(changed, " ")})
		ok := r.ExitCode == 0 && !r.TimedOut
		if !ok && e.spill("hook output", r.Output) {
			r.Output = withheld("hook output", e)
		}
		e.emit("hook", map[string]any{"stage": stage, "command": h, "exit_code": r.ExitCode, "passed": ok, "output": clip(r.Output, 4000)})
		if !ok {
			fmt.Fprintf(&b, "Site check %q failed (exit %d):\n%s\n", h, r.ExitCode, clip(r.Output, 3000))
		}
	}
	return b.String()
}

func (e *Env) postEdit(ctx context.Context, rel string) string {
	if len(e.PostEditHooks) == 0 {
		return ""
	}
	rep := e.RunHooks(ctx, "post_edit", e.PostEditHooks, []string{rel})
	if rep != "" {
		e.HookFailures++
		return "\n" + rep + "Fix the problems the site checks report; the proposal cannot be approved while they fail."
	}
	return ""
}

// MemoryFile is the per-directory conventions file.
const MemoryFile = "GOVCODE.md"

// memoryFor returns the GOVCODE.md files between the repo root (exclusive,
// it is loaded into the task prompt) and dir that have not been loaded
// yet, within the byte budget.
func (e *Env) memoryFor(relDir string) string {
	if e.MemoryLoaded == nil {
		e.MemoryLoaded = map[string]bool{}
	}
	var dirs []string
	for d := relDir; d != "." && d != "/" && d != ""; d = filepath.Dir(d) {
		dirs = append([]string{d}, dirs...)
	}
	var b strings.Builder
	for _, d := range dirs {
		if e.MemoryLoaded[d] {
			continue
		}
		e.MemoryLoaded[d] = true
		data, err := os.ReadFile(filepath.Join(e.Jail.Root, d, MemoryFile))
		if err != nil || len(data) == 0 {
			continue
		}
		if e.MemoryBudget <= 0 {
			break
		}
		if len(data) > e.MemoryBudget {
			data = data[:e.MemoryBudget]
		}
		if e.spill("memory "+d+"/"+MemoryFile, string(data)) {
			continue
		}
		e.MemoryBudget -= len(data)
		sum := sha256.Sum256(data)
		e.emit("memory_loaded", map[string]any{"path": d + "/" + MemoryFile, "sha256": hex.EncodeToString(sum[:]), "bytes": len(data)})
		fmt.Fprintf(&b, "[Conventions from %s/%s]\n%s\n[end of conventions]\n\n", d, MemoryFile, strings.TrimSpace(string(data)))
	}
	return b.String()
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

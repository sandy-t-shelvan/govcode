// Package eval measures whether a local model can drive govcode's tools on
// real legacy-code tasks. Each task is a small repository with a bug or a
// change request, a visible test command, and a hidden checker copied in
// only after the agent finishes (so editing the tests cannot fake a pass).
package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/agent"
	"github.com/sandy-t-shelvan/govcode/internal/gitx"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

type OracleStep struct {
	Tool string         `json:"tool"`
	Args map[string]any `json:"args"`
}

type Task struct {
	ID           string       `json:"id"`
	Language     string       `json:"language"`
	Title        string       `json:"title"`
	Prompt       string       `json:"prompt"`
	TestCommand  string       `json:"test_command"`
	CheckCommand string       `json:"check_command"`
	Requires     []string     `json:"requires"` // executables needed, e.g. gnatmake
	Allowlist    []string     `json:"allowlist"`
	Oracle       []OracleStep `json:"oracle"` // reference solution, for harness validation
	Dir          string       `json:"-"`
}

type Config struct {
	TasksDir   string
	OutDir     string
	Only       string
	MaxTurns   int
	NewBackend func() (llm.Backend, error)
	Oracle     bool // use each task's reference solution (validates scoring)
	Null       bool // model that never calls a tool (validates scoring)
	Log        io.Writer
}

type TaskResult struct {
	ID        string        `json:"id"`
	Language  string        `json:"language"`
	Title     string        `json:"title"`
	Passed    bool          `json:"passed"`
	Skipped   string        `json:"skipped,omitempty"`
	Error     string        `json:"error,omitempty"`
	CheckOut  string        `json:"check_output,omitempty"`
	Metrics   agent.Metrics `json:"metrics"`
	ValidRate float64       `json:"valid_call_rate"`
	Changed   []string      `json:"changed"`
	DurationS float64       `json:"duration_s"`
}

type Report struct {
	Model   string       `json:"model"`
	NumCtx  int          `json:"num_ctx"`
	Started string       `json:"started"`
	Results []TaskResult `json:"results"`
	Totals  Totals       `json:"totals"`
	// Complete is false while the run is in progress or if it was
	// interrupted; the report is rewritten after every task so a long run
	// that is killed keeps the tasks it finished.
	Complete bool   `json:"complete"`
	Path     string `json:"-"`
}

type Totals struct {
	Tasks         int            `json:"tasks"`
	Run           int            `json:"run"`
	Passed        int            `json:"passed"`
	CallsEmitted  int            `json:"calls_emitted"`
	ValidCalls    int            `json:"valid_calls"`
	ExecOK        int            `json:"exec_ok"`
	ExecError     int            `json:"exec_error"`
	UnknownTool   int            `json:"unknown_tool"`
	SchemaInvalid int            `json:"schema_invalid"`
	NoCallTurns   int            `json:"no_call_turns"`
	Turns         int            `json:"turns"`
	ParsedBy      map[string]int `json:"parsed_by"`
	Finished      int            `json:"finished"`
	PromptTokens  int            `json:"prompt_tokens"`
	OutputTokens  int            `json:"output_tokens"`
	// UsageUnreported is the number of turns whose reply had no token usage.
	UsageUnreported int     `json:"usage_unreported_turns,omitempty"`
	ModelSeconds    float64 `json:"model_seconds"`
}

func LoadTasks(dir, only string) ([]Task, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ts []Task
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "task.json"))
		if err != nil {
			continue
		}
		var t Task
		if err := json.Unmarshal(b, &t); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		t.Dir = filepath.Join(dir, e.Name())
		if matchOnly(t.ID, only) {
			ts = append(ts, t)
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].ID < ts[j].ID })
	return ts, nil
}

// matchOnly reports whether id is selected by only: empty selects all,
// otherwise any comma-separated part contained in id selects it.
func matchOnly(id, only string) bool {
	if only == "" {
		return true
	}
	for _, p := range strings.Split(only, ",") {
		if p = strings.TrimSpace(p); p != "" && strings.Contains(id, p) {
			return true
		}
	}
	return false
}

func Run(ctx context.Context, cfg Config) (*Report, error) {
	tasks, err := LoadTasks(cfg.TasksDir, cfg.Only)
	if err != nil {
		return nil, err
	}
	if len(tasks) == 0 {
		return nil, fmt.Errorf("no tasks in %s", cfg.TasksDir)
	}
	rep := &Report{Started: time.Now().UTC().Format(time.RFC3339), Totals: Totals{ParsedBy: map[string]int{}}}
	for _, t := range tasks {
		r := runTask(ctx, cfg, t, rep)
		rep.Results = append(rep.Results, r)
		fmt.Fprintf(cfg.Log, "[%s] passed=%v %s\n", t.ID, r.Passed, r.Skipped+r.Error)
		rep.total()
		if ctx.Err() != nil {
			break
		}
		rep.save(cfg.OutDir)
	}
	rep.total()
	rep.Complete = ctx.Err() == nil && len(rep.Results) == len(tasks)
	rep.save(cfg.OutDir)
	return rep, nil
}

// save writes the JSON and Markdown reports. The path is fixed on the first
// call so each rewrite replaces the same files.
func (r *Report) save(dir string) {
	if dir == "" {
		return
	}
	if r.Path == "" {
		os.MkdirAll(dir, 0o755)
		name := strings.NewReplacer(":", "_", "/", "_").Replace(r.Model)
		r.Path = filepath.Join(dir, fmt.Sprintf("%s-%s.json", time.Now().UTC().Format("20060102-150405"), name))
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	writeAtomic(r.Path, b)
	var md strings.Builder
	r.Markdown(&md)
	writeAtomic(strings.TrimSuffix(r.Path, ".json")+".md", []byte(md.String()))
}

// writeAtomic replaces path via a temp file so a kill mid-write never leaves
// a truncated report.
func writeAtomic(path string, b []byte) {
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, path)
	}
}

func runTask(ctx context.Context, cfg Config, t Task, rep *Report) (res TaskResult) {
	res = TaskResult{ID: t.ID, Language: t.Language, Title: t.Title}
	start := time.Now()
	defer func() { res.DurationS = time.Since(start).Seconds() }()
	for _, bin := range t.Requires {
		if _, err := exec.LookPath(bin); err != nil {
			res.Skipped = "missing " + bin
			return
		}
	}
	work, err := os.MkdirTemp("", "govcode-eval-"+t.ID+"-")
	if err != nil {
		res.Error = err.Error()
		return
	}
	defer os.RemoveAll(work)
	if err := setupRepo(filepath.Join(t.Dir, "repo"), work); err != nil {
		res.Error = err.Error()
		return
	}
	var backend llm.Backend
	switch {
	case cfg.Oracle:
		backend = oracleBackend(t)
	case cfg.Null:
		backend = &llm.Scripted{Name: "null", Responses: repeat(llm.Response{Content: "I think the code is fine."}, 10)}
	default:
		if backend, err = cfg.NewBackend(); err != nil {
			res.Error = err.Error()
			return
		}
	}
	rep.Model = backend.ModelName()
	rep.NumCtx = backend.Options().NumCtx
	jail, _ := tools.NewJail(work)
	runner, err := tools.NewRunner(tools.SandboxBestEffort, jail.Root, nil, nil)
	if err != nil {
		res.Error = err.Error()
		return
	}
	allow := append([]string{"make", "gcc", "g++", "cc", "gnatmake", "gprbuild", "cobc", "gfortran", "ls", "cat", "grep"}, t.Allowlist...)
	env := &tools.Env{Jail: jail, Runner: runner, TestCommand: t.TestCommand, TestTimeout: 3 * time.Minute,
		Allowlist: allow, RequireTest: true}
	maxTurns := cfg.MaxTurns
	if maxTurns == 0 {
		maxTurns = 30
	}
	ag := &agent.Agent{Backend: backend, Tools: tools.NewSet(env), Cfg: agent.Config{MaxTurns: maxTurns, Out: cfg.Log}}
	ar, err := ag.Run(ctx, t.Prompt, agent.RepoContext{Summary: gitx.Summary(work), TestCommand: t.TestCommand})
	if err != nil {
		res.Error = err.Error()
	}
	if ar != nil {
		res.Metrics = ar.Metrics
		res.ValidRate = ar.Metrics.ValidCallRate()
		res.Changed = ar.Changed
	}
	res.Passed, res.CheckOut = check(ctx, t, work)
	return
}

func repeat(r llm.Response, n int) []llm.Response {
	out := make([]llm.Response, n)
	for i := range out {
		out[i] = r
	}
	return out
}

func setupRepo(src, dst string) error {
	if err := copyTree(src, dst); err != nil {
		return err
	}
	for _, a := range [][]string{{"init", "-q", "-b", "main"}, {"add", "-A"},
		{"-c", "user.name=eval", "-c", "user.email=eval@localhost", "commit", "-qm", "baseline"}} {
		if out, err := exec.Command("git", append([]string{"-C", dst}, a...)...).CombinedOutput(); err != nil {
			return fmt.Errorf("git %v: %s", a, out)
		}
	}
	return nil
}

// check copies the final worktree, overlays the hidden checker (which
// overwrites any test files the agent touched), and runs check_command.
func check(ctx context.Context, t Task, work string) (bool, string) {
	dir, err := os.MkdirTemp("", "govcode-check-")
	if err != nil {
		return false, err.Error()
	}
	defer os.RemoveAll(dir)
	copyTree(work, dir)
	os.RemoveAll(filepath.Join(dir, ".git"))
	if _, err := os.Stat(filepath.Join(t.Dir, "check")); err == nil {
		copyTree(filepath.Join(t.Dir, "check"), dir)
	}
	cmd := t.CheckCommand
	if cmd == "" {
		cmd = t.TestCommand
	}
	r, _ := tools.NewRunner(tools.SandboxBestEffort, dir, nil, nil)
	out := r.Run(ctx, cmd, 3*time.Minute)
	tail := out.Output
	if len(tail) > 2000 {
		tail = tail[len(tail)-2000:]
	}
	return out.ExitCode == 0 && !out.TimedOut, tail
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode().Perm())
	})
}

// oracleBackend replays the task's reference solution as native tool calls,
// then runs tests and finishes. A correct harness must score it 100%.
func oracleBackend(t Task) llm.Backend {
	var rs []llm.Response
	for _, s := range t.Oracle {
		b, _ := json.Marshal(s.Args)
		rs = append(rs, llm.Response{ToolCalls: []llm.ToolCall{{Name: s.Tool, Args: b, Source: llm.SourceNative}}})
	}
	rs = append(rs,
		llm.Response{ToolCalls: []llm.ToolCall{{Name: "run_tests", Args: json.RawMessage(`{}`), Source: llm.SourceNative}}},
		llm.Response{ToolCalls: []llm.ToolCall{{Name: "finish", Args: json.RawMessage(`{"summary":"oracle"}`), Source: llm.SourceNative}}})
	return &llm.Scripted{Name: "oracle", Responses: rs}
}

func (r *Report) total() {
	r.Totals = Totals{ParsedBy: map[string]int{}}
	t := &r.Totals
	for _, x := range r.Results {
		t.Tasks++
		if x.Skipped != "" {
			continue
		}
		t.Run++
		m := x.Metrics
		if x.Passed {
			t.Passed++
		}
		if m.Finished {
			t.Finished++
		}
		t.CallsEmitted += m.CallsEmitted
		t.ValidCalls += m.CallsEmitted - m.UnknownTool - m.SchemaInvalid
		t.ExecOK += m.ExecOK
		t.ExecError += m.ExecError
		t.UnknownTool += m.UnknownTool
		t.SchemaInvalid += m.SchemaInvalid
		t.NoCallTurns += m.NoCallTurns
		t.Turns += m.Turns
		t.PromptTokens += m.PromptTokens
		t.OutputTokens += m.CompletionTokens
		t.UsageUnreported += m.UsageUnreported
		t.ModelSeconds += m.ModelTime.Seconds()
		for k, v := range m.ParsedBy {
			t.ParsedBy[k] += v
		}
	}
}

func pct(a, b int) string {
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(a)/float64(b))
}

func (r *Report) Print(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "TASK\tLANG\tPASS\tFINISHED\tTURNS\tCALLS\tVALID\tEXEC-ERR\tNO-CALL\tPARSED\tSECS\n")
	for _, x := range r.Results {
		if x.Skipped != "" {
			fmt.Fprintf(tw, "%s\t%s\tSKIP (%s)\n", x.ID, x.Language, x.Skipped)
			continue
		}
		m := x.Metrics
		fmt.Fprintf(tw, "%s\t%s\t%v\t%v\t%d\t%d\t%s\t%d\t%d\t%s\t%.0f\n", x.ID, x.Language, x.Passed, m.Finished, m.Turns,
			m.CallsEmitted, pct(m.CallsEmitted-m.UnknownTool-m.SchemaInvalid, m.CallsEmitted), m.ExecError, m.NoCallTurns, parsed(m.ParsedBy), x.DurationS)
	}
	tw.Flush()
	t := r.Totals
	fmt.Fprintf(w, "\nmodel %s  num_ctx %d\n", r.Model, r.NumCtx)
	fmt.Fprintf(w, "tasks passed:          %d/%d run (%d skipped)\n", t.Passed, t.Run, t.Tasks-t.Run)
	fmt.Fprintf(w, "tool calls emitted:    %d over %d turns\n", t.CallsEmitted, t.Turns)
	fmt.Fprintf(w, "valid tool calls:      %s  (known tool + schema-valid args)\n", pct(t.ValidCalls, t.CallsEmitted))
	fmt.Fprintf(w, "executed without error:%s  (e.g. old_text matched)\n", " "+pct(t.ExecOK, t.CallsEmitted))
	fmt.Fprintf(w, "turns with no call:    %d\n", t.NoCallTurns)
	fmt.Fprintf(w, "parse path:            %s\n", parsed(t.ParsedBy))
	fmt.Fprintf(w, "model tokens:          %d prompt, %d output%s\n", t.PromptTokens, t.OutputTokens, unreported(t.UsageUnreported, t.Turns))
}

// unreported qualifies token totals when the server did not report usage.
func unreported(n, turns int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" (lower bound: the server reported no usage for %d of %d turns)", n, turns)
}

func parsed(m map[string]int) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var p []string
	for _, k := range ks {
		p = append(p, fmt.Sprintf("%s=%d", strings.TrimPrefix(k, "fallback-"), m[k]))
	}
	return strings.Join(p, ",")
}

func (r *Report) Markdown(w io.Writer) {
	t := r.Totals
	fmt.Fprintf(w, "# govcode eval: %s\n\n- num_ctx: %d\n- started: %s\n- **tasks passed: %d/%d**\n- **valid tool calls: %s** (%d/%d)\n- executed without error: %s\n- parse path: %s\n\n",
		r.Model, r.NumCtx, r.Started, t.Passed, t.Run, pct(t.ValidCalls, t.CallsEmitted), t.ValidCalls, t.CallsEmitted, pct(t.ExecOK, t.CallsEmitted), parsed(t.ParsedBy))
	fmt.Fprintf(w, "| task | lang | pass | finished | turns | calls | valid | exec err | no-call | stop |\n|---|---|---|---|---|---|---|---|---|---|\n")
	for _, x := range r.Results {
		m := x.Metrics
		if x.Skipped != "" {
			fmt.Fprintf(w, "| %s | %s | skipped: %s |||||||||\n", x.ID, x.Language, x.Skipped)
			continue
		}
		fmt.Fprintf(w, "| %s | %s | %v | %v | %d | %d | %s | %d | %d | %s |\n", x.ID, x.Language, x.Passed, m.Finished, m.Turns, m.CallsEmitted,
			pct(m.CallsEmitted-m.UnknownTool-m.SchemaInvalid, m.CallsEmitted), m.ExecError, m.NoCallTurns, m.StopReason)
	}
}

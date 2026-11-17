// Package agent runs the plan -> edit -> test -> fix loop against a local
// model.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

// Recorder receives every model exchange and tool execution. The audit log
// implements it.
type Recorder interface {
	Record(kind string, payload any) error
}

type nopRecorder struct{}

func (nopRecorder) Record(string, any) error { return nil }

type Config struct {
	MaxTurns      int
	MaxNoCallNags int // consecutive replies without a tool call before giving up
	Out           io.Writer
	Verbose       bool
	// PlanMode starts read-only: only exploration tools and propose_plan
	// are offered until PlanReviewer approves a plan.
	PlanMode bool
	// OnToken, if set and the backend streams, receives model text as it is
	// generated, one complete line at a time. Each line passes the spillage
	// check before it is released.
	OnToken func(string)
	// History, when set (resume), is the conversation to continue instead
	// of a fresh system and task message. A plan already approved in it
	// stays approved.
	History []llm.Message
	// OnTurn receives a copy of the conversation after every turn, so the
	// caller can persist it for resume.
	OnTurn func(msgs []llm.Message)
}

// nagText is sent after a reply with no tool call. When the model's lock
// gives a tool-call format, it is repeated: small models that describe a
// call in prose usually have lost the format, not the intent.
func nagText(toolPrompt string) string {
	t := "You did not call a tool. Continue the task by calling a tool now. If the task is complete and tests pass, call finish."
	if toolPrompt != "" {
		t += "\n" + toolPrompt
	}
	return t
}

// approvedPlanMarker is written into the task message when a plan is
// approved; it survives in saved history.
const approvedPlanMarker = "\nAPPROVED PLAN (follow it; do not expand the scope):\n"

// PlanReviewer is the human who approves the plan in plan mode.
type PlanReviewer interface {
	ReviewPlan(steps []string, summary string) (approved bool, feedback string)
}

// ReadOnlyTools are the tools offered while planning.
var ReadOnlyTools = map[string]bool{"list_files": true, "search": true, "read_file": true, "outline": true, "update_plan": true}

var proposePlanSpec = llm.ToolSpec{Name: "propose_plan",
	Description: "Submit your plan for human approval. Edit, test and command tools become available only after the plan is approved.",
	Properties: map[string]llm.Property{
		"steps":   {Type: "array", Description: "Short imperative steps", Items: &llm.Property{Type: "string"}},
		"summary": {Type: "string", Description: "What you will change and why, in one or two sentences"},
	}, Required: []string{"steps", "summary"}}

// Metrics are what the Phase 1 tool-call eval measures.
type Metrics struct {
	Turns            int            `json:"turns"`
	PlanRevisions    int            `json:"plan_revisions,omitempty"`
	CallsEmitted     int            `json:"calls_emitted"`
	ParsedBy         map[string]int `json:"parsed_by"`
	UnknownTool      int            `json:"unknown_tool"`
	SchemaInvalid    int            `json:"schema_invalid"`
	ExecOK           int            `json:"exec_ok"`
	ExecError        int            `json:"exec_error"` // tool ran but reported an error (e.g. old_text not found)
	NoCallTurns      int            `json:"no_call_turns"`
	ContextTrims     int            `json:"context_trims"`
	PromptTokens     int            `json:"prompt_tokens"`
	CompletionTokens int            `json:"completion_tokens"`
	ModelTime        time.Duration  `json:"model_time_ns"`
	Finished         bool           `json:"finished"`
	StopReason       string         `json:"stop_reason"`
}

// ValidCallRate is the fraction of emitted calls that named a real tool and
// had schema-valid arguments: the core "can it call tools" number.
func (m Metrics) ValidCallRate() float64 {
	if m.CallsEmitted == 0 {
		return 0
	}
	return float64(m.CallsEmitted-m.UnknownTool-m.SchemaInvalid) / float64(m.CallsEmitted)
}

type Agent struct {
	Backend      llm.Backend
	Tools        *tools.Set
	Rec          Recorder
	Cfg          Config
	PlanReviewer PlanReviewer
}

type Result struct {
	Summary string
	Metrics Metrics
	Changed []string
}

func (a *Agent) logf(format string, args ...any) {
	if a.Cfg.Out != nil {
		fmt.Fprintf(a.Cfg.Out, format, args...)
	}
}

func (a *Agent) Run(ctx context.Context, task string, rc RepoContext) (*Result, error) {
	if a.Rec == nil {
		a.Rec = nopRecorder{}
	}
	if a.Cfg.MaxTurns == 0 {
		a.Cfg.MaxTurns = 40
	}
	if a.Cfg.MaxNoCallNags == 0 {
		a.Cfg.MaxNoCallNags = 3
	}
	planning := a.Cfg.PlanMode
	if planning && a.PlanReviewer == nil {
		return nil, fmt.Errorf("plan mode needs a human plan reviewer")
	}
	allSpecs := a.Tools.Specs()
	specsFor := func(planning bool) ([]llm.ToolSpec, map[string]llm.ToolSpec) {
		var out []llm.ToolSpec
		for _, s := range allSpecs {
			if !planning || ReadOnlyTools[s.Name] {
				out = append(out, s)
			}
		}
		if planning {
			out = append(out, proposePlanSpec)
		}
		by := map[string]llm.ToolSpec{}
		for _, s := range out {
			by[s.Name] = s
		}
		return out, by
	}
	var msgs []llm.Message
	if len(a.Cfg.History) >= 2 {
		msgs = append([]llm.Message(nil), a.Cfg.History...)
		if planning && strings.Contains(msgs[1].Content, approvedPlanMarker) {
			planning = false
		}
	} else {
		msgs = []llm.Message{
			{Role: llm.RoleSystem, Content: systemPrompt},
			{Role: llm.RoleUser, Content: taskPrompt(task, rc)},
		}
		if planning {
			msgs[1].Content += "\nPLAN MODE: you can only read code. Explore, then call propose_plan. Edit tools unlock after a human approves your plan.\n"
		}
	}
	specs, specByName := specsFor(planning)
	opts := a.Backend.Options()
	turnDone := func() {
		if a.Cfg.OnTurn != nil {
			a.Cfg.OnTurn(append([]llm.Message(nil), msgs...))
		}
	}
	// Report the starting conversation too, so a run whose first model
	// request fails can still be resumed.
	turnDone()
	m := Metrics{ParsedBy: map[string]int{}}
	nags := 0
	env := a.Tools.Env

	for m.Turns < a.Cfg.MaxTurns {
		if err := ctx.Err(); err != nil {
			m.StopReason = "cancelled"
			return &Result{Metrics: m}, err
		}
		m.Turns++
		fitted, trims, err := fitBudget(msgs, specs, opts.NumCtx, opts.MaxTokens)
		if err != nil {
			m.StopReason = "context_overflow"
			return &Result{Metrics: m}, err
		}
		m.ContextTrims += trims
		t0 := time.Now()
		var resp *llm.Response
		streamed := false
		if st, ok := a.Backend.(llm.Streamer); ok && a.Cfg.OnToken != nil {
			lb := &lineBuffer{emit: a.Cfg.OnToken, check: func(l string) bool { return env.Spill("streamed model output", l) }}
			resp, err = st.ChatStream(ctx, fitted, specs, lb.write)
			lb.flush()
			streamed = true
		} else {
			resp, err = a.Backend.Chat(ctx, fitted, specs)
		}
		m.ModelTime += time.Since(t0)
		if err != nil {
			m.StopReason = "model_error"
			a.Rec.Record("model_error", map[string]any{"turn": m.Turns, "error": err.Error()})
			return &Result{Metrics: m}, fmt.Errorf("model request failed: %w", err)
		}
		m.PromptTokens += resp.Usage.PromptTokens
		m.CompletionTokens += resp.Usage.CompletionTokens

		calls, content := resp.ToolCalls, resp.Content
		if len(calls) == 0 {
			calls, content = llm.ExtractToolCalls(resp.Content, specs)
		}
		content = stripThinking(content)
		recorded := resp.Content
		if env.Spill("model output", resp.Content) {
			// Do not copy over-classified text into the log or history.
			recorded, content = "[withheld: classification marking above repository level]", ""
		}
		a.Rec.Record("model_response", map[string]any{"turn": m.Turns, "content": recorded, "tool_calls": calls,
			"usage": resp.Usage, "finish_reason": resp.FinishReason, "model": a.Backend.ModelName()})
		if strings.TrimSpace(content) != "" && !streamed {
			a.logf("\n%s\n", strings.TrimSpace(content))
		}

		if len(calls) == 0 {
			m.NoCallTurns++
			nags++
			if nags > a.Cfg.MaxNoCallNags {
				m.StopReason = "no_tool_call"
				break
			}
			msgs = append(msgs, llm.Message{Role: llm.RoleAssistant, Content: recorded},
				llm.Message{Role: llm.RoleUser, Content: nagText(opts.ToolPrompt)})
			turnDone()
			continue
		}
		nags = 0

		asst := llm.Message{Role: llm.RoleAssistant, Content: content}
		var results []llm.Message
		for i := range calls {
			c := &calls[i]
			if c.ID == "" {
				c.ID = fmt.Sprintf("call_%d_%d", m.Turns, i)
			}
			m.CallsEmitted++
			m.ParsedBy[c.Source]++
			if c.Name == proposePlanSpec.Name {
				out, approved := a.reviewPlan(c, planning, &m, msgs)
				results = append(results, llm.Message{Role: llm.RoleTool, Content: out, ToolCallID: c.ID, ToolName: c.Name})
				if approved {
					planning = false
					specs, specByName = specsFor(false)
				}
				continue
			}
			if planning && !ReadOnlyTools[c.Name] {
				if _, known := a.Tools.Get(c.Name); known {
					m.ExecError++
					msg := fmt.Sprintf("Error: %s is not available until your plan is approved. Call propose_plan first.", c.Name)
					a.Rec.Record("tool_result", map[string]any{"call_id": c.ID, "tool": c.Name, "error": msg})
					results = append(results, llm.Message{Role: llm.RoleTool, Content: msg, ToolCallID: c.ID, ToolName: c.Name})
					continue
				}
			}
			out, ok := a.execute(ctx, c, specByName, &m)
			results = append(results, llm.Message{Role: llm.RoleTool, Content: out, ToolCallID: c.ID, ToolName: c.Name})
			_ = ok
			if env.Finished {
				break
			}
		}
		asst.ToolCalls = calls[:len(results)]
		msgs = append(msgs, asst)
		msgs = append(msgs, results...)
		turnDone()
		if env.Finished {
			m.Finished = true
			m.StopReason = "finished"
			break
		}
	}
	if m.StopReason == "" {
		m.StopReason = "max_turns"
	}
	var changed []string
	for p := range env.Changed {
		changed = append(changed, p)
	}
	return &Result{Summary: env.Summary, Metrics: m, Changed: changed}, nil
}

// reviewPlan asks the human to approve the proposed plan. On approval the
// plan is pinned into the task message, which context trimming never drops.
func (a *Agent) reviewPlan(c *llm.ToolCall, planning bool, m *Metrics, msgs []llm.Message) (string, bool) {
	if !planning {
		return "The plan is already approved. Continue with the work.", false
	}
	args, err := llm.ValidateArgs(proposePlanSpec, c.Args)
	if err != nil {
		m.SchemaInvalid++
		return "Error: " + err.Error(), false
	}
	m.ExecOK++
	var steps []string
	for _, s := range args["steps"].([]any) {
		steps = append(steps, fmt.Sprint(s))
	}
	summary := fmt.Sprint(args["summary"])
	if a.Tools.Env.Spill("proposed plan", strings.Join(steps, "\n")+"\n"+summary) {
		return "Error: the plan contains a classification marking above this repository's level and was not shown to the reviewer. Rewrite it without that content.", false
	}
	a.Rec.Record("plan_proposed", map[string]any{"call_id": c.ID, "steps": steps, "summary": summary})
	ok, feedback := a.PlanReviewer.ReviewPlan(steps, summary)
	a.Rec.Record("plan_decision", map[string]any{"call_id": c.ID, "decision": map[bool]string{true: "approved", false: "rejected"}[ok], "feedback": feedback})
	if !ok {
		m.PlanRevisions++
		return fmt.Sprintf("The reviewer rejected the plan: %s\nRevise it and call propose_plan again.", feedback), false
	}
	a.Tools.Env.Plan = steps
	var b strings.Builder
	b.WriteString(approvedPlanMarker)
	for i, s := range steps {
		fmt.Fprintf(&b, "%d. %s\n", i+1, s)
	}
	if feedback != "" {
		b.WriteString("Reviewer notes: " + feedback + "\n")
	}
	msgs[1].Content += b.String()
	return "Plan approved. Edit, test and command tools are now available. Carry out the plan.", true
}

func (a *Agent) execute(ctx context.Context, c *llm.ToolCall, specs map[string]llm.ToolSpec, m *Metrics) (string, bool) {
	spec, ok := specs[c.Name]
	if !ok {
		m.UnknownTool++
		msg := fmt.Sprintf("Error: there is no tool named %q. Available tools: %s", c.Name, strings.Join(a.Tools.Names(), ", "))
		a.Rec.Record("tool_result", map[string]any{"call_id": c.ID, "tool": c.Name, "error": msg})
		return msg, false
	}
	args, err := llm.ValidateArgs(spec, c.Args)
	if err != nil {
		m.SchemaInvalid++
		msg := "Error: " + err.Error()
		a.Rec.Record("tool_result", map[string]any{"call_id": c.ID, "tool": c.Name, "error": msg})
		a.logf("  ✗ %s: %s\n", c.Name, err)
		return msg, false
	}
	if b, err := json.Marshal(args); err == nil {
		c.Args = b // record the normalized arguments in history
	}
	tool, _ := a.Tools.Get(c.Name)
	a.logf("  → %s %s\n", c.Name, brief(args))
	out, err := tool.Run(ctx, args)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return "Error: cancelled", false
		}
		m.ExecError++
		msg := "Error: " + err.Error()
		a.Rec.Record("tool_result", map[string]any{"call_id": c.ID, "tool": c.Name, "args": args, "error": msg})
		a.logf("    %s\n", firstLine(msg))
		return msg, false
	}
	m.ExecOK++
	a.Rec.Record("tool_result", map[string]any{"call_id": c.ID, "tool": c.Name, "args": args, "output": out})
	if a.Cfg.Verbose {
		a.logf("%s\n", indent(out))
	}
	return out, true
}

// lineBuffer releases streamed text one complete line at a time, after the
// line passes check (the spillage guard). A withheld line is replaced.
type lineBuffer struct {
	emit  func(string)
	check func(string) bool // true = withhold
	buf   strings.Builder
}

func (b *lineBuffer) write(s string) {
	for {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			b.buf.WriteString(s)
			return
		}
		b.buf.WriteString(s[:i+1])
		b.release()
		s = s[i+1:]
	}
}

func (b *lineBuffer) release() {
	line := b.buf.String()
	b.buf.Reset()
	if line == "" {
		return
	}
	if b.check(line) {
		b.emit("[withheld: classification marking above repository level]\n")
		return
	}
	b.emit(line)
}

func (b *lineBuffer) flush() {
	if b.buf.Len() > 0 {
		b.buf.WriteByte('\n')
		b.release()
	}
}

func stripThinking(s string) string {
	for {
		i := strings.Index(s, "<think>")
		if i < 0 {
			return s
		}
		j := strings.Index(s[i:], "</think>")
		if j < 0 {
			return s[:i]
		}
		s = s[:i] + s[i+j+len("</think>"):]
	}
}

func brief(args map[string]any) string {
	var parts []string
	for _, k := range []string{"path", "pattern", "command", "glob", "offset"} {
		if v, ok := args[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, " ")
}

func firstLine(s string) string { l, _, _ := strings.Cut(s, "\n"); return l }

func indent(s string) string {
	s = strings.TrimRight(s, "\n")
	if len(s) > 1500 {
		s = s[:1500] + "\n…"
	}
	return "    " + strings.ReplaceAll(s, "\n", "\n    ")
}

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
}

// Metrics are what the Phase 1 tool-call eval measures.
type Metrics struct {
	Turns            int            `json:"turns"`
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
	Backend llm.Backend
	Tools   *tools.Set
	Rec     Recorder
	Cfg     Config
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
	specs := a.Tools.Specs()
	specByName := map[string]llm.ToolSpec{}
	for _, s := range specs {
		specByName[s.Name] = s
	}
	opts := a.Backend.Options()
	msgs := []llm.Message{
		{Role: llm.RoleSystem, Content: systemPrompt},
		{Role: llm.RoleUser, Content: taskPrompt(task, rc)},
	}
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
		resp, err := a.Backend.Chat(ctx, fitted, specs)
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
		if strings.TrimSpace(content) != "" {
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
				llm.Message{Role: llm.RoleUser, Content: "You did not call a tool. Continue the task by calling a tool now. If the task is complete and tests pass, call finish."})
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

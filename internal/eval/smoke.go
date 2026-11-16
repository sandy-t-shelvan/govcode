package eval

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
)

// Smoke sends one request that should produce exactly one read_file call.
// It reports whether the server returned a structured call or text that
// needed the fallback parser, which tells you whether the server's tool
// template / --tool-call-parser is configured correctly.
func Smoke(ctx context.Context, b llm.Backend, w io.Writer) error {
	spec := llm.ToolSpec{Name: "read_file", Description: "Read a file", Properties: map[string]llm.Property{
		"path": {Type: "string", Description: "file path"}}, Required: []string{"path"}}
	msgs := []llm.Message{
		{Role: llm.RoleSystem, Content: "You are a coding agent. Use tools."},
		{Role: llm.RoleUser, Content: "Read the file src/PAYROLL.cbl."},
	}
	t0 := time.Now()
	r, err := b.Chat(ctx, msgs, []llm.ToolSpec{spec})
	if err != nil {
		return err
	}
	calls := r.ToolCalls
	if len(calls) == 0 {
		calls, _ = llm.ExtractToolCalls(r.Content, []llm.ToolSpec{spec})
	}
	fmt.Fprintf(w, "model %s num_ctx=%d  %.1fs  prompt=%d out=%d tokens\n", b.ModelName(), b.Options().NumCtx, time.Since(t0).Seconds(), r.Usage.PromptTokens, r.Usage.CompletionTokens)
	if len(calls) == 0 {
		fmt.Fprintf(w, "FAIL: no tool call. Raw content:\n%s\n", r.Content)
		return fmt.Errorf("model did not call a tool")
	}
	c := calls[0]
	_, verr := llm.ValidateArgs(spec, c.Args)
	fmt.Fprintf(w, "tool call: %s %s  parsed=%s  schema-valid=%v\n", c.Name, c.Args, c.Source, verr == nil)
	if c.Source != llm.SourceNative {
		fmt.Fprintln(w, "note: the server returned the call as text; govcode recovered it, but check the Modelfile TEMPLATE / vLLM --tool-call-parser")
	}
	if verr != nil || c.Name != "read_file" {
		return fmt.Errorf("unexpected call")
	}
	fmt.Fprintln(w, "PASS")
	return nil
}

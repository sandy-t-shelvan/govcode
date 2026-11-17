package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/sandy-t-shelvan/govcode/internal/netguard"
)

// Ollama uses the native /api/chat endpoint so num_ctx is applied on every
// request (Ollama's OpenAI-compatible /v1 endpoint ignores it and silently
// falls back to the server default, typically 2048-4096 tokens, which
// truncates the system prompt and tool schemas).
type Ollama struct {
	BaseURL string
	Model   string
	Opts    Options
	client  *http.Client
}

func NewOllama(baseURL, model string, opts Options) (*Ollama, error) {
	if err := netguard.CheckURL(baseURL); err != nil {
		return nil, err
	}
	if opts.NumCtx <= 0 {
		return nil, fmt.Errorf("ollama: num_ctx must be set explicitly")
	}
	return &Ollama{BaseURL: strings.TrimRight(baseURL, "/"), Model: model, Opts: opts, client: netguard.Client(0)}, nil
}

func (o *Ollama) Options() Options  { return o.Opts }
func (o *Ollama) ModelName() string { return o.Model }

type ollamaToolCall struct {
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type ollamaMsg struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
	ToolName  string           `json:"tool_name,omitempty"`
}

func (o *Ollama) Chat(ctx context.Context, msgs []Message, tools []ToolSpec) (*Response, error) {
	body := o.body(msgs, tools)
	return o.chat(ctx, body)
}

// body builds the /api/chat request; num_ctx is always set explicitly.
func (o *Ollama) body(msgs []Message, tools []ToolSpec) map[string]any {
	msgs = withToolPrompt(msgs, tools, o.Opts.ToolPrompt)
	om := make([]ollamaMsg, 0, len(msgs))
	for _, m := range msgs {
		x := ollamaMsg{Role: m.Role, Content: m.Content, ToolName: m.ToolName}
		for _, tc := range m.ToolCalls {
			var c ollamaToolCall
			c.Function.Name = tc.Name
			c.Function.Arguments = tc.Args
			x.ToolCalls = append(x.ToolCalls, c)
		}
		om = append(om, x)
	}
	var ts []map[string]any
	for _, t := range tools {
		ts = append(ts, map[string]any{"type": "function", "function": map[string]any{
			"name": t.Name, "description": t.Description, "parameters": t.schema()}})
	}
	body := map[string]any{
		"model":    o.Model,
		"messages": om,
		"stream":   false,
		"options": map[string]any{
			"num_ctx":     o.Opts.NumCtx,
			"num_predict": o.Opts.MaxTokens,
			"temperature": o.Opts.Temperature,
			"seed":        o.Opts.Seed,
		},
	}
	if len(ts) > 0 {
		body["tools"] = ts
	}
	return body
}

func (o *Ollama) chat(ctx context.Context, body map[string]any) (*Response, error) {
	var out struct {
		Message         ollamaMsg `json:"message"`
		PromptEvalCount int       `json:"prompt_eval_count"`
		EvalCount       int       `json:"eval_count"`
		DoneReason      string    `json:"done_reason"`
		Error           string    `json:"error"`
	}
	if err := postJSON(ctx, o.client, o.BaseURL+"/api/chat", body, &out); err != nil {
		return nil, err
	}
	if out.Error != "" {
		return nil, fmt.Errorf("ollama: %s", out.Error)
	}
	r := &Response{
		Content:      out.Message.Content,
		Usage:        Usage{PromptTokens: out.PromptEvalCount, CompletionTokens: out.EvalCount},
		FinishReason: out.DoneReason,
	}
	for i, tc := range out.Message.ToolCalls {
		r.ToolCalls = append(r.ToolCalls, ToolCall{
			ID: fmt.Sprintf("call_%d", i), Name: tc.Function.Name, Args: normalizeArgs(tc.Function.Arguments), Source: SourceNative})
	}
	return r, nil
}

// OllamaModel is an entry from /api/tags.
type OllamaModel struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// ListOllamaModels returns installed models and their manifest digests, used
// to check the served model against the signed lock file.
func ListOllamaModels(ctx context.Context, baseURL string) ([]OllamaModel, error) {
	if err := netguard.CheckURL(baseURL); err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/api/tags", nil)
	resp, err := netguard.Client(0).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Models []OllamaModel `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Models, nil
}

func postJSON(ctx context.Context, c *http.Client, url string, in any, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("model server %s: HTTP %d: %s", url, resp.StatusCode, truncate(string(data), 500))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("model server: bad JSON: %w: %s", err, truncate(string(data), 200))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

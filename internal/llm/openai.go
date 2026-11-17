package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/sandy-t-shelvan/govcode/internal/netguard"
)

// OpenAICompat talks to vLLM or llama.cpp llama-server. The context length is
// fixed server-side (vLLM --max-model-len, llama-server -c); NumCtx here must
// match it and is used for prompt budgeting.
type OpenAICompat struct {
	BaseURL string // e.g. http://127.0.0.1:8000/v1
	Model   string
	Opts    Options
	client  *http.Client
}

func NewOpenAICompat(baseURL, model string, opts Options) (*OpenAICompat, error) {
	if err := netguard.CheckURL(baseURL); err != nil {
		return nil, err
	}
	if opts.NumCtx <= 0 {
		return nil, fmt.Errorf("openai-compat: num_ctx must be set explicitly (match --max-model-len / -c)")
	}
	return &OpenAICompat{BaseURL: strings.TrimRight(baseURL, "/"), Model: model, Opts: opts, client: netguard.Client(0)}, nil
}

func (o *OpenAICompat) Options() Options  { return o.Opts }
func (o *OpenAICompat) ModelName() string { return o.Model }

type oaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaiMsg struct {
	Role       string        `json:"role"`
	Content    *string       `json:"content"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

func (o *OpenAICompat) Chat(ctx context.Context, msgs []Message, tools []ToolSpec) (*Response, error) {
	return o.chat(ctx, o.body(msgs, tools))
}

func (o *OpenAICompat) body(msgs []Message, tools []ToolSpec) map[string]any {
	msgs = withToolPrompt(msgs, tools, o.Opts.ToolPrompt)
	om := make([]oaiMsg, 0, len(msgs))
	for _, m := range msgs {
		content := m.Content
		x := oaiMsg{Role: m.Role, Content: &content, ToolCallID: m.ToolCallID}
		for _, tc := range m.ToolCalls {
			c := oaiToolCall{ID: tc.ID, Type: "function"}
			c.Function.Name = tc.Name
			c.Function.Arguments = string(tc.Args)
			x.ToolCalls = append(x.ToolCalls, c)
		}
		om = append(om, x)
	}
	body := map[string]any{
		"model":       o.Model,
		"messages":    om,
		"stream":      false,
		"max_tokens":  o.Opts.MaxTokens,
		"temperature": o.Opts.Temperature,
		"seed":        o.Opts.Seed,
	}
	if len(tools) > 0 {
		var ts []map[string]any
		for _, t := range tools {
			ts = append(ts, map[string]any{"type": "function", "function": map[string]any{
				"name": t.Name, "description": t.Description, "parameters": t.schema()}})
		}
		body["tools"] = ts
		body["tool_choice"] = "auto"
	}
	return body
}

// oaiChatResponse is a non-streamed /chat/completions reply.
type oaiChatResponse struct {
	Choices []struct {
		Message struct {
			Content          *string       `json:"content"`
			ReasoningContent *string       `json:"reasoning_content"`
			ToolCalls        []oaiToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage Usage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (o *OpenAICompat) chat(ctx context.Context, body map[string]any) (*Response, error) {
	var out oaiChatResponse
	if err := postJSON(ctx, o.client, o.BaseURL+"/chat/completions", body, &out); err != nil {
		return nil, err
	}
	return out.response()
}

func (out *oaiChatResponse) response() (*Response, error) {
	if out.Error != nil {
		return nil, fmt.Errorf("model server: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("model server returned no choices")
	}
	ch := out.Choices[0]
	r := &Response{Usage: out.Usage, FinishReason: ch.FinishReason}
	if ch.Message.Content != nil {
		r.Content = *ch.Message.Content
	}
	for i, tc := range ch.Message.ToolCalls {
		id := tc.ID
		if id == "" {
			id = fmt.Sprintf("call_%d", i)
		}
		r.ToolCalls = append(r.ToolCalls, ToolCall{ID: id, Name: tc.Function.Name,
			Args: normalizeArgs(json.RawMessage(tc.Function.Arguments)), Source: SourceNative})
	}
	return r, nil
}

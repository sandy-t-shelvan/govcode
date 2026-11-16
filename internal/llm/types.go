// Package llm talks to a locally served open-weight model. Two wire
// protocols are supported: Ollama's native /api/chat (which, unlike its /v1
// shim, honors options.num_ctx per request) and the OpenAI-compatible
// /v1/chat/completions served by vLLM and llama.cpp's llama-server.
package llm

import (
	"context"
	"encoding/json"
)

const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// Parse sources recorded on every tool call, used by the eval metrics.
const (
	SourceNative  = "native"
	SourceQwenXML = "fallback-qwen-xml"
	SourceHermes  = "fallback-hermes"
	SourceMistral = "fallback-mistral"
	SourceJSON    = "fallback-json"
)

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolName   string     `json:"tool_name,omitempty"`
}

type ToolCall struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Args   json.RawMessage `json:"args"`
	Source string          `json:"source"`
}

// Property is the subset of JSON Schema that tool parameters use.
type Property struct {
	Type        string    `json:"type"`
	Description string    `json:"description,omitempty"`
	Items       *Property `json:"items,omitempty"`
	Enum        []string  `json:"enum,omitempty"`
}

type ToolSpec struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Properties  map[string]Property `json:"properties"`
	Required    []string            `json:"required"`
}

func (t ToolSpec) schema() map[string]any {
	props := map[string]any{}
	for k, p := range t.Properties {
		props[k] = p
	}
	req := t.Required
	if req == nil {
		req = []string{}
	}
	return map[string]any{"type": "object", "properties": props, "required": req}
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

type Response struct {
	Content      string     `json:"content"`
	ToolCalls    []ToolCall `json:"tool_calls"`
	Usage        Usage      `json:"usage"`
	FinishReason string     `json:"finish_reason"`
}

// Options are generation settings sent on every request.
type Options struct {
	NumCtx      int     `json:"num_ctx"`
	MaxTokens   int     `json:"max_tokens"`
	Temperature float64 `json:"temperature"`
	Seed        int     `json:"seed"`
}

type Backend interface {
	Chat(ctx context.Context, msgs []Message, tools []ToolSpec) (*Response, error)
	Options() Options
	ModelName() string
}

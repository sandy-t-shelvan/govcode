// Package llm talks to a locally served open-weight model. Two wire
// protocols are supported: Ollama's native /api/chat (which, unlike its /v1
// shim, honors options.num_ctx per request) and the OpenAI-compatible
// /v1/chat/completions served by vLLM and llama.cpp's llama-server.
package llm

import (
	"context"
	"encoding/json"
	"strings"
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
	SourceGranite = "fallback-granite"
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
	// ToolPrompt is appended to the system message whenever tools are
	// offered. Some chat templates (Granite's, for one) only tell the model
	// how to call tools when the caller sends no system message of its own;
	// this restores that instruction. It comes from the signed model lock.
	ToolPrompt string `json:"tool_prompt,omitempty"`
}

// withToolPrompt returns msgs with prompt appended to the first system
// message when tools are offered. msgs is not modified.
func withToolPrompt(msgs []Message, tools []ToolSpec, prompt string) []Message {
	if prompt == "" || len(tools) == 0 {
		return msgs
	}
	out := append([]Message(nil), msgs...)
	for i := range out {
		if out[i].Role == RoleSystem {
			out[i].Content = strings.TrimRight(out[i].Content, "\n") + "\n\n" + prompt
			return out
		}
	}
	return append([]Message{{Role: RoleSystem, Content: prompt}}, out...)
}

type Backend interface {
	Chat(ctx context.Context, msgs []Message, tools []ToolSpec) (*Response, error)
	Options() Options
	ModelName() string
}

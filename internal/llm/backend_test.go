package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOllamaSendsNumCtxEveryRequest(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("path %s, want /api/chat (the /v1 shim ignores num_ctx)", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		io.WriteString(w, `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"read_file","arguments":{"path":"a.c"}}}]},"prompt_eval_count":120,"eval_count":9,"done_reason":"stop"}`)
	}))
	defer srv.Close()
	o, err := NewOllama(srv.URL, "govcode-qwen3-coder", Options{NumCtx: 32768, MaxTokens: 4096, Temperature: 0.2})
	if err != nil {
		t.Fatal(err)
	}
	r, err := o.Chat(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, testTools)
	if err != nil {
		t.Fatal(err)
	}
	opts := got["options"].(map[string]any)
	if opts["num_ctx"] != float64(32768) {
		t.Errorf("num_ctx = %v", opts["num_ctx"])
	}
	if got["stream"] != false {
		t.Error("stream should be false")
	}
	if len(r.ToolCalls) != 1 || r.ToolCalls[0].Source != SourceNative || string(r.ToolCalls[0].Args) != `{"path":"a.c"}` {
		t.Errorf("tool calls %+v", r.ToolCalls)
	}
	if r.Usage.PromptTokens != 120 {
		t.Errorf("usage %+v", r.Usage)
	}
}

func TestNumCtxRequired(t *testing.T) {
	if _, err := NewOllama("http://127.0.0.1:11434", "m", Options{}); err == nil {
		t.Error("ollama without num_ctx accepted")
	}
	if _, err := NewOpenAICompat("http://127.0.0.1:8000/v1", "m", Options{}); err == nil {
		t.Error("openai-compat without num_ctx accepted")
	}
}

func TestRemoteEndpointRejected(t *testing.T) {
	if _, err := NewOllama("http://10.1.1.1:11434", "m", Options{NumCtx: 8192}); err == nil {
		t.Error("non-loopback ollama accepted")
	}
	if _, err := NewOpenAICompat("https://api.openai.com/v1", "m", Options{NumCtx: 8192}); err == nil {
		t.Error("cloud endpoint accepted")
	}
}

func TestOpenAICompatDoubleEncodedArgs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"message":{"content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"path\": \"x.adb\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`)
	}))
	defer srv.Close()
	o, _ := NewOpenAICompat(srv.URL+"/v1", "qwen3-coder", Options{NumCtx: 32768, MaxTokens: 1024})
	r, err := o.Chat(context.Background(), nil, testTools)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.ToolCalls) != 1 || string(r.ToolCalls[0].Args) != `{"path": "x.adb"}` {
		t.Errorf("%+v", r.ToolCalls)
	}
}

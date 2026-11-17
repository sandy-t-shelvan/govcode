package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOllamaStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["stream"] != true || body["options"].(map[string]any)["num_ctx"] != float64(32768) {
			t.Errorf("request %v", body)
		}
		for _, c := range []string{"Reading ", "the file.\n"} {
			io.WriteString(w, `{"message":{"role":"assistant","content":`+mustQ(c)+`},"done":false}`+"\n")
		}
		io.WriteString(w, `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"read_file","arguments":{"path":"a.c"}}}]},"done":false}`+"\n")
		io.WriteString(w, `{"message":{"role":"assistant","content":""},"done":true,"done_reason":"stop","prompt_eval_count":50,"eval_count":7}`+"\n")
	}))
	defer srv.Close()
	o, _ := NewOllama(srv.URL, "m", Options{NumCtx: 32768, MaxTokens: 100})
	var deltas []string
	r, err := o.ChatStream(context.Background(), nil, testTools, func(s string) { deltas = append(deltas, s) })
	if err != nil {
		t.Fatal(err)
	}
	if r.Content != "Reading the file.\n" || len(deltas) != 2 || len(r.ToolCalls) != 1 || string(r.ToolCalls[0].Args) != `{"path":"a.c"}` || r.Usage.CompletionTokens != 7 {
		t.Fatalf("%+v deltas=%q", r, deltas)
	}
}

func TestOpenAIStreamAssemblesToolCallFragments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ev := func(s string) { io.WriteString(w, "data: "+s+"\n\n") }
		ev(`{"choices":[{"delta":{"content":"Let me "}}]}`)
		ev(`{"choices":[{"delta":{"content":"edit."}}]}`)
		ev(`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"edit_","arguments":"{\"path\":"}}]}}]}`)
		ev(`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"file","arguments":"\"x.adb\",\"old_text\":\"a\","}}]}}]}`)
		ev(`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"new_text\":\"b\"}"}},{"index":1,"id":"c2","function":{"name":"run_tests","arguments":"{}"}}]}}]}`)
		ev(`{"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":9,"completion_tokens":4}}`)
		ev(`[DONE]`)
	}))
	defer srv.Close()
	o, _ := NewOpenAICompat(srv.URL+"/v1", "m", Options{NumCtx: 8192, MaxTokens: 100})
	var got strings.Builder
	r, err := o.ChatStream(context.Background(), nil, nil, func(s string) { got.WriteString(s) })
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "Let me edit." || r.Content != "Let me edit." {
		t.Fatalf("content %q", got.String())
	}
	if len(r.ToolCalls) != 2 || r.ToolCalls[0].Name != "edit_file" || r.ToolCalls[0].ID != "c1" || r.ToolCalls[1].Name != "run_tests" {
		t.Fatalf("calls %+v", r.ToolCalls)
	}
	var a map[string]string
	json.Unmarshal(r.ToolCalls[0].Args, &a)
	if a["path"] != "x.adb" || a["new_text"] != "b" || r.Usage.PromptTokens != 9 || r.FinishReason != "tool_calls" {
		t.Fatalf("args %v usage %+v", a, r.Usage)
	}
}

func TestStreamHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "model not loaded", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	o, _ := NewOllama(srv.URL, "m", Options{NumCtx: 4096})
	if _, err := o.ChatStream(context.Background(), nil, nil, nil); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err %v", err)
	}
}

func mustQ(s string) string { b, _ := json.Marshal(s); return string(b) }

// A server that ignores stream=true and answers with one ordinary JSON reply
// (scripts/e2e/fake_model.py, some proxies) must still yield its tool calls,
// not an empty turn that ends the run as "no tool call".
func TestOpenAIStreamAcceptsNonStreamedReply(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"Reading.","tool_calls":[{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"track.c\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":12,"completion_tokens":3}}`)
	}))
	defer srv.Close()
	o, _ := NewOpenAICompat(srv.URL+"/v1", "m", Options{NumCtx: 8192, MaxTokens: 100})
	var got strings.Builder
	r, err := o.ChatStream(context.Background(), nil, testTools, func(s string) { got.WriteString(s) })
	if err != nil {
		t.Fatal(err)
	}
	if len(r.ToolCalls) != 1 || r.ToolCalls[0].Name != "read_file" || string(r.ToolCalls[0].Args) != `{"path":"track.c"}` {
		t.Fatalf("calls %+v", r.ToolCalls)
	}
	if r.Content != "Reading." || got.String() != "Reading." || r.Usage.PromptTokens != 12 || r.FinishReason != "tool_calls" {
		t.Fatalf("%+v delta=%q", r, got.String())
	}
}

func TestOpenAIStreamEmptyOrGarbageIsAnError(t *testing.T) {
	for name, body := range map[string]string{
		"empty":    "",
		"comments": ": keep-alive\n\n",
		"html":     "<html>proxy error</html>",
		"error":    `{"error":{"message":"model not loaded"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
			defer srv.Close()
			o, _ := NewOpenAICompat(srv.URL+"/v1", "m", Options{NumCtx: 8192, MaxTokens: 100})
			if r, err := o.ChatStream(context.Background(), nil, testTools, nil); err == nil {
				t.Fatalf("no error; response %+v", r)
			}
		})
	}
}

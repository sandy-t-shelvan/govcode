package llm

import (
	"encoding/json"
	"testing"
)

// Model output is untrusted. These fuzzers assert the parsers never panic
// and that whatever they return is well-formed.

func FuzzExtractToolCalls(f *testing.F) {
	for _, s := range []string{
		"<tool_call>\n<function=read_file>\n<parameter=path>\na.c\n</parameter>\n</function>\n</tool_call>",
		`<tool_call>{"name":"read_file","arguments":{"path":"a"}}</tool_call>`,
		`[TOOL_CALLS][{"name":"read_file","arguments":{"path":"a"}}]`,
		`[TOOL_CALLS]read_file[ARGS]{"path":"a"}`,
		"```json\n{\"name\":\"read_file\",\"arguments\":{}}\n```",
		"<function=", "[TOOL_CALLS]", "<tool_call>", "{", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		calls, _ := ExtractToolCalls(s, testTools)
		for _, c := range calls {
			if c.Name == "" {
				t.Fatalf("call with empty name from %q", s)
			}
			if !json.Valid(c.Args) {
				t.Fatalf("invalid args JSON %q from %q", c.Args, s)
			}
			_, _ = ValidateArgs(testTools[0], c.Args)
		}
	})
}

func FuzzRepairJSON(f *testing.F) {
	for _, s := range []string{`{"a":1,}`, `{"a":"b"`, "```json\n{}\n```", `x {"a":[1,2,`, `"\u`, `{"a":"\"}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := RepairJSON(s)
		if out != s && !json.Valid([]byte(out)) {
			t.Fatalf("RepairJSON(%q) = %q: changed input but result is invalid JSON", s, out)
		}
	})
}

func FuzzValidateArgs(f *testing.F) {
	for _, s := range []string{`{"path":"a","offset":"3"}`, `{"path":1}`, `[]`, `null`, `{"limit":1e400}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, spec := range testTools {
			args, err := ValidateArgs(spec, json.RawMessage(s))
			if err == nil {
				for _, r := range spec.Required {
					if _, ok := args[r]; !ok {
						t.Fatalf("validated args missing required %q: %q", r, s)
					}
				}
				if _, err := json.Marshal(args); err != nil {
					t.Fatalf("validated args not marshalable: %v", err)
				}
			}
		}
	})
}

// A model server's reply to a streaming request is untrusted: whatever it
// sends, the non-stream fallback must not panic, and a reply it accepts must
// carry well-formed tool calls.
func FuzzNonStreamReply(f *testing.F) {
	for _, s := range []string{
		`{"choices":[{"message":{"content":"x","tool_calls":[{"id":"c","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a\"}"}}]},"finish_reason":"tool_calls"}]}`,
		`{"choices":[]}`, `{"error":{"message":"m"}}`, `{"choices":[{"message":{"tool_calls":[{"function":{"arguments":"not json"}}]}}]}`,
		": ping", "<html>", "{", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := nonStreamReply(s, func(string) {})
		if err != nil {
			return
		}
		if r == nil {
			t.Fatal("nil response without error")
		}
		for _, c := range r.ToolCalls {
			if !json.Valid(c.Args) {
				t.Fatalf("invalid args JSON %q from %q", c.Args, s)
			}
		}
	})
}

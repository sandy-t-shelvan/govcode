package llm

import (
	"encoding/json"
	"testing"
)

var testTools = []ToolSpec{
	{Name: "read_file", Properties: map[string]Property{
		"path": {Type: "string"}, "offset": {Type: "integer"}, "limit": {Type: "integer"}}, Required: []string{"path"}},
	{Name: "edit_file", Properties: map[string]Property{
		"path": {Type: "string"}, "old_text": {Type: "string"}, "new_text": {Type: "string"}}, Required: []string{"path", "old_text", "new_text"}},
}

func args(t *testing.T, c ToolCall) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(c.Args, &m); err != nil {
		t.Fatalf("args not JSON: %s", c.Args)
	}
	return m
}

func TestQwenXML(t *testing.T) {
	in := "I'll fix the column.\n<tool_call>\n<function=edit_file>\n<parameter=path>\nsrc/PAYROLL.cbl\n</parameter>\n<parameter=old_text>\n       01 WS-RATE  PIC 9V99.\n</parameter>\n<parameter=new_text>\n       01 WS-RATE  PIC 9V9999.\n</parameter>\n</function>\n</tool_call>"
	calls, rest := ExtractToolCalls(in, testTools)
	if len(calls) != 1 || calls[0].Name != "edit_file" || calls[0].Source != SourceQwenXML {
		t.Fatalf("got %+v", calls)
	}
	a := args(t, calls[0])
	// COBOL area A indentation (7 spaces) must survive exactly.
	if a["old_text"] != "       01 WS-RATE  PIC 9V99." {
		t.Errorf("old_text = %q", a["old_text"])
	}
	if rest != "I'll fix the column." {
		t.Errorf("rest = %q", rest)
	}
}

func TestQwenXMLIntegerCoercion(t *testing.T) {
	in := "<tool_call><function=read_file><parameter=path>a.c</parameter><parameter=offset>40</parameter></function></tool_call>"
	calls, _ := ExtractToolCalls(in, testTools)
	if len(calls) != 1 {
		t.Fatal("no call")
	}
	if a := args(t, calls[0]); a["offset"] != float64(40) {
		t.Errorf("offset = %#v", a["offset"])
	}
}

func TestHermes(t *testing.T) {
	in := `<tool_call>
{"name": "read_file", "arguments": {"path": "main.c",}}
</tool_call>`
	calls, _ := ExtractToolCalls(in, testTools)
	if len(calls) != 1 || calls[0].Source != SourceHermes || args(t, calls[0])["path"] != "main.c" {
		t.Fatalf("got %+v", calls)
	}
}

func TestMistralArray(t *testing.T) {
	in := `Let me look. [TOOL_CALLS][{"name": "read_file", "arguments": {"path": "pkg.adb"}}, {"name":"read_file","arguments":{"path":"pkg.ads"}}]`
	calls, rest := ExtractToolCalls(in, testTools)
	if len(calls) != 2 || calls[1].Source != SourceMistral || rest != "Let me look." {
		t.Fatalf("got %+v rest=%q", calls, rest)
	}
}

func TestMistralV11(t *testing.T) {
	in := `[TOOL_CALLS]read_file[ARGS]{"path": "x.f90"}`
	calls, _ := ExtractToolCalls(in, testTools)
	if len(calls) != 1 || args(t, calls[0])["path"] != "x.f90" {
		t.Fatalf("got %+v", calls)
	}
}

func TestJSONFenceOnlyKnownTools(t *testing.T) {
	in := "Example config:\n```json\n{\"name\": \"server\", \"arguments\": {}}\n```\nNow:\n```json\n{\"name\": \"read_file\", \"arguments\": {\"path\": \"a.c\"}}\n```"
	calls, _ := ExtractToolCalls(in, testTools)
	if len(calls) != 1 || calls[0].Name != "read_file" {
		t.Fatalf("got %+v", calls)
	}
}

func TestPlainTextNoCalls(t *testing.T) {
	calls, rest := ExtractToolCalls("The bug is on line 12.", testTools)
	if len(calls) != 0 || rest != "The bug is on line 12." {
		t.Fatal("false positive")
	}
}

func TestNormalizeArgs(t *testing.T) {
	cases := map[string]string{
		`"{\"path\":\"a\"}"`: `{"path":"a"}`,
		``:                   `{}`,
		`{"path":"a",}`:      `{"path":"a"}`,
		`{"path":"a"`:        `{"path":"a"}`,
	}
	for in, want := range cases {
		if got := string(normalizeArgs(json.RawMessage(in))); got != want {
			t.Errorf("normalizeArgs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateArgs(t *testing.T) {
	spec := testTools[0]
	a, err := ValidateArgs(spec, json.RawMessage(`{"path":"a.c","offset":"10","explanation":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if a["offset"] != 10 {
		t.Errorf("offset not coerced: %#v", a["offset"])
	}
	if _, ok := a["explanation"]; ok {
		t.Error("unknown key not dropped")
	}
	if _, err := ValidateArgs(spec, json.RawMessage(`{"offset":1}`)); err == nil {
		t.Error("missing required not reported")
	}
	if _, err := ValidateArgs(spec, json.RawMessage(`{"path":"a","limit":"lots"}`)); err == nil {
		t.Error("bad integer not reported")
	}
}

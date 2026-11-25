package llm

import (
	"encoding/json"
	"os"
	"strings"
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

// Captured from Devstral-Small-2507 Q4_K_M on Ollama v0.40.16 with the old
// Modelfile template (GOV-10): Ollama dropped [ARGS] and parsed no call.
func TestMistralV11WithoutArgsMarker(t *testing.T) {
	in := `[TOOL_CALLS]read_file{"path":"main.c"}`
	calls, rest := ExtractToolCalls(in, testTools)
	if len(calls) != 1 || calls[0].Name != "read_file" || calls[0].Source != SourceMistral || args(t, calls[0])["path"] != "main.c" || rest != "" {
		t.Fatalf("got %+v rest=%q", calls, rest)
	}
	// Without [ARGS] an unknown name is not a call.
	if calls, _ := ExtractToolCalls(`[TOOL_CALLS]config{"debug":true}`, testTools); len(calls) != 0 {
		t.Fatalf("unknown tool without [ARGS] accepted: %+v", calls)
	}
	// With [ARGS] the marker itself is explicit, as before.
	if calls, _ := ExtractToolCalls(`[TOOL_CALLS]other_tool[ARGS]{"a":1}`, testTools); len(calls) != 1 {
		t.Fatalf("explicit [ARGS] call dropped: %+v", calls)
	}
}

func TestMistralV11BackToBack(t *testing.T) {
	in := `[TOOL_CALLS]read_file[ARGS]{"path":"a.c"}[TOOL_CALLS]read_file[ARGS]{"path":"b.c"}[TOOL_CALLS]outline[ARGS]{"path":"c.c"}</s>`
	calls, _ := ExtractToolCalls(in, testTools)
	if len(calls) != 3 || args(t, calls[1])["path"] != "b.c" || args(t, calls[2])["path"] != "c.c" {
		t.Fatalf("want 3 calls, got %+v", calls)
	}
}

// An unknown name without [ARGS] must not swallow a real call after it.
func TestMistralV11UnknownBeforeReal(t *testing.T) {
	in := `[TOOL_CALLS]config{"x":1} then [TOOL_CALLS]read_file[ARGS]{"path":"a.c"}`
	calls, _ := ExtractToolCalls(in, testTools)
	if len(calls) != 1 || calls[0].Name != "read_file" || args(t, calls[0])["path"] != "a.c" {
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

// A code fence inside an argument is text. The fence regex used to end the
// block at the first ``` and repair the cut-off object, so an edit whose
// new_text contains a markdown sample was written without that sample.
// A fence that actually ends the JSON string must not be repaired into a
// truncated edit, and must not run the example call that follows it.
// Trailing commas and a prose fence before a real call still parse.
func TestJSONFenceInsideArguments(t *testing.T) {
	tools := append(testTools, ToolSpec{Name: "run_command", Properties: map[string]Property{
		"command": {Type: "string"}}, Required: []string{"command"}})
	newText := "Run it:\n```\nmake test\n```\n\nExample:\n\n```json\n{\"name\":\"run_command\",\"arguments\":{\"command\":\"make\"}}\n```\n"
	argsJSON, err := json.Marshal(map[string]any{"path": "README.md", "old_text": "intro", "new_text": newText})
	if err != nil {
		t.Fatal(err)
	}
	// Models write the name first. json.Marshal of a map would not.
	calls, _ := ExtractToolCalls("```json\n{\"name\":\"edit_file\",\"arguments\":"+string(argsJSON)+"}\n```", tools)
	if len(calls) != 1 || calls[0].Name != "edit_file" {
		t.Fatalf("got %+v", calls)
	}
	if got := args(t, calls[0])["new_text"]; got != newText {
		t.Fatalf("new_text = %q", got)
	}
	// The first fence ends the string, so the object is not JSON. Repairing
	// it used to write new_text "Run it:\n" and drop the rest.
	cut := "```json\n" +
		`{"name":"edit_file","arguments":{"path":"README.md","old_text":"intro","new_text":"Run it:\n` +
		"```\nmake test\n```\n\nExample:\n\n```json\n" +
		`{"name":"run_command","arguments":{"command":"make"}}` +
		"\n```\n\"}}\n```"
	if calls, _ := ExtractToolCalls(cut, tools); len(calls) != 0 {
		t.Fatalf("truncated fence was executed: %+v", calls)
	}
	// A fence the model simply did not finish has no ``` in the argument, so
	// the missing brace is still repaired.
	trunc := "```json\n{\"name\":\"read_file\",\"arguments\":{\"path\":\"a.c\""
	if calls, _ := ExtractToolCalls(trunc, tools); len(calls) != 1 || calls[0].Name != "read_file" || args(t, calls[0])["path"] != "a.c" {
		t.Fatalf("truncated fence: %+v", calls)
	}
	comma := "```json\n{\"name\": \"read_file\", \"arguments\": {\"path\": \"main.c\",}}\n```"
	if calls, _ := ExtractToolCalls(comma, tools); len(calls) != 1 || calls[0].Name != "read_file" {
		t.Fatalf("trailing comma fence: %+v", calls)
	}
	prose := "```\nnot a call\n```\n```json\n{\"name\":\"read_file\",\"arguments\":{\"path\":\"a.c\"}}\n```"
	if calls, _ := ExtractToolCalls(prose, tools); len(calls) != 1 || args(t, calls[0])["path"] != "a.c" {
		t.Fatalf("prose fence then call: %+v", calls)
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

func TestUnparseableArgsReportedToModel(t *testing.T) {
	for _, raw := range []string{`{0}`, `[1,2]`, `"just text"`, `42`} {
		a := normalizeArgs(json.RawMessage(raw))
		if !json.Valid(a) {
			t.Fatalf("normalizeArgs(%q) produced invalid JSON %q", raw, a)
		}
		_, err := ValidateArgs(testTools[0], a)
		if err == nil || !strings.Contains(err.Error(), "not a valid JSON object") {
			t.Errorf("args %q: want unparseable error, got %v", raw, err)
		}
	}
}

func TestGraniteToolCalls(t *testing.T) {
	tools := []ToolSpec{{Name: "read_file"}, {Name: "run_tests"}}
	cases := []struct {
		in    string
		names []string
		rest  string
	}{
		// What llama.cpp returns: the <|tool_call|> special token is stripped.
		{`[{"arguments": {"path": "src/PAYROLL.cbl"}, "name": "read_file"}]`, []string{"read_file"}, ""},
		{"I will read it.\n<|tool_call|>[{\"name\":\"read_file\",\"arguments\":{\"path\":\"a.c\"}},{\"name\":\"run_tests\",\"arguments\":{}}]", []string{"read_file", "run_tests"}, "I will read it."},
		// Unknown tool in a bare list: not a call.
		{`[{"name": "rm_rf", "arguments": {}}]`, nil, ""},
		// Ordinary JSON array in prose is not a call.
		{`[1, 2, 3]`, nil, ""},
		{`The values are [{"name": "read_file"}] in the table.`, nil, ""},
	}
	for _, c := range cases {
		calls, rest := ExtractToolCalls(c.in, tools)
		if len(calls) != len(c.names) {
			t.Fatalf("%q: got %d calls, want %d", c.in, len(calls), len(c.names))
		}
		for i, n := range c.names {
			if calls[i].Name != n || calls[i].Source != SourceGranite {
				t.Errorf("%q: call %d = %s/%s", c.in, i, calls[i].Name, calls[i].Source)
			}
		}
		if len(c.names) > 0 && rest != c.rest {
			t.Errorf("%q: rest %q, want %q", c.in, rest, c.rest)
		}
	}
	calls, _ := ExtractToolCalls(`[{"arguments": {"path": "x.c"}, "name": "read_file"}]`, tools)
	if string(calls[0].Args) != `{"path":"x.c"}` && string(calls[0].Args) != `{"path": "x.c"}` {
		t.Errorf("args %s", calls[0].Args)
	}
}

func TestWithToolPrompt(t *testing.T) {
	msgs := []Message{{Role: RoleSystem, Content: "sys\n"}, {Role: RoleUser, Content: "u"}}
	tools := []ToolSpec{{Name: "read_file"}}
	got := withToolPrompt(msgs, tools, "CALL TOOLS LIKE THIS")
	if got[0].Content != "sys\n\nCALL TOOLS LIKE THIS" || msgs[0].Content != "sys\n" {
		t.Fatalf("got %q, original %q", got[0].Content, msgs[0].Content)
	}
	if g := withToolPrompt(msgs, nil, "X"); g[0].Content != "sys\n" {
		t.Error("prompt added without tools")
	}
	if g := withToolPrompt(msgs[1:], tools, "X"); len(g) != 2 || g[0].Role != RoleSystem || g[0].Content != "X" {
		t.Errorf("no system message: %+v", g)
	}
	// Both backends send it.
	o, err := NewOpenAICompat("http://127.0.0.1:1/v1", "m", Options{NumCtx: 4096, ToolPrompt: "TP"})
	if err != nil {
		t.Fatal(err)
	}
	b := o.body(msgs, tools)
	if m := b["messages"].([]oaiMsg); !strings.HasSuffix(*m[0].Content, "TP") {
		t.Errorf("openai body: %q", *m[0].Content)
	}
	ol, err := NewOllama("http://127.0.0.1:1", "m", Options{NumCtx: 4096, ToolPrompt: "TP"})
	if err != nil {
		t.Fatal(err)
	}
	if m := ol.body(msgs, tools)["messages"].([]ollamaMsg); !strings.HasSuffix(m[0].Content, "TP") {
		t.Errorf("ollama body: %q", m[0].Content)
	}
}

func TestRepairInvalidEscapes(t *testing.T) {
	cases := map[string]string{
		`{"new_text":"buf[0] = '\0';"}`:       `buf[0] = '\0';`,
		`{"new_text":"printf(\"%d\\n\", x)"}`: `printf("%d\n", x)`,
		`{"new_text":"c = '\x41'"}`:           `c = '\x41'`,
		`{"new_text":"é and \uZZ"}`:           `é and \uZZ`,
		`{"new_text":"tab\there"}`:            "tab\there",
	}
	for in, want := range cases {
		var v struct {
			NewText string `json:"new_text"`
		}
		if err := json.Unmarshal([]byte(RepairJSON(in)), &v); err != nil {
			t.Errorf("%s: %v (repaired %s)", in, err, RepairJSON(in))
			continue
		}
		if v.NewText != want {
			t.Errorf("%s: got %q, want %q", in, v.NewText, want)
		}
	}
}

// A real Granite-3.3-8B reply from the GOV-40 air-gapped run: four calls in
// one list, the edit containing C's '\0'. Before the escape repair, the
// whole list failed to parse and no call ran.
func TestGraniteRealMultiCall(t *testing.T) {
	b, err := os.ReadFile("testdata/granite_multi_call.txt")
	if err != nil {
		t.Fatal(err)
	}
	tools := []ToolSpec{{Name: "read_file"}, {Name: "search"}, {Name: "update_plan"}, {Name: "edit_file"}}
	calls, _ := ExtractToolCalls(string(b), tools)
	var names []string
	for _, c := range calls {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "read_file,search,update_plan,edit_file" {
		t.Fatalf("calls %v", names)
	}
	var edit struct {
		NewText string `json:"new_text"`
	}
	json.Unmarshal(calls[3].Args, &edit)
	if !strings.Contains(edit.NewText, `t->callsign[CALLSIGN_LEN - 1] = '\0';`) {
		t.Errorf("new_text lost the C literal: %q", edit.NewText)
	}
}

// A real Granite reply after a no-call nag: an arguments-only object (not a
// call) and then the call as a fenced JSON list. Before, only fenced
// objects were accepted and the edit was dropped.
func TestFencedListRealGranite(t *testing.T) {
	b, err := os.ReadFile("testdata/granite_fenced_list.txt")
	if err != nil {
		t.Fatal(err)
	}
	calls, _ := ExtractToolCalls(string(b), []ToolSpec{{Name: "edit_file"}, {Name: "run_tests"}})
	if len(calls) != 1 || calls[0].Name != "edit_file" || calls[0].Source != SourceJSON {
		t.Fatalf("calls %+v", calls)
	}
	var a struct {
		OldText string `json:"old_text"`
	}
	json.Unmarshal(calls[0].Args, &a)
	if a.OldText != "strcpy(t->callsign, callsign);" {
		t.Errorf("old_text %q", a.OldText)
	}
	// A fenced list with an unknown name is not a call.
	if c, _ := ExtractToolCalls("```json\n[{\"name\":\"edit_file\",\"arguments\":{}},{\"name\":\"rm\",\"arguments\":{}}]\n```", []ToolSpec{{Name: "edit_file"}}); len(c) != 0 {
		t.Errorf("unknown tool in list accepted: %+v", c)
	}
}

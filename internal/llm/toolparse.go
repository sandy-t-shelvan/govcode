package llm

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Local models served without a matching tool-call parser (or quantized
// models that drift from their training format) often write tool calls into
// the text content instead of the structured tool_calls field. ExtractToolCalls
// recovers them. It returns the calls and the content with the call markup
// removed.
//
// Formats handled, in priority order:
//   - Qwen3-Coder XML:  <tool_call><function=NAME><parameter=K>V</parameter></function></tool_call>
//   - Hermes/Qwen2.5:   <tool_call>{"name":..., "arguments":{...}}</tool_call>
//   - Mistral/Devstral: [TOOL_CALLS][{"name":..., "arguments":{...}}]  or  [TOOL_CALLS]NAME[ARGS]{...}
//   - JSON block:       ```json {"name":..., "arguments":{...}} ```  (only if NAME is a known tool)
func ExtractToolCalls(content string, tools []ToolSpec) ([]ToolCall, string) {
	known := map[string]ToolSpec{}
	for _, t := range tools {
		known[t.Name] = t
	}
	if calls, rest := parseQwenXML(content, known); len(calls) > 0 {
		return number(calls), rest
	}
	if calls, rest := parseHermes(content, known); len(calls) > 0 {
		return number(calls), rest
	}
	if calls, rest := parseMistral(content, known); len(calls) > 0 {
		return number(calls), rest
	}
	if calls, rest := parseJSONBlocks(content, known); len(calls) > 0 {
		return number(calls), rest
	}
	return nil, content
}

func number(calls []ToolCall) []ToolCall {
	for i := range calls {
		calls[i].ID = fmt.Sprintf("call_fb_%d", i)
	}
	return calls
}

var (
	reQwenFunc  = regexp.MustCompile(`(?s)<function=([A-Za-z0-9_\-]+)>(.*?)</function>`)
	reQwenParam = regexp.MustCompile(`(?s)<parameter=([A-Za-z0-9_\-]+)>(.*?)</parameter>`)
	reToolCall  = regexp.MustCompile(`(?s)<tool_call>(.*?)(?:</tool_call>|$)`)
)

func parseQwenXML(s string, known map[string]ToolSpec) ([]ToolCall, string) {
	if !strings.Contains(s, "<function=") {
		return nil, s
	}
	var calls []ToolCall
	for _, m := range reQwenFunc.FindAllStringSubmatch(s, -1) {
		name := m[1]
		args := map[string]any{}
		spec := known[name]
		for _, p := range reQwenParam.FindAllStringSubmatch(m[2], -1) {
			args[p[1]] = coerceXMLValue(trimOneNewline(p[2]), spec.Properties[p[1]].Type)
		}
		b, _ := json.Marshal(args)
		calls = append(calls, ToolCall{Name: name, Args: b, Source: SourceQwenXML})
	}
	rest := reToolCall.ReplaceAllString(s, "")
	rest = reQwenFunc.ReplaceAllString(rest, "")
	return calls, strings.TrimSpace(rest)
}

// Qwen3-Coder emits a newline after <parameter=x> and before </parameter>;
// strip exactly one on each side so code values keep their own whitespace.
func trimOneNewline(v string) string {
	v = strings.TrimPrefix(v, "\n")
	v = strings.TrimSuffix(v, "\n")
	return v
}

func coerceXMLValue(v, typ string) any {
	switch typ {
	case "integer":
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	case "number":
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f
		}
	case "boolean":
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	case "array", "object":
		var x any
		if err := json.Unmarshal([]byte(RepairJSON(v)), &x); err == nil {
			return x
		}
	}
	return v
}

type nameArgs struct {
	Name       string          `json:"name"`
	Arguments  json.RawMessage `json:"arguments"`
	Parameters json.RawMessage `json:"parameters"`
}

func (n nameArgs) toCall(src string) ToolCall {
	a := n.Arguments
	if len(a) == 0 {
		a = n.Parameters
	}
	return ToolCall{Name: n.Name, Args: normalizeArgs(a), Source: src}
}

func parseHermes(s string, known map[string]ToolSpec) ([]ToolCall, string) {
	if !strings.Contains(s, "<tool_call>") {
		return nil, s
	}
	var calls []ToolCall
	for _, m := range reToolCall.FindAllStringSubmatch(s, -1) {
		var na nameArgs
		if json.Unmarshal([]byte(RepairJSON(m[1])), &na) == nil && na.Name != "" {
			calls = append(calls, na.toCall(SourceHermes))
		}
	}
	return calls, strings.TrimSpace(reToolCall.ReplaceAllString(s, ""))
}

var reMistralV11 = regexp.MustCompile(`(?s)\[TOOL_CALLS\]\s*([A-Za-z0-9_\-]+)\s*\[ARGS\]\s*(\{.*?\})\s*(?:$|\[TOOL_CALLS\]|</s>)`)

func parseMistral(s string, known map[string]ToolSpec) ([]ToolCall, string) {
	idx := strings.Index(s, "[TOOL_CALLS]")
	if idx < 0 {
		return nil, s
	}
	// Newer tokenizer format: [TOOL_CALLS]name[ARGS]{...}
	if ms := reMistralV11.FindAllStringSubmatch(s, -1); len(ms) > 0 {
		var calls []ToolCall
		for _, m := range ms {
			calls = append(calls, ToolCall{Name: m[1], Args: normalizeArgs(json.RawMessage(m[2])), Source: SourceMistral})
		}
		return calls, strings.TrimSpace(s[:idx])
	}
	payload := RepairJSON(strings.TrimSpace(s[idx+len("[TOOL_CALLS]"):]))
	var arr []nameArgs
	if err := json.Unmarshal([]byte(payload), &arr); err != nil {
		var one nameArgs
		if json.Unmarshal([]byte(payload), &one) != nil || one.Name == "" {
			return nil, s
		}
		arr = []nameArgs{one}
	}
	var calls []ToolCall
	for _, na := range arr {
		if na.Name != "" {
			calls = append(calls, na.toCall(SourceMistral))
		}
	}
	return calls, strings.TrimSpace(s[:idx])
}

var reFence = regexp.MustCompile("(?s)```(?:json|JSON)?\\s*\n(.*?)```")

func parseJSONBlocks(s string, known map[string]ToolSpec) ([]ToolCall, string) {
	var calls []ToolCall
	rest := s
	try := func(raw string) bool {
		var na nameArgs
		if json.Unmarshal([]byte(RepairJSON(raw)), &na) != nil {
			return false
		}
		if _, ok := known[na.Name]; !ok {
			return false
		}
		calls = append(calls, na.toCall(SourceJSON))
		return true
	}
	for _, m := range reFence.FindAllStringSubmatch(s, -1) {
		if try(m[1]) {
			rest = strings.Replace(rest, m[0], "", 1)
		}
	}
	if len(calls) == 0 {
		t := strings.TrimSpace(s)
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") && try(t) {
			rest = ""
		}
	}
	return calls, strings.TrimSpace(rest)
}

// normalizeArgs turns whatever the server returned into a JSON object:
// handles double-encoded strings ("{\"a\":1}"), empty args, and minor syntax
// errors.
func normalizeArgs(raw json.RawMessage) json.RawMessage {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return json.RawMessage("{}")
	}
	if strings.HasPrefix(t, `"`) {
		var inner string
		if json.Unmarshal([]byte(t), &inner) == nil {
			t = strings.TrimSpace(inner)
		}
	}
	if json.Valid([]byte(t)) {
		return json.RawMessage(t)
	}
	return json.RawMessage(RepairJSON(t))
}

var reTrailingComma = regexp.MustCompile(`,\s*([}\]])`)

// RepairJSON fixes the faults local models most often make in JSON:
// surrounding code fences, leading prose, trailing commas, and a missing
// final brace. It returns the input unchanged if repair does not help.
func RepairJSON(s string) string {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(t, "```json")
	t = strings.TrimPrefix(t, "```")
	t = strings.TrimSuffix(t, "```")
	t = strings.TrimSpace(t)
	if json.Valid([]byte(t)) {
		return t
	}
	if i := strings.IndexAny(t, "{["); i > 0 {
		t = t[i:]
	}
	t = reTrailingComma.ReplaceAllString(t, "$1")
	if json.Valid([]byte(t)) {
		return t
	}
	// Close unbalanced braces/brackets (truncated output), outside strings.
	var stack []byte
	inStr, esc := false, false
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '{' || c == '[':
			stack = append(stack, c)
		case (c == '}' || c == ']') && len(stack) > 0:
			stack = stack[:len(stack)-1]
		}
	}
	fixed := t
	if inStr {
		fixed += `"`
	}
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i] == '{' {
			fixed += "}"
		} else {
			fixed += "]"
		}
	}
	if json.Valid([]byte(fixed)) {
		return fixed
	}
	return s
}

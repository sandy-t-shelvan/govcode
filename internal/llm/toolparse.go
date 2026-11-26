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
//   - Granite:          <|tool_call|>[{"name":..., "arguments":{...}}]  (the marker is a special
//     token that servers usually strip, so a bare JSON list is accepted when
//     every NAME is a known tool)
//   - JSON block:       ```json {"name":..., "arguments":{...}} ``` or a fenced list of those
//     (only if every NAME is a known tool)
func ExtractToolCalls(content string, tools []ToolSpec) ([]ToolCall, string) {
	known := map[string]ToolSpec{}
	for _, t := range tools {
		known[t.Name] = t
	}
	// A Qwen reply that contains <function= is handled here even when it
	// yields no call. Falling through would execute a call that was written
	// inside an argument after a tag closed the real one early.
	if calls, rest, ok := parseQwenXML(content, known); ok {
		return number(calls), rest
	}
	if calls, rest := parseHermes(content, known); len(calls) > 0 {
		return number(calls), rest
	}
	if calls, rest := parseMistral(content, known); len(calls) > 0 {
		return number(calls), rest
	}
	if calls, rest := parseGranite(content, known); len(calls) > 0 {
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
	reQwenFunc = regexp.MustCompile(`(?s)<function=([A-Za-z0-9_\-]+)>(.*?)</function>`)
	reToolCall = regexp.MustCompile(`(?s)<tool_call>(.*?)(?:</tool_call>|$)`)
)

// parseQwenXML reads Qwen3-Coder calls. ok is false when s is not this
// format. A function whose body is not a list of unique parameters (a
// </parameter> or <parameter= inside a value, which this format cannot
// escape) is not a call: the text that follows would otherwise be applied
// as a different path or a different tool. ok is still true in that case so
// the caller does not parse the argument again with another format.
func parseQwenXML(s string, known map[string]ToolSpec) (calls []ToolCall, rest string, ok bool) {
	if !strings.Contains(s, "<function=") {
		return nil, s, false
	}
	matches := reQwenFunc.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil, s, false
	}
	for _, m := range matches {
		args, good := qwenParameters(m[2], known[m[1]])
		if !good {
			return nil, s, true
		}
		b, _ := json.Marshal(args)
		calls = append(calls, ToolCall{Name: m[1], Args: b, Source: SourceQwenXML})
	}
	rest = reToolCall.ReplaceAllString(s, "")
	rest = reQwenFunc.ReplaceAllString(rest, "")
	return calls, strings.TrimSpace(rest), true
}

// qwenParameters reads one <function> body. The body must be only
// <parameter=name>value</parameter> elements, separated by whitespace, with
// each name used once. A value is the raw text up to the next </parameter>;
// this format has no escape, so a tag inside the value is the same byte
// sequence as the end of the parameter. That call is refused.
func qwenParameters(body string, spec ToolSpec) (map[string]any, bool) {
	args := map[string]any{}
	s := body
	for {
		s = strings.TrimLeft(s, " \t\r\n")
		if s == "" {
			return args, true
		}
		const open = "<parameter="
		if !strings.HasPrefix(s, open) {
			return nil, false
		}
		name, after, found := strings.Cut(s[len(open):], ">")
		if !found || !qwenName(name) {
			return nil, false
		}
		if _, dup := args[name]; dup {
			return nil, false
		}
		val, rest, found := strings.Cut(after, "</parameter>")
		if !found || strings.Contains(val, "<parameter=") {
			return nil, false
		}
		typ := ""
		if spec.Properties != nil {
			typ = spec.Properties[name].Type
		}
		args[name] = coerceXMLValue(trimOneNewline(val), typ)
		s = rest
	}
}

func qwenName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
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

// One v11 call per [TOOL_CALLS] segment: name, then [ARGS], then a JSON object.
// [ARGS] is optional: Ollama strips it as a control token but can leave
// [TOOL_CALLS] in the text (captured from Devstral-Small-2507 on Ollama
// v0.40.16, GOV-10). Without [ARGS] the name must be a known tool.
// Splitting on the marker first keeps one call's match from running into
// the next, so back-to-back calls are all returned.
var reMistralV11Seg = regexp.MustCompile(`(?s)^\s*([A-Za-z0-9_\-]+)\s*(\[ARGS\])?\s*(\{.*\})\s*(?:</s>)?\s*$`)

func parseMistral(s string, known map[string]ToolSpec) ([]ToolCall, string) {
	idx := strings.Index(s, "[TOOL_CALLS]")
	if idx < 0 {
		return nil, s
	}
	// Newer tokenizer format: [TOOL_CALLS]name[ARGS]{...}[TOOL_CALLS]...
	var v11 []ToolCall
	for _, seg := range strings.Split(s[idx+len("[TOOL_CALLS]"):], "[TOOL_CALLS]") {
		m := reMistralV11Seg.FindStringSubmatch(seg)
		if m == nil {
			continue
		}
		if _, ok := known[m[1]]; m[2] == "" && !ok {
			continue
		}
		v11 = append(v11, ToolCall{Name: m[1], Args: normalizeArgs(json.RawMessage(m[3])), Source: SourceMistral})
	}
	if len(v11) > 0 {
		return v11, strings.TrimSpace(s[:idx])
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

const graniteMarker = "<|tool_call|>"

// parseGranite reads Granite's tool-call list. Without the marker, the
// content must be nothing but the list and every name a known tool, so that
// ordinary JSON in a reply is not mistaken for a call.
func parseGranite(s string, known map[string]ToolSpec) ([]ToolCall, string) {
	t, before := strings.TrimSpace(s), ""
	if i := strings.Index(t, graniteMarker); i >= 0 {
		before, t = strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+len(graniteMarker):])
	} else if !strings.HasPrefix(t, "[") || !strings.HasSuffix(t, "]") {
		return nil, s
	}
	var arr []nameArgs
	if json.Unmarshal([]byte(RepairJSON(t)), &arr) != nil || len(arr) == 0 {
		return nil, s
	}
	var calls []ToolCall
	for _, na := range arr {
		if _, ok := known[na.Name]; !ok {
			return nil, s
		}
		calls = append(calls, na.toCall(SourceGranite))
	}
	return calls, before
}

var reFence = regexp.MustCompile("(?s)```(?:json|JSON)?\\s*\n(.*?)```")

func parseJSONBlocks(s string, known map[string]ToolSpec) ([]ToolCall, string) {
	var calls []ToolCall
	rest := s
	try := func(raw string) bool {
		fixed := RepairJSON(raw)
		// A list of calls (Granite and others write one when they fall back
		// to a code fence): every element must name a known tool.
		if strings.HasPrefix(strings.TrimSpace(fixed), "[") {
			var arr []nameArgs
			if json.Unmarshal([]byte(fixed), &arr) != nil || len(arr) == 0 {
				return false
			}
			for _, na := range arr {
				if _, ok := known[na.Name]; !ok {
					return false
				}
			}
			for _, na := range arr {
				calls = append(calls, na.toCall(SourceJSON))
			}
			return true
		}
		var na nameArgs
		if json.Unmarshal([]byte(fixed), &na) != nil {
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
		return objectOrMarker(t)
	}
	if r := RepairJSON(t); json.Valid([]byte(r)) {
		return objectOrMarker(r)
	}
	return unparseable(t)
}

// UnparseableKey marks arguments that could not be turned into a JSON
// object; ValidateArgs reports them to the model instead of guessing.
const UnparseableKey = "_govcode_unparseable_arguments"

func unparseable(raw string) json.RawMessage {
	if len(raw) > 500 {
		raw = raw[:500]
	}
	b, _ := json.Marshal(map[string]string{UnparseableKey: raw})
	return b
}

// objectOrMarker accepts only a JSON object; arrays, strings and numbers
// are reported as unparseable arguments.
func objectOrMarker(s string) json.RawMessage {
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return unparseable(s)
	}
	return json.RawMessage(s)
}

var reTrailingComma = regexp.MustCompile(`,\s*([}\]])`)

// RepairJSON fixes the faults local models most often make in JSON:
// surrounding code fences, leading prose, trailing commas, and a missing
// final brace. It returns the input unchanged if repair does not help.
// fixInvalidEscapes makes a backslash that does not start a valid JSON
// escape literal. Models writing C, Ada or COBOL into a JSON string often
// leave '\0' or '\x41' as is; JSON rejects those, and the whole tool-call
// list was lost. The model meant the backslash itself, so it is doubled.
func fixInvalidEscapes(t string) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !inStr {
			if c == '"' {
				inStr = true
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '"':
			inStr = false
		case '\\':
			if i+1 < len(t) && strings.IndexByte(`"\\/bfnrtu`, t[i+1]) >= 0 {
				if t[i+1] == 'u' && !(i+5 < len(t) && isHex4(t[i+2:i+6])) {
					b.WriteString(`\\`)
					continue
				}
				b.WriteByte(c)
				b.WriteByte(t[i+1])
				i++
				continue
			}
			b.WriteString(`\\`)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isHex4(s string) bool {
	for i := 0; i < 4; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

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
	t = fixInvalidEscapes(t)
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

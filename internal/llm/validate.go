package llm

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// ValidateArgs checks a call against its tool schema and returns normalized
// arguments. Safe coercions (numeric strings to integers, "true" to bool, a
// lone string to a one-element array) are applied because quantized models
// make these mistakes constantly; anything else is a precise error message
// that is sent back to the model so it can correct the call.
func ValidateArgs(spec ToolSpec, raw json.RawMessage) (map[string]any, error) {
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("arguments are not a JSON object: %v", err)
	}
	if args == nil {
		args = map[string]any{}
	}
	var problems []string
	for _, r := range spec.Required {
		if v, ok := args[r]; !ok || v == nil {
			problems = append(problems, fmt.Sprintf("missing required parameter %q", r))
		}
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p, ok := spec.Properties[k]
		if !ok {
			// Drop unknown keys rather than fail: models often add "explanation".
			delete(args, k)
			continue
		}
		v, err := coerce(args[k], p)
		if err != nil {
			problems = append(problems, fmt.Sprintf("parameter %q: %v", k, err))
			continue
		}
		args[k] = v
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid call to %s: %s. Expected parameters: %s",
			spec.Name, strings.Join(problems, "; "), describe(spec))
	}
	return args, nil
}

func coerce(v any, p Property) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch p.Type {
	case "string":
		switch x := v.(type) {
		case string:
			if len(p.Enum) > 0 && !contains(p.Enum, x) {
				return nil, fmt.Errorf("must be one of %v, got %q", p.Enum, x)
			}
			return x, nil
		case float64, bool:
			return fmt.Sprint(x), nil
		}
		return nil, fmt.Errorf("expected string, got %T", v)
	case "integer":
		switch x := v.(type) {
		case float64:
			if x != math.Trunc(x) {
				return nil, fmt.Errorf("expected integer, got %v", x)
			}
			return int(x), nil
		case string:
			n, err := strconv.Atoi(strings.TrimSpace(x))
			if err != nil {
				return nil, fmt.Errorf("expected integer, got %q", x)
			}
			return n, nil
		}
		return nil, fmt.Errorf("expected integer, got %T", v)
	case "number":
		switch x := v.(type) {
		case float64:
			return x, nil
		case string:
			f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
			if err != nil {
				return nil, fmt.Errorf("expected number, got %q", x)
			}
			return f, nil
		}
		return nil, fmt.Errorf("expected number, got %T", v)
	case "boolean":
		switch x := v.(type) {
		case bool:
			return x, nil
		case string:
			b, err := strconv.ParseBool(strings.TrimSpace(x))
			if err != nil {
				return nil, fmt.Errorf("expected boolean, got %q", x)
			}
			return b, nil
		}
		return nil, fmt.Errorf("expected boolean, got %T", v)
	case "array":
		switch x := v.(type) {
		case []any:
			if p.Items != nil {
				for i := range x {
					c, err := coerce(x[i], *p.Items)
					if err != nil {
						return nil, fmt.Errorf("item %d: %v", i, err)
					}
					x[i] = c
				}
			}
			return x, nil
		case string:
			var arr []any
			if json.Unmarshal([]byte(x), &arr) == nil {
				return coerce(arr, p)
			}
			return coerce([]any{x}, p)
		}
		return nil, fmt.Errorf("expected array, got %T", v)
	}
	return v, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func describe(spec ToolSpec) string {
	var parts []string
	keys := make([]string, 0, len(spec.Properties))
	for k := range spec.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		req := ""
		if contains(spec.Required, k) {
			req = ", required"
		}
		parts = append(parts, fmt.Sprintf("%s (%s%s)", k, spec.Properties[k].Type, req))
	}
	return strings.Join(parts, ", ")
}

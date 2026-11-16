package agent

import (
	"fmt"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
)

// estimateTokens is deliberately pessimistic. Source code, especially
// COBOL/Ada with long identifiers and column padding, tokenizes at roughly
// 3 bytes/token; under-estimating would overflow num_ctx and the server
// would silently truncate the front of the prompt (the system prompt).
func estimateTokens(msgs []llm.Message, tools []llm.ToolSpec) int {
	n := 0
	for _, m := range msgs {
		n += 8 + len(m.Content)/3
		for _, tc := range m.ToolCalls {
			n += 12 + len(tc.Args)/3
		}
	}
	for _, t := range tools {
		n += 20 + len(t.Description)/3
		for k, p := range t.Properties {
			n += 6 + (len(k)+len(p.Description))/3
		}
	}
	return n
}

const elided = "[earlier tool output elided to fit the context window; call the tool again if you need it]"

// fitBudget shrinks history to fit numCtx-maxTokens. Order of sacrifice:
//  1. contents of old tool results (keep the 4 most recent intact),
//  2. whole old exchanges (an assistant tool-call message together with its
//     tool results, so tool_call ids stay paired). The system prompt and the
//     task message are never removed.
func fitBudget(msgs []llm.Message, tools []llm.ToolSpec, numCtx, maxTokens int) ([]llm.Message, int, error) {
	budget := numCtx - maxTokens - 256
	if budget <= 0 {
		return nil, 0, fmt.Errorf("num_ctx %d too small for max_tokens %d", numCtx, maxTokens)
	}
	out := append([]llm.Message(nil), msgs...)
	if estimateTokens(out, tools) <= budget {
		return out, 0, nil
	}
	trimmed := 0
	var toolIdx []int
	for i, m := range out {
		if m.Role == llm.RoleTool {
			toolIdx = append(toolIdx, i)
		}
	}
	for k := 0; k < len(toolIdx)-4 && estimateTokens(out, tools) > budget; k++ {
		i := toolIdx[k]
		if out[i].Content != elided {
			out[i].Content = elided
			trimmed++
		}
	}
	for estimateTokens(out, tools) > budget {
		// find first assistant message after the task (index >= 2)
		start := -1
		for i := 2; i < len(out); i++ {
			if out[i].Role == llm.RoleAssistant {
				start = i
				break
			}
		}
		if start < 0 || start >= len(out)-2 {
			return nil, trimmed, fmt.Errorf("prompt does not fit num_ctx=%d even after trimming history; raise num_ctx or reduce output limits", numCtx)
		}
		end := start + 1
		for end < len(out) && out[end].Role == llm.RoleTool {
			end++
		}
		out = append(out[:start], out[end:]...)
		trimmed++
	}
	return out, trimmed, nil
}

package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/marking"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

// streamingScripted delivers each response's content in small fragments.
type streamingScripted struct{ llm.Scripted }

func (s *streamingScripted) ChatStream(ctx context.Context, msgs []llm.Message, ts []llm.ToolSpec, on func(string)) (*llm.Response, error) {
	r, err := s.Chat(ctx, msgs, ts)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(r.Content); i += 3 {
		on(r.Content[i:min(i+3, len(r.Content))])
	}
	return r, nil
}

func TestStreamingIsLineBufferedAndSpillageChecked(t *testing.T) {
	env := fixture(t)
	env.MaxLevel = marking.S
	fin, _ := json.Marshal(map[string]any{"summary": "nothing to change"})
	m := &streamingScripted{llm.Scripted{Responses: []llm.Response{
		{Content: "Looking at sum.c now.\nTOP SECRET//SI banner\nDone looking", ToolCalls: []llm.ToolCall{{Name: "finish", Args: fin, Source: llm.SourceNative}}},
	}}}
	env.RequireTest = false
	var got []string
	a := &Agent{Backend: m, Tools: tools.NewSet(env), Cfg: Config{OnToken: func(s string) { got = append(got, s) }}}
	if _, err := a.Run(context.Background(), "look", RepoContext{}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "Looking at sum.c now.\n" || !strings.Contains(got[1], "withheld") || got[2] != "Done looking\n" {
		t.Fatalf("streamed lines %q", got)
	}
	for _, l := range got {
		if strings.Contains(l, "TOP SECRET") {
			t.Fatal("over-classified line streamed to the user")
		}
	}
}

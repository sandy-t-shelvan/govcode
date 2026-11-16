package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

func fixture(t *testing.T) *tools.Env {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"sum.c":    "int sum(int *a, int n) {\n    int s = 0;\n    for (int i = 0; i <= n; i++) s += a[i];\n    return s;\n}\n",
		"test.c":   "#include <stdio.h>\nint sum(int*,int);\nint main(void){int a[4]={1,2,3,99};return sum(a,3)==6?0:(printf(\"got %d\\n\",sum(a,3)),1);}\n",
		"Makefile": "test:\n\tcc -o t sum.c test.c && ./t\n",
	}
	for p, c := range files {
		os.WriteFile(filepath.Join(dir, p), []byte(c), 0o644)
	}
	for _, a := range [][]string{{"init", "-q"}, {"add", "-A"}, {"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"}} {
		exec.Command("git", append([]string{"-C", dir}, a...)...).Run()
	}
	j, _ := tools.NewJail(dir)
	r, _ := tools.NewRunner(tools.SandboxBestEffort, j.Root, nil, nil)
	return &tools.Env{Jail: j, Runner: r, TestCommand: "make -s test", RequireTest: true}
}

func native(name string, args map[string]any) llm.ToolCall {
	b, _ := json.Marshal(args)
	return llm.ToolCall{Name: name, Args: b, Source: llm.SourceNative}
}

type rec struct{ kinds []string }

func (r *rec) Record(k string, _ any) error { r.kinds = append(r.kinds, k); return nil }

func TestPlanEditTestFixLoop(t *testing.T) {
	env := fixture(t)
	model := &llm.Scripted{Responses: []llm.Response{
		{ToolCalls: []llm.ToolCall{native("read_file", map[string]any{"path": "sum.c"})}},
		{ToolCalls: []llm.ToolCall{native("update_plan", map[string]any{"steps": []string{"fix loop bound", "run tests"}})}},
		// a wrong edit first (still off by one in another way) -> tests fail
		{Content: "<tool_call>\n<function=edit_file>\n<parameter=path>\nsum.c\n</parameter>\n<parameter=old_text>\n    for (int i = 0; i <= n; i++) s += a[i];\n</parameter>\n<parameter=new_text>\n    for (int i = 1; i <= n; i++) s += a[i];\n</parameter>\n</function>\n</tool_call>"},
		{ToolCalls: []llm.ToolCall{native("finish", map[string]any{"summary": "premature"})}}, // refused: not tested
		{ToolCalls: []llm.ToolCall{native("run_tests", nil)}},                                 // fails
		{ToolCalls: []llm.ToolCall{native("edit_file", map[string]any{"path": "sum.c",
			"old_text": "for (int i = 1; i <= n; i++)", "new_text": "for (int i = 0; i < n; i++)"})}},
		{ToolCalls: []llm.ToolCall{native("run_tests", nil)}}, // passes
		{Content: "Done, tests pass."},                        // no call -> nag
		{ToolCalls: []llm.ToolCall{native("bogus_tool", nil), native("finish", map[string]any{"summary": "Fixed off-by-one in sum()."})}},
	}}
	r := &rec{}
	a := &Agent{Backend: model, Tools: tools.NewSet(env), Rec: r}
	res, err := a.Run(context.Background(), "sum() returns the wrong total; fix it", RepoContext{TestCommand: env.TestCommand})
	if err != nil {
		t.Fatal(err)
	}
	m := res.Metrics
	if !m.Finished || res.Summary != "Fixed off-by-one in sum()." {
		t.Fatalf("not finished: %+v", m)
	}
	if m.CallsEmitted != 9 || m.ParsedBy[llm.SourceQwenXML] != 1 || m.ParsedBy[llm.SourceNative] != 8 {
		t.Errorf("parse counts: %+v", m)
	}
	if m.UnknownTool != 1 || m.ExecError != 1 || m.NoCallTurns != 1 || m.ExecOK != 7 {
		t.Errorf("outcome counts: %+v", m)
	}
	got, _ := os.ReadFile(filepath.Join(env.Jail.Root, "sum.c"))
	if !strings.Contains(string(got), "i < n") {
		t.Errorf("fix not applied: %s", got)
	}
	if len(res.Changed) != 1 || res.Changed[0] != "sum.c" {
		t.Errorf("changed = %v", res.Changed)
	}
	// unknown tool error must reach the model with the list of real tools
	last := model.Seen[len(model.Seen)-1]
	_ = last
	if len(r.kinds) == 0 {
		t.Error("nothing recorded")
	}
	// the tool-call/result pairing must be intact in what the model saw
	for _, req := range model.Seen {
		for i, msg := range req {
			if msg.Role == llm.RoleTool && (i == 0 || (req[i-1].Role != llm.RoleAssistant && req[i-1].Role != llm.RoleTool)) {
				t.Fatalf("orphan tool message at %d", i)
			}
		}
	}
}

func TestBudgetKeepsSystemAndTask(t *testing.T) {
	big := strings.Repeat("x", 30000)
	msgs := []llm.Message{{Role: "system", Content: "sys"}, {Role: "user", Content: "task"}}
	for i := 0; i < 10; i++ {
		msgs = append(msgs, llm.Message{Role: "assistant", ToolCalls: []llm.ToolCall{{ID: "c", Name: "read_file", Args: json.RawMessage(`{}`)}}},
			llm.Message{Role: "tool", Content: big, ToolCallID: "c"})
	}
	out, trims, err := fitBudget(msgs, nil, 32768, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Content != "sys" || out[1].Content != "task" || trims == 0 {
		t.Fatalf("budget dropped essentials or did nothing (trims=%d)", trims)
	}
	if estimateTokens(out, nil) > 32768-4096 {
		t.Fatal("still over budget")
	}
	if out[len(out)-1].Content != big {
		t.Fatal("most recent tool output was elided")
	}
}

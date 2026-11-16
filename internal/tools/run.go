package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
)

// ---- run_tests ----

type runTests struct{ e *Env }

func (t *runTests) Spec() llm.ToolSpec {
	return llm.ToolSpec{Name: "run_tests",
		Description: "Build and run the project's tests (the command is fixed by policy). Returns exit code and output.",
		Properties:  map[string]llm.Property{}}
}

func (t *runTests) Run(ctx context.Context, _ map[string]any) (string, error) {
	if t.e.TestCommand == "" {
		return "", fmt.Errorf("no test command is configured for this repository; use run_command to build")
	}
	to := t.e.TestTimeout
	if to == 0 {
		to = 10 * time.Minute
	}
	r := t.e.Runner.Run(ctx, t.e.TestCommand, to)
	t.e.TestRuns++
	t.e.TestedGen = t.e.EditGen
	t.e.LastTestPass = r.ExitCode == 0 && !r.TimedOut
	t.e.emit("test", r)
	status := "PASSED"
	if !t.e.LastTestPass {
		status = "FAILED"
	}
	if r.TimedOut {
		status = "TIMED OUT"
	}
	return fmt.Sprintf("Tests %s (exit %d, %s)\n$ %s\n%s", status, r.ExitCode, r.Duration.Round(time.Millisecond), r.Command, r.Output), nil
}

// ---- run_command ----

type runCommand struct{ e *Env }

func (t *runCommand) Spec() llm.ToolSpec {
	return llm.ToolSpec{Name: "run_command",
		Description: "Run a shell command in the repository root (sandboxed: no network, only this repo is writable). Commands outside the policy allowlist need human approval.",
		Properties: map[string]llm.Property{
			"command": p("string", "Shell command, e.g. 'make -C src' or 'gnatmake -gnatwa main.adb'"),
			"timeout": p("integer", "Seconds (default 120, max 900)"),
		}, Required: []string{"command"}}
}

// shellMeta are constructs that let a command chain or substitute another
// command; an allowlisted prefix only auto-approves the simple case.
var shellMeta = []string{";", "&&", "||", "|", "`", "$(", ">", "<", "\n", "&"}

func (e *Env) allowlisted(cmd string) bool {
	// Check the raw string, not a trimmed copy: the decision must be about
	// exactly the bytes that would run.
	for _, m := range shellMeta {
		if strings.Contains(cmd, m) {
			return false
		}
	}
	c := strings.TrimSpace(cmd)
	for _, a := range e.Allowlist {
		if c == a || strings.HasPrefix(c, a+" ") {
			return true
		}
	}
	return false
}

func (t *runCommand) Run(ctx context.Context, a map[string]any) (string, error) {
	cmd := strings.TrimSpace(str(a, "command"))
	if cmd == "" {
		return "", fmt.Errorf("command is empty")
	}
	how := "allowlist"
	if !t.e.allowlisted(cmd) {
		if t.e.Approver == nil {
			t.e.emit("command_denied", map[string]any{"command": cmd, "reason": "not allowlisted, no approver"})
			return "", fmt.Errorf("command not permitted by policy (not on allowlist): %s", cmd)
		}
		ok, who := t.e.Approver.ApproveCommand(cmd)
		if !ok {
			t.e.emit("command_denied", map[string]any{"command": cmd, "reason": "denied by " + who})
			return "", fmt.Errorf("the human reviewer denied this command: %s. Try another approach", cmd)
		}
		how = "approved by " + who
	}
	to := time.Duration(min(max(integer(a, "timeout", 120), 1), 900)) * time.Second
	r := t.e.Runner.Run(ctx, cmd, to)
	t.e.emit("command", map[string]any{"result": r, "authorized": how})
	suffix := ""
	if r.TimedOut {
		suffix = " (timed out)"
	}
	return fmt.Sprintf("exit %d%s\n%s", r.ExitCode, suffix, r.Output), nil
}

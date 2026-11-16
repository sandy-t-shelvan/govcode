package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/permissions"
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
	if t.e.spill("run_tests output", r.Output) {
		r.Output = withheld("test output", t.e)
	}
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

// shellMeta is kept for the fuzz test; the rules engine owns the list.
var shellMeta = permissions.ShellMeta

// allowlisted reports whether cmd would run without asking a human.
func (e *Env) allowlisted(cmd string) bool {
	d, _ := e.rules().Decide("run_command", cmd)
	return d == permissions.Allow
}

func (t *runCommand) Run(ctx context.Context, a map[string]any) (string, error) {
	cmd := strings.TrimSpace(str(a, "command"))
	if cmd == "" {
		return "", fmt.Errorf("command is empty")
	}
	if err := t.e.authorize("run_command", cmd); err != nil {
		return "", err
	}
	to := time.Duration(min(max(integer(a, "timeout", 120), 1), 900)) * time.Second
	r := t.e.Runner.Run(ctx, cmd, to)
	if t.e.spill("run_command output", r.Output) {
		r.Output = withheld("command output", t.e)
	}
	t.e.emit("command", map[string]any{"result": r})
	suffix := ""
	if r.TimedOut {
		suffix = " (timed out)"
	}
	return fmt.Sprintf("exit %d%s\n%s", r.ExitCode, suffix, r.Output), nil
}

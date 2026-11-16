package tools

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Sandbox modes.
const (
	SandboxRequired   = "required"    // refuse to run commands without bubblewrap
	SandboxBestEffort = "best-effort" // use bubblewrap if present
	SandboxOff        = "off"         // development only
)

// Runner executes shell commands for run_tests / run_command.
//
// With bubblewrap the command sees: system directories read-only, the
// worktree read-write, a private /tmp, no network namespace (no interfaces
// but loopback), and nothing else from the host — not $HOME, not other
// repositories, not the audit log or signing keys. This is what "least
// privilege to one repo" means for code the model asks to run.
type Runner struct {
	Mode      string
	Worktree  string
	ExtraRO   []string // toolchain dirs outside the defaults, e.g. /opt/gnat
	Env       []string // KEY=VALUE passed into the sandbox
	MaxOutput int
	bwrap     string
	shell     string
}

var defaultRO = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc/alternatives", "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/passwd", "/etc/group", "/etc/localtime", "/opt"}

func NewRunner(mode, worktree string, extraRO, env []string) (*Runner, error) {
	r := &Runner{Mode: mode, Worktree: worktree, ExtraRO: extraRO, Env: env, MaxOutput: 30000}
	r.shell = "/bin/bash"
	if _, err := os.Stat(r.shell); err != nil {
		r.shell = "/bin/sh"
	}
	if mode != SandboxOff {
		if p, err := exec.LookPath("bwrap"); err == nil {
			// bwrap needs unprivileged user namespaces; probe once.
			if exec.Command(p, "--ro-bind", "/", "/", "--unshare-net", "true").Run() == nil {
				r.bwrap = p
			}
		}
		if r.bwrap == "" && mode == SandboxRequired {
			return nil, fmt.Errorf("sandbox required by policy but bubblewrap (bwrap) is not installed or user namespaces are disabled")
		}
	}
	return r, nil
}

// Sandboxed reports whether commands run under bubblewrap.
func (r *Runner) Sandboxed() bool { return r.bwrap != "" }

type ExecResult struct {
	Command  string        `json:"command"`
	ExitCode int           `json:"exit_code"`
	Output   string        `json:"output"`
	Duration time.Duration `json:"duration_ns"`
	TimedOut bool          `json:"timed_out"`
	Sandbox  string        `json:"sandbox"`
}

func (r *Runner) Run(ctx context.Context, command string, timeout time.Duration) ExecResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	env := append([]string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/tmp", "TMPDIR=/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TERM=dumb",
	}, r.Env...)
	var cmd *exec.Cmd
	sandbox := "none"
	if r.bwrap != "" {
		sandbox = "bubblewrap"
		args := []string{"--die-with-parent", "--new-session", "--unshare-all", "--clearenv",
			"--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"}
		for _, p := range append(append([]string{}, defaultRO...), r.ExtraRO...) {
			if _, err := os.Stat(p); err == nil {
				args = append(args, "--ro-bind", p, p)
			}
		}
		// Linked worktrees reference the main repository's git dir; expose it
		// read-only so read-only git commands work.
		if gd := gitCommonDir(r.Worktree); gd != "" {
			args = append(args, "--ro-bind", gd, gd)
		}
		args = append(args, "--bind", r.Worktree, r.Worktree, "--chdir", r.Worktree)
		for _, e := range env {
			k, v, _ := strings.Cut(e, "=")
			args = append(args, "--setenv", k, v)
		}
		args = append(args, "--", r.shell, "-c", command)
		cmd = exec.CommandContext(ctx, r.bwrap, args...)
	} else {
		cmd = exec.CommandContext(ctx, r.shell, "-c", command)
		cmd.Dir = r.Worktree
		cmd.Env = env
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	cmd.Stdin = nil
	start := time.Now()
	err := cmd.Run()
	res := ExecResult{Command: command, Duration: time.Since(start), Sandbox: sandbox}
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
	} else if ee, ok := err.(*exec.ExitError); ok {
		res.ExitCode = ee.ExitCode()
	} else if err != nil {
		res.ExitCode = -1
		buf.WriteString("\n[govcode: " + err.Error() + "]")
	}
	res.Output = headTail(buf.String(), r.MaxOutput)
	return res
}

func gitCommonDir(wt string) string {
	out, err := exec.Command("git", "-C", wt, "rev-parse", "--path-format=absolute", "--git-common-dir").Output()
	if err != nil {
		return ""
	}
	d := strings.TrimSpace(string(out))
	if filepath.IsAbs(d) {
		return d
	}
	return ""
}

// headTail keeps the start and end of long output; compiler errors are
// usually at the start and test summaries at the end.
func headTail(s string, max int) string {
	if len(s) <= max {
		return s
	}
	h := max * 2 / 5
	t := max - h
	return s[:h] + fmt.Sprintf("\n\n[... %d bytes omitted ...]\n\n", len(s)-max) + s[len(s)-t:]
}

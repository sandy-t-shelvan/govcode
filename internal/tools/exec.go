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

	"github.com/sandy-t-shelvan/govcode/internal/permissions"
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
	// Hide reports whether a worktree file (repo-relative, '/'-separated)
	// must be hidden from commands. A directory covered as a whole becomes an
	// empty read-only tmpfs; any other such file is bound to /dev/null on a
	// nodev mount, so opening it fails (Permission denied). Nil hides nothing.
	Hide func(rel string) bool
	// HideGit hides the repository's git data (object store and the
	// worktree's .git), so history cannot reveal hidden files.
	HideGit bool
	// Cover lists host paths that must not be readable while hiding, such
	// as govcode's state directory (other runs' worktrees, the audit log),
	// in case a read-only bind (/opt, extra_ro_paths) would expose them.
	Cover []string
	bwrap string
	shell string
	// maskOK: this bwrap supports --args and --remount-ro, which hiding
	// needs. Without them commands still run, but nothing can be hidden.
	maskOK bool
}

// maxBwrapArgs stays under bubblewrap's own limit on arguments (9000 in
// current releases), leaving a margin for builds that differ.
const maxBwrapArgs = 8000

var defaultRO = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc/alternatives", "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/passwd", "/etc/group", "/etc/localtime", "/etc/gnucobol", "/etc/gprconfig", "/opt"}

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
				r.maskOK = probeMasking(p)
			}
		}
		if r.bwrap == "" && mode == SandboxRequired {
			return nil, fmt.Errorf("sandbox required by policy but bubblewrap (bwrap) is not installed or user namespaces are disabled")
		}
	}
	return r, nil
}

// CanHide reports whether this runner can hide files from commands
// (bubblewrap with --args and --remount-ro).
func (r *Runner) CanHide() bool { return r.bwrap != "" && r.maskOK }

// Sandboxed reports whether commands run under bubblewrap.
func (r *Runner) Sandboxed() bool { return r.bwrap != "" }

type ExecResult struct {
	Command  string        `json:"command"`
	ExitCode int           `json:"exit_code"`
	Output   string        `json:"output"`
	Duration time.Duration `json:"duration_ns"`
	TimedOut bool          `json:"timed_out"`
	Sandbox  string        `json:"sandbox"`
	// HiddenPaths counts files masked from the command; names are never
	// reported, since list_files withholds them from the model too.
	HiddenPaths int `json:"hidden_paths,omitempty"`
}

func (r *Runner) Run(ctx context.Context, command string, timeout time.Duration) ExecResult {
	return r.RunWith(ctx, command, timeout, nil)
}

// RunWith is Run with extra KEY=VALUE environment for this command only.
func (r *Runner) RunWith(ctx context.Context, command string, timeout time.Duration, extra []string) ExecResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	env := append([]string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/tmp", "TMPDIR=/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TERM=dumb",
	}, r.Env...)
	env = append(env, extra...)
	plan := r.maskPlan()
	hiding := plan.count > 0 || r.HideGit
	if r.bwrap != "" && hiding && !r.maskOK {
		return ExecResult{Command: command, ExitCode: -1, Sandbox: "bubblewrap", Output: "[govcode: refused: policy read rules protect files in this repository, " +
			"and this bubblewrap cannot hide them (it lacks --args or --remount-ro). Install a newer bubblewrap.]"}
	}
	if r.bwrap == "" && r.Mode != SandboxOff && hiding {
		return ExecResult{Command: command, ExitCode: -1, Sandbox: "none", Output: "[govcode: refused: policy read rules protect files in this repository, " +
			"and without bubblewrap they cannot be hidden from commands. Install bubblewrap (bwrap) with user namespaces enabled, " +
			"or use sandbox.mode \"off\" for development only.]"}
	}
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
		// The read-only system binds (/opt, extra_ro_paths) could contain the
		// main repository or its git dir, where nothing is masked. While
		// hiding, cover those with an empty tmpfs; the worktree bind below
		// still applies on top.
		if plan.count > 0 || r.HideGit {
			for _, p := range append(r.repoPaths(), r.Cover...) {
				if SandboxVisible(p, r.ExtraRO) {
					args = append(args, "--tmpfs", p)
				}
			}
		}
		// Linked worktrees reference the main repository's git dir; expose it
		// read-only so read-only git commands work.
		if gd := gitCommonDir(r.Worktree); gd != "" && !r.HideGit {
			args = append(args, "--ro-bind", gd, gd)
		}
		args = append(args, "--bind", r.Worktree, r.Worktree, "--chdir", r.Worktree)
		// Masks must come after the worktree bind: bubblewrap applies
		// mounts in argument order. A directory the rules protect as a whole
		// becomes an empty read-only tmpfs; other protected files are bound
		// to /dev/null one by one.
		for _, d := range plan.dirs {
			args = append(args, "--tmpfs", d, "--remount-ro", d)
		}
		for _, f := range plan.files {
			args = append(args, "--ro-bind", "/dev/null", f)
		}
		if r.HideGit {
			g := filepath.Join(r.Worktree, ".git")
			if fi, err := os.Lstat(g); err == nil && fi.IsDir() {
				args = append(args, "--tmpfs", g)
			} else if err == nil && fi.Mode().IsRegular() {
				args = append(args, "--ro-bind", "/dev/null", g)
			}
		}
		for _, e := range env {
			k, v, _ := strings.Cut(e, "=")
			args = append(args, "--setenv", k, v)
		}
		if len(args) > maxBwrapArgs {
			return ExecResult{Command: command, ExitCode: -1, Sandbox: sandbox, Output: fmt.Sprintf("[govcode: refused: %d separately protected files "+
				"need more sandbox arguments than bubblewrap accepts. Protect whole directories (for example keys/**), move the files out of "+
				"the repository, or list them in sandbox.expose.]", len(plan.files))}
		}
		if r.maskOK {
			// Options go through a file descriptor (--args) so that long
			// paths cannot exceed the kernel's argument-size limit.
			argf, aerr := bwrapArgsFile(args)
			if aerr != nil {
				return ExecResult{Command: command, ExitCode: -1, Sandbox: sandbox, Output: "[govcode: " + aerr.Error() + "]"}
			}
			defer argf.Close()
			cmd = exec.CommandContext(ctx, r.bwrap, "--args", "3", "--", r.shell, "-c", command)
			cmd.ExtraFiles = []*os.File{argf} // fd 3
		} else {
			args = append(args, "--", r.shell, "-c", command)
			cmd = exec.CommandContext(ctx, r.bwrap, args...)
		}
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
	res := ExecResult{Command: command, Duration: time.Since(start), Sandbox: sandbox, HiddenPaths: plan.count}
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
	} else if ee, ok := err.(*exec.ExitError); ok {
		res.ExitCode = ee.ExitCode()
	} else if err != nil {
		res.ExitCode = -1
		buf.WriteString("\n[govcode: " + err.Error() + "]")
	}
	res.Output = headTail(scrubSetupError(buf.String(), sandbox == "bubblewrap" && hiding), r.MaxOutput)
	return res
}

// HideReadProtected configures the runner so commands cannot read what
// read_file may not: a file whose read_file decision is deny or ask
// (commands cannot prompt per file) is masked unless it matches an expose
// glob, and git is hidden unless exposeGit. Without any read_file deny or
// ask rule nothing is hidden and nothing changes.
func (r *Runner) HideReadProtected(rules *permissions.Rules, expose []string, exposeGit bool) {
	if !rules.Restricts("read_file") {
		return
	}
	r.Hide = func(rel string) bool {
		for _, g := range expose {
			if permissions.PathMatch(g, rel) {
				return false
			}
		}
		d, _ := rules.Decide("read_file", rel)
		return d == permissions.Deny || d == permissions.Ask
	}
	r.HideGit = !exposeGit
}

// maskPlan is what the sandbox hides: directories the rules protect as a
// whole, single protected files elsewhere, and how many files that covers.
type maskPlan struct {
	dirs, files []string
	count       int
}

// maskPlan walks the worktree (not following symlinks; masking a target
// also covers links to it; .git is left to HideGit) and selects what r.Hide
// protects. A directory is masked as a whole only when every entry in it is
// a hidden file or such a directory, it holds at least one hidden file, and
// the rule covers the directory itself: a new file created in it would be
// hidden too (keys/** does; **/*.pem does not, so a certs/ directory of .pem
// files stays writable). The worktree root is never masked whole.
func (r *Runner) maskPlan() maskPlan {
	var p maskPlan
	if r.Hide == nil {
		return p
	}
	var walk func(abs, rel string) (whole bool, dirs, files []string, n int)
	walk = func(abs, rel string) (bool, []string, []string, int) {
		ents, err := os.ReadDir(abs)
		if err != nil {
			return false, nil, nil, 0
		}
		whole := rel != ""
		var dirs, files []string
		n := 0
		for _, de := range ents {
			name := de.Name()
			cabs, crel := filepath.Join(abs, name), name
			if rel != "" {
				crel = rel + "/" + name
			}
			switch {
			case name == ".git":
				whole = false
			case de.IsDir():
				w, d, f, c := walk(cabs, crel)
				n += c
				if w {
					dirs = append(dirs, cabs)
				} else {
					whole = false
					dirs, files = append(dirs, d...), append(files, f...)
				}
			case de.Type().IsRegular() && r.Hide(crel):
				files = append(files, cabs)
				n++
			default:
				whole = false
			}
		}
		if whole && n > 0 && r.Hide(rel+"/.govcode-probe") {
			return true, nil, nil, n
		}
		return false, dirs, files, n
	}
	_, p.dirs, p.files, p.count = walk(r.Worktree, "")
	return p
}

// probeMasking reports whether bwrap supports what hiding needs: options
// read from a file descriptor (--args) and --remount-ro.
func probeMasking(bwrap string) bool {
	f, err := bwrapArgsFile([]string{"--ro-bind", "/", "/", "--tmpfs", "/tmp", "--remount-ro", "/tmp", "--unshare-net"})
	if err != nil {
		return false
	}
	defer f.Close()
	cmd := exec.Command(bwrap, "--args", "3", "--", "true")
	cmd.ExtraFiles = []*os.File{f}
	return cmd.Run() == nil
}

// scrubSetupError replaces bubblewrap's own failure message while files are
// hidden: it can name a protected path (for example "bwrap: Can't mount
// tmpfs on .../keys"), and those names are withheld from the model.
func scrubSetupError(out string, hiding bool) string {
	if hiding && strings.HasPrefix(out, "bwrap: ") {
		return "[govcode: the sandbox could not be set up; bubblewrap's message is withheld because it can name protected files]"
	}
	return out
}

// repoPaths are the main repository's root and git directory, other than the
// worktree itself.
func (r *Runner) repoPaths() []string {
	gd := gitCommonDir(r.Worktree)
	if gd == "" {
		return nil
	}
	var out []string
	if filepath.Base(gd) == ".git" {
		if root := filepath.Dir(gd); root != r.Worktree {
			out = append(out, root)
		}
	}
	if filepath.Dir(gd) != r.Worktree {
		out = append(out, gd)
	}
	return out
}

// bwrapArgsFile writes NUL-separated bubblewrap options to an unlinked
// temporary file, positioned at its start, for bwrap --args.
func bwrapArgsFile(args []string) (*os.File, error) {
	f, err := os.CreateTemp("", "govcode-bwrap-*")
	if err != nil {
		return nil, fmt.Errorf("sandbox arguments: %v", err)
	}
	os.Remove(f.Name())
	var b strings.Builder
	for _, a := range args {
		b.WriteString(a)
		b.WriteByte(0)
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return nil, fmt.Errorf("sandbox arguments: %v", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("sandbox arguments: %v", err)
	}
	return f, nil
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

// SandboxVisible reports whether path is inside a directory the sandbox
// binds (the system directories plus extra read-only paths).
func SandboxVisible(path string, extra []string) bool {
	for _, d := range append(append([]string{}, defaultRO...), extra...) {
		if path == d || strings.HasPrefix(path, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

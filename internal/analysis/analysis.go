// Package analysis runs the site's mandatory static analyzers over the files
// a proposal changes. DoWI 8430.01 treats AI-generated code as unverified
// input that needs the same security testing as human-written code, so in
// strict mode every changed file must be analyzed (or explicitly exempted)
// before a proposal can be approved.
package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/permissions"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

// Analyzer is one entry of the policy's analysis map.
type Analyzer struct {
	Name       string   `json:"name"`
	Extensions []string `json:"extensions"` // ".c", ".h"; matched case-insensitively
	// Command runs in the sandbox from the worktree root, with the files
	// it covers appended as shell-quoted arguments and also listed in
	// $GOVCODE_FILES. Its first word is the analyzer binary.
	Command string `json:"command"`
	// FailOn is a regex; an output line matching it is a blocking finding.
	// A non-zero exit or a timeout always blocks.
	FailOn string `json:"fail_on,omitempty"`
	// Finding is a regex counting every finding line (default: FailOn).
	Finding string `json:"finding,omitempty"`
	// VersionArgs prints the analyzer version (default "--version").
	VersionArgs []string `json:"version_args,omitempty"`
}

// Validate compiles the regexes and checks the required fields.
func (a Analyzer) Validate() error {
	if a.Name == "" || a.Command == "" || len(a.Extensions) == 0 {
		return fmt.Errorf("analysis analyzer needs name, extensions and command")
	}
	for _, e := range a.Extensions {
		if !strings.HasPrefix(e, ".") {
			return fmt.Errorf("analyzer %s: extension %q must start with a dot", a.Name, e)
		}
	}
	for _, r := range []string{a.FailOn, a.Finding} {
		if _, err := regexp.Compile(r); err != nil {
			return fmt.Errorf("analyzer %s: %v", a.Name, err)
		}
	}
	return nil
}

// Binary is the first word of the command.
func (a Analyzer) Binary() string {
	f := strings.Fields(a.Command)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

func (a Analyzer) covers(file string) bool {
	ext := strings.ToLower(filepath.Ext(file))
	for _, e := range a.Extensions {
		if strings.ToLower(e) == ext {
			return true
		}
	}
	return false
}

// Tool identifies the analyzer binary a host actually has.
type Tool struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
}

// Resolve finds the analyzer binary, hashes it and reads its version. It
// runs on the host, not in the sandbox: the binary is root-installed and
// named by the root-owned policy.
func Resolve(a Analyzer) (Tool, error) {
	bin := a.Binary()
	p, err := exec.LookPath(bin)
	if err != nil {
		return Tool{}, fmt.Errorf("analyzer %s: %s not found", a.Name, bin)
	}
	if p, err = filepath.EvalSymlinks(p); err != nil {
		return Tool{}, err
	}
	f, err := os.Open(p)
	if err != nil {
		return Tool{}, err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return Tool{}, err
	}
	args := a.VersionArgs
	if len(args) == 0 {
		args = []string{"--version"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, p, args...).CombinedOutput()
	ver := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if len(ver) > 120 {
		ver = ver[:120]
	}
	return Tool{Name: a.Name, Path: p, SHA256: hex.EncodeToString(h.Sum(nil)), Version: ver}, nil
}

// Runner is the sandboxed command runner (tools.Runner).
type Runner interface {
	RunWith(ctx context.Context, command string, timeout time.Duration, extra []string) tools.ExecResult
}

// Result is one analyzer's run over the files it covers.
type Result struct {
	Analyzer string        `json:"analyzer"`
	Tool     Tool          `json:"tool"`
	Files    []string      `json:"files"`
	ExitCode int           `json:"exit_code"`
	TimedOut bool          `json:"timed_out"`
	Findings int           `json:"findings"`
	Blocking int           `json:"blocking"`
	Passed   bool          `json:"passed"`
	Output   string        `json:"-"`
	Duration time.Duration `json:"duration_ns"`
}

// Report is the outcome for a whole proposal.
type Report struct {
	Results   []Result
	Uncovered []string // changed files no analyzer covers and no exemption matches
	Exempt    []string
}

// Passed reports whether every analyzer passed and every file was covered.
func (r *Report) Passed() bool {
	for _, x := range r.Results {
		if !x.Passed {
			return false
		}
	}
	return len(r.Uncovered) == 0
}

// Run analyzes changed (repo-relative paths). tools must be in the same
// order as analyzers. Deleted files are skipped: there is nothing to analyze.
func Run(ctx context.Context, run Runner, worktree string, analyzers []Analyzer, resolved []Tool, unanalyzedOK []string, changed []string, timeout time.Duration) *Report {
	rep := &Report{}
	byAnalyzer := make([][]string, len(analyzers))
	for _, f := range changed {
		if _, err := os.Lstat(filepath.Join(worktree, f)); err != nil {
			continue
		}
		covered := false
		for i, a := range analyzers {
			if a.covers(f) {
				byAnalyzer[i] = append(byAnalyzer[i], f)
				covered = true
			}
		}
		if covered {
			continue
		}
		exempt := false
		for _, pat := range unanalyzedOK {
			if permissions.PathMatch(pat, f) {
				exempt = true
				break
			}
		}
		if exempt {
			rep.Exempt = append(rep.Exempt, f)
		} else {
			rep.Uncovered = append(rep.Uncovered, f)
		}
	}
	for i, a := range analyzers {
		files := byAnalyzer[i]
		if len(files) == 0 {
			continue
		}
		cmd := a.Command
		for _, f := range files {
			cmd += " " + shQuote(f)
		}
		start := time.Now()
		x := run.RunWith(ctx, cmd, timeout, []string{"GOVCODE_FILES=" + strings.Join(files, " ")})
		res := Result{Analyzer: a.Name, Files: files, ExitCode: x.ExitCode, TimedOut: x.TimedOut, Output: x.Output, Duration: time.Since(start)}
		if i < len(resolved) {
			res.Tool = resolved[i]
		}
		failRe := compile(a.FailOn)
		findRe := compile(a.Finding)
		if findRe == nil {
			findRe = failRe
		}
		for _, line := range strings.Split(x.Output, "\n") {
			if findRe != nil && findRe.MatchString(line) {
				res.Findings++
			}
			if failRe != nil && failRe.MatchString(line) {
				res.Blocking++
			}
		}
		res.Passed = x.ExitCode == 0 && !x.TimedOut && res.Blocking == 0
		rep.Results = append(rep.Results, res)
	}
	return rep
}

func compile(s string) *regexp.Regexp {
	if s == "" {
		return nil
	}
	return regexp.MustCompile(s) // validated at policy load
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

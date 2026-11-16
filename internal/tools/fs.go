package tools

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/permissions"
)

const (
	maxListResults   = 400
	maxSearchResults = 150
	defaultReadLines = 300
	maxReadLines     = 1500
	maxLineWidth     = 400
)

// ---- list_files ----

type listFiles struct{ e *Env }

func (t *listFiles) Spec() llm.ToolSpec {
	return llm.ToolSpec{Name: "list_files",
		Description: "List files in the repository (tracked and new). Use a glob like '**/*.adb' or 'src/*.c' to filter.",
		Properties: map[string]llm.Property{
			"pattern": p("string", "Glob, e.g. '**/*.cbl'. Default: all files"),
			"path":    p("string", "Directory to list, relative to repo root. Default: root"),
		}}
}

func (t *listFiles) Run(ctx context.Context, a map[string]any) (string, error) {
	dir := t.e.Jail.Root
	if d := str(a, "path"); d != "" && d != "." {
		r, err := t.e.Jail.Resolve(d)
		if err != nil {
			return "", err
		}
		dir = r
	}
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--full-name").Output()
	if err != nil {
		return "", fmt.Errorf("git ls-files failed: %v", err)
	}
	pat := str(a, "pattern")
	var files []string
	seen := map[string]bool{}
	for _, f := range strings.Split(string(out), "\x00") {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		if _, err := os.Lstat(filepath.Join(t.e.Jail.Root, f)); err != nil {
			continue // deleted in worktree
		}
		if pat != "" && !globMatch(pat, f) {
			continue
		}
		if d, _ := t.e.rules().Decide("read_file", f); d == permissions.Deny {
			continue // denied paths are not even listed
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return "No files matched.", nil
	}
	var b strings.Builder
	for i, f := range files {
		if i == maxListResults {
			fmt.Fprintf(&b, "[... %d more files; narrow the pattern or path ...]\n", len(files)-maxListResults)
			break
		}
		b.WriteString(f + "\n")
	}
	return b.String(), nil
}

// globMatch supports '**' (any depth) plus path.Match syntax. A pattern with
// no '/' matches the base name at any depth (so '*.c' finds src/a.c).
func globMatch(pattern, name string) bool { return permissions.PathMatch(pattern, name) }

// ---- search ----

type search struct{ e *Env }

func (t *search) Spec() llm.ToolSpec {
	return llm.ToolSpec{Name: "search",
		Description: "Search file contents with a regular expression (git grep, extended regex). Returns file:line: text.",
		Properties: map[string]llm.Property{
			"pattern":     p("string", "Extended regular expression"),
			"glob":        p("string", "Only search files matching this glob, e.g. '*.adb'"),
			"path":        p("string", "Directory to search, relative to repo root"),
			"ignore_case": p("boolean", "Case-insensitive (default false; COBOL is often upper case)"),
		}, Required: []string{"pattern"}}
}

func (t *search) Run(ctx context.Context, a map[string]any) (string, error) {
	pat := str(a, "pattern")
	if _, err := regexp.Compile(pat); err != nil {
		return "", fmt.Errorf("invalid regex: %v", err)
	}
	args := []string{"-C", t.e.Jail.Root, "grep", "-n", "-I", "-E", "--untracked", "--no-color", "--full-name"}
	if boolean(a, "ignore_case") {
		args = append(args, "-i")
	}
	args = append(args, "-e", pat, "--")
	spec := ""
	if d := str(a, "path"); d != "" && d != "." {
		r, err := t.e.Jail.Resolve(d)
		if err != nil {
			return "", err
		}
		spec = t.e.Jail.Rel(r)
	}
	if g := str(a, "glob"); g != "" {
		if !strings.Contains(g, "/") {
			g = "**/" + g
		}
		if spec != "" {
			g = spec + "/" + g
		}
		args = append(args, ":(glob)"+g)
	} else if spec != "" {
		args = append(args, spec)
	}
	args = append(args, ":(exclude).govcode")
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return "No matches.", nil
		}
		return "", fmt.Errorf("search failed: %v", err)
	}
	all := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	var lines []string
	hidden := 0
	for _, l := range all {
		file, rest, _ := strings.Cut(l, ":")
		if d, _ := t.e.rules().Decide("read_file", file); d == permissions.Deny {
			continue
		}
		if t.e.spill("search result in "+file, rest) {
			hidden++
			continue
		}
		lines = append(lines, l)
	}
	if hidden > 0 {
		lines = append(lines, fmt.Sprintf("[govcode: %d matching line(s) withheld: classification marking above this repository's level]", hidden))
	}
	if len(lines) == 0 {
		return "No matches.", nil
	}
	var b strings.Builder
	for i, l := range lines {
		if i == maxSearchResults {
			fmt.Fprintf(&b, "[... %d more matches; refine the pattern or add a glob ...]\n", len(lines)-maxSearchResults)
			break
		}
		if len(l) > maxLineWidth {
			l = l[:maxLineWidth] + " [...]"
		}
		b.WriteString(l + "\n")
	}
	return b.String(), nil
}

// ---- read_file ----

type readFile struct{ e *Env }

func (t *readFile) Spec() llm.ToolSpec {
	return llm.ToolSpec{Name: "read_file",
		Description: fmt.Sprintf("Read a file with line numbers ('  42| text'). Reads %d lines from offset unless limit is given. The 'N| ' prefix is not part of the file.", defaultReadLines),
		Properties: map[string]llm.Property{
			"path":   p("string", "File path relative to repo root"),
			"offset": p("integer", "First line to show (1-based). Default 1"),
			"limit":  p("integer", "Number of lines to show"),
		}, Required: []string{"path"}}
}

func (t *readFile) Run(_ context.Context, a map[string]any) (string, error) {
	abs, err := t.e.Jail.Resolve(str(a, "path"))
	if err != nil {
		return "", err
	}
	if err := t.e.authorize("read_file", t.e.Jail.Rel(abs)); err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %v", str(a, "path"), err)
	}
	if t.e.spill("read_file "+t.e.Jail.Rel(abs), string(data)) {
		return withheld("file "+t.e.Jail.Rel(abs), t.e), nil
	}
	if bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 {
		return "", fmt.Errorf("%s is a binary file", str(a, "path"))
	}
	lines := strings.SplitAfter(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	off := max(integer(a, "offset", 1), 1)
	lim := integer(a, "limit", defaultReadLines)
	lim = min(max(lim, 1), maxReadLines)
	if off > len(lines) && len(lines) > 0 {
		return "", fmt.Errorf("offset %d is past end of file (%d lines)", off, len(lines))
	}
	end := min(off-1+lim, len(lines))
	var b strings.Builder
	crlf := bytes.Contains(data, []byte("\r\n"))
	note := ""
	if !utf8.Valid(data) {
		note = " (not valid UTF-8: non-ASCII bytes shown as �; avoid editing those lines)"
	}
	if crlf {
		note += " (CRLF line endings; preserved automatically on edit)"
	}
	fmt.Fprintf(&b, "%s: lines %d-%d of %d%s\n", t.e.Jail.Rel(abs), off, end, len(lines), note)
	w := len(fmt.Sprint(end))
	for i := off - 1; i < end; i++ {
		l := strings.TrimRight(lines[i], "\r\n")
		if !utf8.ValidString(l) {
			l = strings.ToValidUTF8(l, "�")
		}
		if len(l) > 2000 {
			l = l[:2000] + " [line truncated]"
		}
		fmt.Fprintf(&b, "%*d| %s\n", w, i+1, l)
	}
	if end < len(lines) {
		fmt.Fprintf(&b, "[%d more lines; use offset=%d to continue]\n", len(lines)-end, end+1)
	}
	return b.String(), nil
}

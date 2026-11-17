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

	"github.com/sandy-t-shelvan/govcode/internal/llm"
)

// ---- edit_file ----

type editFile struct{ e *Env }

func (t *editFile) Spec() llm.ToolSpec {
	return llm.ToolSpec{Name: "edit_file",
		Description: "Replace exact text in a file. old_text must match the file exactly (spaces, tabs, columns) and be unique; copy it from read_file WITHOUT the line-number prefix. Include a few surrounding lines to make it unique.",
		Properties: map[string]llm.Property{
			"path":        p("string", "File path relative to repo root"),
			"old_text":    p("string", "Exact existing text to replace"),
			"new_text":    p("string", "Replacement text"),
			"replace_all": p("boolean", "Replace every occurrence (default false)"),
		}, Required: []string{"path", "old_text", "new_text"}}
}

var reLineNumPrefix = regexp.MustCompile(`(?m)^ *\d+\| ?`)

func (t *editFile) Run(ctx context.Context, a map[string]any) (string, error) {
	rel := str(a, "path")
	abs, err := t.e.Jail.Resolve(rel)
	if err != nil {
		return "", err
	}
	if err := t.e.authorize("edit_file", t.e.Jail.Rel(abs)); err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %v (use create_file for new files)", rel, err)
	}
	oldT, newT := str(a, "old_text"), str(a, "new_text")
	if t.e.spill("edit_file new_text for "+t.e.Jail.Rel(abs), newT) {
		return "", fmt.Errorf("edit refused: new_text contains a classification marking above this repository's level (%s)", t.e.MaxLevel)
	}
	if oldT == "" {
		return "", fmt.Errorf("old_text is empty; to add text, include an existing neighbouring line in old_text and new_text")
	}
	if oldT == newT {
		return "", fmt.Errorf("old_text and new_text are identical; nothing to change")
	}
	crlf := bytes.Contains(data, []byte("\r\n"))
	if crlf {
		oldT = toCRLF(oldT)
		newT = toCRLF(newT)
	}
	count := bytes.Count(data, []byte(oldT))
	note := ""
	if count == 0 {
		// Common local-model mistake: copying read_file's "  12| " prefix.
		if stripped := reLineNumPrefix.ReplaceAllString(oldT, ""); stripped != oldT && bytes.Count(data, []byte(stripped)) > 0 {
			oldT = stripped
			newT = reLineNumPrefix.ReplaceAllString(newT, "")
			count = bytes.Count(data, []byte(oldT))
			note = " (line-number prefixes were removed from old_text/new_text)"
		}
	}
	if count == 0 {
		return "", fmt.Errorf("old_text not found in %s.%s Re-read the file and copy the text exactly", rel, nearMiss(data, oldT))
	}
	if count > 1 && !boolean(a, "replace_all") {
		return "", fmt.Errorf("old_text occurs %d times in %s (lines %s); add surrounding lines to make it unique, or set replace_all", count, rel, lineList(data, oldT))
	}
	n := 1
	if boolean(a, "replace_all") {
		n = -1
	}
	updated := bytes.Replace(data, []byte(oldT), []byte(newT), n)
	fi, _ := os.Stat(abs)
	if err := os.WriteFile(abs, updated, fi.Mode().Perm()); err != nil {
		return "", err
	}
	t.e.EditGen++
	t.e.Changed[t.e.Jail.Rel(abs)] = true
	t.e.emit("edit", map[string]any{"path": t.e.Jail.Rel(abs), "replacements": count})
	if t.e.OnEdit != nil {
		t.e.OnEdit(t.e.Jail.Rel(abs))
	}
	return fmt.Sprintf("Edited %s (%d replacement(s))%s.\n%s%s", rel, map[bool]int{true: count, false: 1}[n == -1], note, fileDiff(t.e.Jail.Root, abs), t.e.postEdit(ctx, t.e.Jail.Rel(abs))), nil
}

func toCRLF(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

// nearMiss reports lines that match when whitespace is ignored, which is
// almost always the cause of a failed match (tabs vs spaces, COBOL columns).
func nearMiss(data []byte, oldT string) string {
	first := strings.TrimSpace(strings.SplitN(strings.TrimSpace(oldT), "\n", 2)[0])
	if first == "" {
		return ""
	}
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	want := norm(first)
	var hits []string
	for i, l := range strings.Split(string(data), "\n") {
		if norm(l) == want || (len(want) > 12 && strings.Contains(norm(l), want)) {
			hits = append(hits, fmt.Sprint(i+1))
			if len(hits) == 5 {
				break
			}
		}
	}
	if len(hits) == 0 {
		return ""
	}
	return fmt.Sprintf(" A line matching your first line except for whitespace is at line(s) %s: check spaces vs tabs and column positions.", strings.Join(hits, ", "))
}

func lineList(data []byte, s string) string {
	var out []string
	off := 0
	for {
		i := bytes.Index(data[off:], []byte(s))
		if i < 0 || len(out) == 8 {
			break
		}
		out = append(out, fmt.Sprint(bytes.Count(data[:off+i], []byte("\n"))+1))
		off += i + 1
	}
	return strings.Join(out, ", ")
}

func fileDiff(root, abs string) string {
	out, _ := exec.Command("git", "-C", root, "diff", "--no-color", "-U2", "--", abs).Output()
	if len(out) == 0 {
		out, _ = exec.Command("git", "-C", root, "diff", "--no-color", "--no-index", "-U2", "/dev/null", abs).Output()
	}
	return headTail(string(out), 4000)
}

// ---- create_file ----

type createFile struct{ e *Env }

func (t *createFile) Spec() llm.ToolSpec {
	return llm.ToolSpec{Name: "create_file",
		Description: "Create a new file. Fails if the file exists unless overwrite is true. Prefer edit_file for existing files.",
		Properties: map[string]llm.Property{
			"path":      p("string", "File path relative to repo root"),
			"content":   p("string", "Full file content"),
			"overwrite": p("boolean", "Replace an existing file (default false)"),
		}, Required: []string{"path", "content"}}
}

func (t *createFile) Run(ctx context.Context, a map[string]any) (string, error) {
	rel := str(a, "path")
	abs, err := t.e.Jail.Resolve(rel)
	if err != nil {
		return "", err
	}
	if err := t.e.authorize("create_file", t.e.Jail.Rel(abs)); err != nil {
		return "", err
	}
	if t.e.spill("create_file content for "+t.e.Jail.Rel(abs), str(a, "content")) {
		return "", fmt.Errorf("create refused: content contains a classification marking above this repository's level (%s)", t.e.MaxLevel)
	}
	if _, err := os.Stat(abs); err == nil && !boolean(a, "overwrite") {
		return "", fmt.Errorf("%s already exists; use edit_file, or set overwrite=true", rel)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(abs, []byte(str(a, "content")), 0o644); err != nil {
		return "", err
	}
	t.e.EditGen++
	t.e.Changed[t.e.Jail.Rel(abs)] = true
	t.e.emit("edit", map[string]any{"path": t.e.Jail.Rel(abs), "created": true})
	if t.e.OnEdit != nil {
		t.e.OnEdit(t.e.Jail.Rel(abs))
	}
	return fmt.Sprintf("Wrote %s (%d bytes).%s", rel, len(str(a, "content")), t.e.postEdit(ctx, t.e.Jail.Rel(abs))), nil
}

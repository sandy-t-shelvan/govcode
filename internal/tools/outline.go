package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
)

// ---- outline ----
//
// A dependency-free structural index for the languages legacy defense code
// is written in. It lets a model with a 32k context navigate a 10,000-line
// COBOL program or Ada body without reading it whole.

type outline struct{ e *Env }

func (t *outline) Spec() llm.ToolSpec {
	return llm.ToolSpec{Name: "outline",
		Description: "List the definitions in a source file with line numbers: C/C++ functions, structs, macros; Ada packages, procedures, functions, types; COBOL divisions, sections, paragraphs; Fortran program units.",
		Properties:  map[string]llm.Property{"path": p("string", "File path relative to repo root")},
		Required:    []string{"path"}}
}

type rule struct {
	re   *regexp.Regexp
	kind string
	name int // capture group of the name
}

var (
	cRules = []rule{
		{regexp.MustCompile(`^\s*#\s*define\s+([A-Za-z_]\w*)`), "macro", 1},
		{regexp.MustCompile(`^\s*(?:typedef\s+)?(struct|union|enum|class)\s+([A-Za-z_]\w*)\s*(?:[:{]|$)`), "", 2},
		{regexp.MustCompile(`^\s*namespace\s+([A-Za-z_]\w*)`), "namespace", 1},
		// function definition: starts in column 0, has (..., not a statement
		{regexp.MustCompile(`^[A-Za-z_][\w\s\*&:<>,~]*?\b([A-Za-z_~][\w:~]*)\s*\([^;]*$`), "function", 1},
		// K&R / GNU style: name at column 0 on its own line after the return type
		{regexp.MustCompile(`^([A-Za-z_]\w*)\s*\([^;]*$`), "function", 1},
	}
	cKeywords = map[string]bool{"if": true, "while": true, "for": true, "switch": true, "return": true, "sizeof": true, "else": true, "do": true}

	adaRules = []rule{
		{regexp.MustCompile(`(?i)^\s*(package\s+body|package)\s+([\w.]+)`), "", 2},
		{regexp.MustCompile(`(?i)^\s*(?:overriding\s+|not\s+overriding\s+)?(procedure|function)\s+("?[\w.]+"?)`), "", 2},
		{regexp.MustCompile(`(?i)^\s*(task\s+body|task\s+type|task|protected\s+body|protected\s+type|protected)\s+(\w+)`), "", 2},
		{regexp.MustCompile(`(?i)^\s*(type|subtype)\s+(\w+)\s+is`), "", 2},
		{regexp.MustCompile(`(?i)^\s*(\w+)\s*:\s*exception\s*;`), "exception", 1},
	}

	cobolRules = []rule{
		{regexp.MustCompile(`(?i)^.{0,7}\s*(IDENTIFICATION|ENVIRONMENT|DATA|PROCEDURE)\s+DIVISION`), "division", 1},
		{regexp.MustCompile(`(?i)PROGRAM-ID\.\s*([\w-]+)`), "program-id", 1},
		{regexp.MustCompile(`(?i)^.{0,7}\s{0,3}([\w-]+)\s+SECTION\s*\.`), "section", 1},
		{regexp.MustCompile(`(?i)^\s{0,7}\s{0,3}(01|77)\s+([\w-]+)`), "data", 2},
		// paragraph: a name alone in area A followed by a period
		{regexp.MustCompile(`(?i)^.{0,7}\s{0,3}([A-Z0-9][\w-]*)\s*\.\s*$`), "paragraph", 1},
	}
	cobolNonPara = map[string]bool{"EXIT": true, "GOBACK": true, "END-IF": true, "END-PERFORM": true, "STOP": true, "CONTINUE": true, "END-EVALUATE": true, "END-READ": true}

	fortranRules = []rule{
		{regexp.MustCompile(`(?i)^\s*(program|module|submodule|block\s+data)\s+(\w+)`), "", 2},
		{regexp.MustCompile(`(?i)^\s*(?:(?:pure|elemental|recursive|impure)\s+)*(?:[\w*()]+\s+)?(subroutine|function)\s+(\w+)`), "", 2},
		{regexp.MustCompile(`(?i)^\s*(type)\s*(?:,\s*\w+\s*)*(?:::)?\s*(\w+)\s*$`), "", 2},
	}
)

func langOf(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".ec", ".pc":
		return "c"
	case ".adb", ".ads", ".ada", ".a":
		return "ada"
	case ".cbl", ".cob", ".cpy", ".cobol", ".pco":
		return "cobol"
	case ".f", ".for", ".f77", ".f90", ".f95", ".f03", ".f08", ".ftn":
		return "fortran"
	}
	return ""
}

func (t *outline) Run(_ context.Context, a map[string]any) (string, error) {
	rel := str(a, "path")
	abs, err := t.e.Jail.Resolve(rel)
	if err != nil {
		return "", err
	}
	if err := t.e.authorize("outline", t.e.Jail.Rel(abs)); err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	if t.e.spill("outline "+t.e.Jail.Rel(abs), string(data)) {
		return withheld("file "+t.e.Jail.Rel(abs), t.e), nil
	}
	lang := langOf(abs)
	if lang == "" {
		return "", fmt.Errorf("outline supports C/C++, Ada, COBOL and Fortran; use search for %s", rel)
	}
	var b strings.Builder
	n := 0
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		kind, name := classify(lang, line)
		if name == "" {
			continue
		}
		fmt.Fprintf(&b, "%6d  %-10s %s\n", i+1, kind, name)
		if n++; n >= 400 {
			b.WriteString("[... truncated at 400 definitions ...]\n")
			break
		}
	}
	if n == 0 {
		return "No definitions found.", nil
	}
	return t.e.Jail.Rel(abs) + " (" + lang + "):\n" + b.String(), nil
}

func classify(lang, line string) (string, string) {
	switch lang {
	case "c":
		if strings.HasPrefix(strings.TrimSpace(line), "//") || strings.HasPrefix(strings.TrimSpace(line), "*") {
			return "", ""
		}
		for _, r := range cRules {
			m := r.re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			name := m[r.name]
			if cKeywords[name] || (r.kind == "function" && strings.HasSuffix(strings.TrimSpace(line), ";")) {
				return "", ""
			}
			kind := r.kind
			if kind == "" {
				kind = m[1]
			}
			return kind, name
		}
	case "ada":
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			return "", ""
		}
		return firstMatch(adaRules, line)
	case "cobol":
		// fixed format: column 7 '*' or '/' is a comment
		if len(line) >= 7 && (line[6] == '*' || line[6] == '/') {
			return "", ""
		}
		if strings.HasPrefix(strings.TrimSpace(line), "*>") {
			return "", ""
		}
		k, n := firstMatch(cobolRules, line)
		if k == "paragraph" && cobolNonPara[strings.ToUpper(n)] {
			return "", ""
		}
		return k, n
	case "fortran":
		if len(line) > 0 && (line[0] == 'C' || line[0] == 'c' || line[0] == '*' || line[0] == '!') && !strings.Contains(strings.ToLower(line), "contains") {
			if len(line) < 2 || line[1] == ' ' || line[0] == '!' || line[0] == '*' {
				return "", ""
			}
		}
		return firstMatch(fortranRules, line)
	}
	return "", ""
}

func firstMatch(rules []rule, line string) (string, string) {
	for _, r := range rules {
		if m := r.re.FindStringSubmatch(line); m != nil {
			kind := r.kind
			if kind == "" {
				kind = strings.ToLower(strings.Join(strings.Fields(m[1]), " "))
			}
			return kind, m[r.name]
		}
	}
	return "", ""
}

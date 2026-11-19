// Package marking detects US classification markings in text so govcode
// can stop spillage: content marked above the repository's accredited
// level must never reach the model, the log's readable summaries, or a
// proposal.
//
// Detection is deliberately conservative about false positives in source
// code: markings are recognised only in the shapes they take in documents
// and comments (banner lines, "LEVEL//CAVEAT" strings, and portion marks
// at the start of a line), always upper case.
package marking

import (
	"regexp"
	"strings"
)

type Level int

const (
	Unknown Level = -1
	U       Level = 0
	C       Level = 1
	S       Level = 2
	TS      Level = 3
)

func (l Level) String() string {
	switch l {
	case U:
		return "UNCLASSIFIED"
	case C:
		return "CONFIDENTIAL"
	case S:
		return "SECRET"
	case TS:
		return "TOP SECRET"
	}
	return "UNKNOWN"
}

var words = map[string]Level{
	"UNCLASSIFIED": U, "U": U,
	"CONFIDENTIAL": C, "C": C,
	"SECRET": S, "S": S,
	"TOP SECRET": TS, "TS": TS,
}

// ParseLevel reads the level from a policy classification string such as
// "SECRET//NOFORN", "TOP SECRET//SCI" or "UNCLASSIFIED//DEVELOPMENT".
func ParseLevel(marking string) Level {
	m := strings.ToUpper(strings.TrimSpace(marking))
	head := strings.TrimSpace(strings.SplitN(m, "//", 2)[0])
	if l, ok := words[head]; ok {
		return l
	}
	return Unknown
}

var (
	// "TOP SECRET//SI//NOFORN", "SECRET//REL TO USA, FVEY", "CONFIDENTIAL//X1"
	reBanner = regexp.MustCompile(`\b(TOP SECRET|SECRET|CONFIDENTIAL|UNCLASSIFIED)//[A-Z0-9]`)
	// A line that is only a level word (banner lines at top/bottom of a page),
	// optionally inside a comment leader.
	reBannerLine = regexp.MustCompile(`^\s*(?://|/\*+|\*|--|\*>|#|!|;|REM\s|[Cc]\s)?\s*(TOP SECRET|SECRET|CONFIDENTIAL)\s*(?:\*/)?\s*$`)
	// "CLASSIFICATION: TOP SECRET", "Classified By: ..." headers
	reHeader = regexp.MustCompile(`(?i:classification)\s*:\s*(TOP SECRET|SECRET|CONFIDENTIAL|UNCLASSIFIED)\b`)
	// Portion marks at the start of a line or comment: "(TS//SI) text", "(S) text"
	rePortion = regexp.MustCompile(`^\s*(?://+|/\*+|\*|--|\*>|#|!|;|[Cc]\s)?\s*\((TS|S|C|U)(?://[A-Z0-9][A-Z0-9 ,/-]*)?\)\s`)
	// A unified-diff hunk header. Body lines of that hunk start with one
	// marker byte ('+', '-' or ' ') that would hide a banner line or a
	// portion mark from the anchored patterns above.
	reHunk = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@`)
)

// Finding is one detected marking. It never carries the surrounding text.
type Finding struct {
	Line  int   `json:"line"`
	Level Level `json:"level"`
}

// Scan returns every marking found in text, with 1-based line numbers.
//
// Unified diffs are scanned too. Once a hunk header has been seen, the
// leading '+', '-' or space on each body line is not part of the file
// text: "-TOP SECRET" and "-(TS) payload" are the same markings as the
// file lines they came from. A '-' or '+' outside a hunk is left alone,
// so ordinary source lines are not re-read as diffs.
func Scan(text string) []Finding {
	var out []Finding
	inHunk := false
	for i, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "diff --git ") || strings.HasPrefix(line, "diff --cc ") {
			inHunk = false
		} else if strings.HasPrefix(line, "@@") && reHunk.MatchString(line) {
			inHunk = true
		}
		scanned := line
		if inHunk && line != "" {
			switch line[0] {
			case '+', '-', ' ':
				scanned = line[1:]
			}
		}
		if l := lineLevel(scanned); l != Unknown {
			out = append(out, Finding{Line: i + 1, Level: l})
		}
	}
	return out
}

func lineLevel(line string) Level {
	best := Unknown
	upd := func(w string) {
		if l, ok := words[w]; ok && l > best {
			best = l
		}
	}
	for _, m := range reBanner.FindAllStringSubmatch(line, -1) {
		upd(m[1])
	}
	if m := reBannerLine.FindStringSubmatch(line); m != nil {
		upd(m[1])
	}
	if m := reHeader.FindStringSubmatch(line); m != nil {
		upd(m[1])
	}
	if m := rePortion.FindStringSubmatch(line); m != nil {
		upd(m[1])
	}
	return best
}

// Above returns the findings whose level exceeds max.
func Above(text string, max Level) []Finding {
	var out []Finding
	for _, f := range Scan(text) {
		if f.Level > max {
			out = append(out, f)
		}
	}
	return out
}

// Highest returns the highest level among findings (Unknown if none).
func Highest(fs []Finding) Level {
	h := Unknown
	for _, f := range fs {
		if f.Level > h {
			h = f.Level
		}
	}
	return h
}

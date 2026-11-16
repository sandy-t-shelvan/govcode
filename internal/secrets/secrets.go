// Package secrets finds credentials in the lines a proposal adds. A
// finding reports file, line and kind only; the matched value is never
// returned, logged or displayed.
package secrets

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

type Finding struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Kind string `json:"kind"`
}

type rule struct {
	kind string
	re   *regexp.Regexp
}

var rules = []rule{
	{"private key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)},
	{"AWS access key id", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"GitLab token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`)},
	{"JSON web token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"credentials in URL", regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@"']+:[^\s/@"']{3,}@`)},
	{"password assignment", regexp.MustCompile(`(?i)\b[a-z0-9_.-]*(?:password|passwd|pwd|passphrase|secret|api[_-]?key|auth[_-]?token|access[_-]?token)[a-z0-9_]*["']?\s*(?:[:=]|:=|=>)\s*["']([^"'\s]{6,})["']`)},
}

var placeholder = regexp.MustCompile(`(?i)^(?:x+|\*+|changeme|change_me|password|secret|example|placeholder|dummy|test|<.*>|\$\{.*\}|%\w+%|\$\w+)$`)

var reQuoted = regexp.MustCompile(`["']([A-Za-z0-9+/=_-]{40,})["']`)

// ScanDiff scans the added lines of a unified diff. allow holds regexps
// (from policy only) that suppress a finding when they match the line.
func ScanDiff(diff string, allow []*regexp.Regexp) []Finding {
	var out []Finding
	file := ""
	newLine := 0
	for _, l := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(l, "+++ "):
			file = strings.TrimPrefix(strings.TrimPrefix(l, "+++ "), "b/")
			continue
		case strings.HasPrefix(l, "@@"):
			newLine = hunkStart(l)
			continue
		case strings.HasPrefix(l, "---"), strings.HasPrefix(l, "diff --git"), strings.HasPrefix(l, "index "):
			continue
		case strings.HasPrefix(l, "-"):
			continue
		case strings.HasPrefix(l, "+"):
			text := l[1:]
			if k := ScanLine(text, allow); k != "" {
				out = append(out, Finding{File: file, Line: newLine, Kind: k})
			}
			newLine++
		default:
			newLine++
		}
	}
	return out
}

// ScanLine returns the kind of secret in line, or "".
func ScanLine(line string, allow []*regexp.Regexp) string {
	for _, a := range allow {
		if a.MatchString(line) {
			return ""
		}
	}
	for _, r := range rules {
		m := r.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if r.kind == "password assignment" && placeholder.MatchString(m[1]) {
			continue
		}
		return r.kind
	}
	for _, m := range reQuoted.FindAllStringSubmatch(line, -1) {
		if isHex(m[1]) {
			continue // hashes and checksums are expected in code
		}
		if entropy(m[1]) >= 4.5 {
			return "high-entropy string"
		}
	}
	return ""
}

func hunkStart(h string) int {
	// @@ -a,b +c,d @@
	i := strings.Index(h, "+")
	if i < 0 {
		return 0
	}
	rest := h[i+1:]
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		end = len(rest)
	}
	n, _ := strconv.Atoi(rest[:end])
	return n
}

func isHex(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

func entropy(s string) float64 {
	freq := map[rune]float64{}
	for _, c := range s {
		freq[c]++
	}
	var h float64
	n := float64(len(s))
	for _, f := range freq {
		p := f / n
		h -= p * math.Log2(p)
	}
	return h
}

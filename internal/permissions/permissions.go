// Package permissions decides whether a tool call is allowed, needs a
// human, or is denied, from rules in the site policy:
//
//	"allow": ["run_command(make *)", "edit_file(src/**)"]
//	"ask":   ["edit_file(Makefile)", "run_command(git *)"]
//	"deny":  ["read_file(keys/**)", "run_command(rm *)"]
//
// Precedence is deny > ask > allow. With no matching rule, run_command
// asks and every other tool is allowed (paths are already confined to the
// repository by the jail). A command containing shell metacharacters is
// never auto-allowed: an allow match is downgraded to ask.
package permissions

import (
	"fmt"
	"path"
	"strings"
)

type Decision int

const (
	Allow Decision = iota
	Ask
	Deny
)

func (d Decision) String() string { return [...]string{"allow", "ask", "deny"}[d] }

type rule struct {
	text    string
	tool    string
	pattern string // "" matches any subject
}

type Rules struct {
	allow, ask, deny []rule
}

// PathTools take a repository-relative path as their subject.
var PathTools = map[string]bool{"read_file": true, "edit_file": true, "create_file": true, "outline": true, "list_files": true, "search": true}

// ShellMeta are constructs that chain or substitute commands.
var ShellMeta = []string{";", "&&", "||", "|", "`", "$(", ">", "<", "\n", "\r", "&"}

func Parse(allow, ask, deny []string) (*Rules, error) {
	r := &Rules{}
	for _, set := range []struct {
		src []string
		dst *[]rule
	}{{allow, &r.allow}, {ask, &r.ask}, {deny, &r.deny}} {
		for _, s := range set.src {
			ru, err := parseRule(s)
			if err != nil {
				return nil, err
			}
			*set.dst = append(*set.dst, ru)
		}
	}
	return r, nil
}

func parseRule(s string) (rule, error) {
	s = strings.TrimSpace(s)
	open := strings.IndexByte(s, '(')
	if open < 0 {
		if s == "" || strings.ContainsAny(s, " )*") {
			return rule{}, fmt.Errorf("bad permission rule %q: want tool or tool(pattern)", s)
		}
		return rule{text: s, tool: s}, nil
	}
	if !strings.HasSuffix(s, ")") || open == 0 {
		return rule{}, fmt.Errorf("bad permission rule %q: want tool(pattern)", s)
	}
	return rule{text: s, tool: s[:open], pattern: s[open+1 : len(s)-1]}, nil
}

// FromAllowlist converts the legacy commands.allowlist prefixes.
func FromAllowlist(prefixes []string) []string {
	var out []string
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, "run_command("+p+")", "run_command("+p+" *)")
		}
	}
	return out
}

// Decide returns the decision for tool acting on subject and the rule that
// produced it ("default" if none matched).
func (r *Rules) Decide(tool, subject string) (Decision, string) {
	if r == nil {
		r = &Rules{}
	}
	if ru, ok := r.match(r.deny, tool, subject); ok {
		return Deny, ru
	}
	if ru, ok := r.match(r.ask, tool, subject); ok {
		return Ask, ru
	}
	if ru, ok := r.match(r.allow, tool, subject); ok {
		if tool == "run_command" && HasShellMeta(subject) {
			return Ask, ru + " (downgraded: shell metacharacters)"
		}
		return Allow, ru
	}
	if tool == "run_command" {
		return Ask, "default"
	}
	return Allow, "default"
}

func (r *Rules) match(rs []rule, tool, subject string) (string, bool) {
	for _, ru := range rs {
		if ru.tool != tool && ru.tool != "*" {
			continue
		}
		if ru.pattern == "" || ru.pattern == "*" || ru.pattern == "**" {
			return ru.text, true
		}
		if PathTools[tool] {
			if PathMatch(ru.pattern, subject) {
				return ru.text, true
			}
		} else if wildcard(ru.pattern, subject) {
			return ru.text, true
		}
	}
	return "", false
}

func HasShellMeta(s string) bool {
	for _, m := range ShellMeta {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// wildcard matches '*' against any run of characters (commands).
func wildcard(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		j := strings.Index(s, parts[i])
		if j < 0 {
			return false
		}
		s = s[j+len(parts[i]):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// PathMatch supports '**' (any number of directories) plus path.Match
// syntax per segment. A pattern without '/' matches the base name at any
// depth; a pattern ending in "/**" also matches the directory itself.
func PathMatch(pattern, name string) bool {
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	if !strings.Contains(pattern, "/") {
		ok, _ := path.Match(pattern, path.Base(name))
		return ok
	}
	return segs(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func segs(ps, ns []string) bool {
	for len(ps) > 0 {
		if ps[0] == "**" {
			for i := 0; i <= len(ns); i++ {
				if segs(ps[1:], ns[i:]) {
					return true
				}
			}
			return false
		}
		if len(ns) == 0 {
			return false
		}
		if ok, _ := path.Match(ps[0], ns[0]); !ok {
			return false
		}
		ps, ns = ps[1:], ns[1:]
	}
	return len(ns) == 0
}

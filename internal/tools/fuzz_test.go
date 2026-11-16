package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzJailResolve: no model-supplied path may resolve outside the root or
// into a denied component, however it is spelled.
func FuzzJailResolve(f *testing.F) {
	root := f.TempDir()
	os.MkdirAll(filepath.Join(root, "src", "sub"), 0o755)
	os.Mkdir(filepath.Join(root, ".git"), 0o755)
	os.Symlink("/etc", filepath.Join(root, "src", "etc-link"))
	os.Symlink("..", filepath.Join(root, "src", "up"))
	j, err := NewJail(root)
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"a.c", "../x", "src/../../x", "/etc/passwd", ".git/config", "src/etc-link/passwd",
		"src/up/../x", "src/./sub/../../../x", "./.git", "src//sub", "src/sub/..\\..\\x", "\x00", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		abs, err := j.Resolve(p)
		if err != nil {
			return
		}
		if abs != j.Root && !strings.HasPrefix(abs, j.Root+string(filepath.Separator)) {
			t.Fatalf("Resolve(%q) = %q escapes root %q", p, abs, j.Root)
		}
		rel, _ := filepath.Rel(j.Root, abs)
		for _, c := range strings.Split(rel, string(filepath.Separator)) {
			if c == ".git" || c == ".govcode" {
				t.Fatalf("Resolve(%q) = %q reaches denied component", p, abs)
			}
		}
		// The deepest existing ancestor must also be inside the root.
		probe := abs
		for {
			if _, err := os.Lstat(probe); err == nil {
				break
			}
			probe = filepath.Dir(probe)
		}
		real, err := filepath.EvalSymlinks(probe)
		if err == nil && real != j.Root && !strings.HasPrefix(real, j.Root+string(filepath.Separator)) {
			t.Fatalf("Resolve(%q) = %q, real path %q escapes root via symlink", p, abs, real)
		}
	})
}

// FuzzAllowlisted: no command containing a shell metacharacter may be
// auto-approved, whatever the allowlist.
func FuzzAllowlisted(f *testing.F) {
	for _, s := range []string{"make", "make test", "make;id", "make && id", "make $(id)", "make `id`", "make|x", "make\nid", "make >/x", "make &"} {
		f.Add(s)
	}
	e := &Env{Allowlist: []string{"make", "gnatmake", "cobc"}}
	f.Fuzz(func(t *testing.T, cmd string) {
		if !e.allowlisted(cmd) {
			return
		}
		for _, m := range shellMeta {
			if strings.Contains(cmd, m) {
				t.Fatalf("allowlisted %q despite metacharacter %q", cmd, m)
			}
		}
	})
}

// FuzzOutline: arbitrary file content never panics the outline parsers.
func FuzzOutline(f *testing.F) {
	for _, s := range []string{cobol, "package body X is\nend X;", "int\nmain(void)\n{", "      PROGRAM P\n      END"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		for _, lang := range []string{"c", "ada", "cobol", "fortran"} {
			for _, l := range strings.Split(line, "\n") {
				classify(lang, l)
			}
		}
	})
}

// Package tools implements the agent's tools. Every file path goes through
// Jail, which confines access to one worktree of one repository.
package tools

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Jail confines paths to Root. Root is a git worktree for a single repo.
type Jail struct {
	Root string // absolute, symlinks resolved
}

// Path components the model may never touch: git internals (history,
// hooks, config) and govcode state.
var deniedComponents = map[string]bool{".git": true, ".govcode": true}

func NewJail(root string) (*Jail, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	return &Jail{Root: real}, nil
}

var ErrOutsideRepo = errors.New("path is outside the repository")

// Resolve maps a model-supplied path (relative to the repo root, or absolute
// inside it) to an absolute path, rejecting escapes via "..", absolute paths
// elsewhere, symlinks pointing out, and denied components.
func (j *Jail) Resolve(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", errors.New("path is empty")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("path contains NUL")
	}
	var abs string
	if filepath.IsAbs(p) {
		abs = filepath.Clean(p)
	} else {
		abs = filepath.Join(j.Root, p)
	}
	if !j.within(abs) {
		return "", fmt.Errorf("%w: %s", ErrOutsideRepo, p)
	}
	rel, _ := filepath.Rel(j.Root, abs)
	for _, c := range strings.Split(rel, string(filepath.Separator)) {
		if deniedComponents[c] {
			return "", fmt.Errorf("access to %s is not permitted", c)
		}
	}
	// Resolve symlinks on the deepest existing ancestor so a link inside the
	// repo cannot point outside it.
	probe := abs
	for {
		if _, err := os.Lstat(probe); err == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	real, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return "", err
	}
	if !j.within(real) {
		return "", fmt.Errorf("%w: %s (symlink escapes repository)", ErrOutsideRepo, p)
	}
	return abs, nil
}

func (j *Jail) within(p string) bool {
	return p == j.Root || strings.HasPrefix(p, j.Root+string(filepath.Separator))
}

// Rel returns the repo-relative form of an absolute path for display.
func (j *Jail) Rel(abs string) string {
	r, err := filepath.Rel(j.Root, abs)
	if err != nil {
		return abs
	}
	return filepath.ToSlash(r)
}

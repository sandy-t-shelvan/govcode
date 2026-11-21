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
// inside it) to the absolute path that will actually be opened. ".." and
// absolute paths outside the repo are rejected, and so is a symlink that
// points out of the repo. Symlinks that stay inside are resolved: the
// returned path is the target, so a later permission check sees the file
// that would be read or written, not the link's own name. A path that lands
// in .git or .govcode, either as requested or after resolution, is rejected.
func (j *Jail) Resolve(p string) (string, error) {
	abs, err := j.cleanAbs(p)
	if err != nil {
		return "", err
	}
	if err := j.denyComponents(abs); err != nil {
		return "", err
	}
	// Resolve symlinks on the deepest existing ancestor so a link inside the
	// repo cannot point outside it, including a link to .git or .govcode.
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
	if probe != abs {
		rest, rerr := filepath.Rel(probe, abs)
		if rerr != nil {
			return "", rerr
		}
		real = filepath.Join(real, rest)
	}
	real = filepath.Clean(real)
	if !j.within(real) {
		return "", fmt.Errorf("%w: %s (symlink escapes repository)", ErrOutsideRepo, p)
	}
	if err := j.denyComponents(real); err != nil {
		return "", err
	}
	return real, nil
}

// cleanAbs is the cleaned absolute path of p with no symlink resolution.
func (j *Jail) cleanAbs(p string) (string, error) {
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
	return abs, nil
}

func (j *Jail) denyComponents(abs string) error {
	rel, err := filepath.Rel(j.Root, abs)
	if err != nil {
		return err
	}
	for _, c := range strings.Split(rel, string(filepath.Separator)) {
		if deniedComponents[c] {
			return fmt.Errorf("access to %s is not permitted", c)
		}
	}
	return nil
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

// Package gitx wraps the git operations govcode needs. It shells out to the
// system git (listed in the SBOM) so it works with any on-prem remote
// (GitLab, Bitbucket Server, Gitea, bare SSH) without network code here.
package gitx

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

type Repo struct {
	Root      string // top-level of the main worktree
	CommonDir string // shared .git directory
}

func run(dir string, env []string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	// Never prompt, never use a pager, ignore user/global hooks paths.
	cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "GIT_OPTIONAL_LOCKS=0")
	cmd.Env = append(cmd.Env, env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func Git(dir string, args ...string) (string, error) { return run(dir, nil, args...) }

func Open(dir string) (*Repo, error) {
	top, err := Git(dir, "rev-parse", "--path-format=absolute", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("not a git repository: %s", dir)
	}
	cd, err := Git(dir, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return nil, err
	}
	root, _ := filepath.EvalSymlinks(strings.TrimSpace(top))
	common, _ := filepath.EvalSymlinks(strings.TrimSpace(cd))
	// If dir is a linked worktree, Root should be the main worktree.
	if filepath.Base(common) == ".git" {
		root = filepath.Dir(common)
	}
	return &Repo{Root: root, CommonDir: common}, nil
}

func (r *Repo) Git(args ...string) (string, error) { return Git(r.Root, args...) }

func (r *Repo) RevParse(rev string) (string, error) {
	out, err := r.Git("rev-parse", "--verify", rev+"^{commit}")
	return strings.TrimSpace(out), err
}

func (r *Repo) CurrentBranch() string {
	out, err := r.Git("symbolic-ref", "--short", "-q", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// AddWorktree creates a detached-from-target branch at base in path.
func (r *Repo) AddWorktree(path, branch, base string) error {
	_, err := r.Git("worktree", "add", "-q", "-b", branch, path, base)
	return err
}

func (r *Repo) RemoveWorktree(path string) error {
	_, err := r.Git("worktree", "remove", "--force", path)
	return err
}

// Author identifies a commit author/committer.
type Author struct{ Name, Email string }

func (a Author) env(prefix string) []string {
	return []string{"GIT_" + prefix + "_NAME=" + a.Name, "GIT_" + prefix + "_EMAIL=" + a.Email}
}

// CommitPaths stages exactly the given repo-relative paths (additions,
// modifications or deletions) and commits. Build outputs and other side
// effects of commands are deliberately not included. Hooks are disabled:
// repository hooks are code the model could have written.
func CommitPaths(wt string, paths []string, msg string, author, committer Author) (string, error) {
	if len(paths) == 0 {
		return "", fmt.Errorf("no changes to commit")
	}
	if _, err := run(wt, nil, append([]string{"add", "-A", "--"}, paths...)...); err != nil {
		return "", err
	}
	if out, _ := run(wt, nil, "diff", "--cached", "--name-only"); strings.TrimSpace(out) == "" {
		return "", fmt.Errorf("no changes to commit")
	}
	env := append(author.env("AUTHOR"), committer.env("COMMITTER")...)
	if _, err := run(wt, env, "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "-m", msg); err != nil {
		return "", err
	}
	out, err := run(wt, nil, "rev-parse", "HEAD")
	return strings.TrimSpace(out), err
}

// CommitAll stages everything in the worktree and commits.
func CommitAll(wt string, msg string, author, committer Author) (string, error) {
	return CommitPaths(wt, []string{"."}, msg, author, committer)
}

// Untracked lists worktree changes not staged (e.g. build outputs).
func Untracked(wt string) []string {
	out, _ := run(wt, nil, "status", "--porcelain", "--untracked-files=all")
	var fs []string
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if len(l) > 3 {
			fs = append(fs, strings.TrimSpace(l[3:]))
		}
	}
	return fs
}

func (r *Repo) Diff(base, head string) (string, error) {
	return r.Git("diff", "--no-color", "--no-ext-diff", "--binary", base, head)
}

func (r *Repo) DiffStat(base, head string) (string, error) {
	return r.Git("diff", "--no-color", "--stat", base, head)
}

// MergeTree computes the tree that results from merging head onto target
// without touching any worktree (git >= 2.38). Returns conflict=true if the
// merge is not clean.
func (r *Repo) MergeTree(target, head string) (tree string, conflict bool, err error) {
	out, err := r.Git("merge-tree", "--write-tree", "--no-messages", target, head)
	first := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if err != nil {
		if first != "" && len(first) == 40 {
			return first, true, nil
		}
		return "", false, err
	}
	return first, false, nil
}

func (r *Repo) TreeOf(rev string) (string, error) {
	out, err := r.Git("rev-parse", rev+"^{tree}")
	return strings.TrimSpace(out), err
}

// CommitTree creates a commit object with the given tree and parents.
func (r *Repo) CommitTree(tree string, parents []string, msg string, author, committer Author) (string, error) {
	args := []string{"commit-tree", tree, "-m", msg}
	for _, p := range parents {
		args = append(args, "-p", p)
	}
	env := append(author.env("AUTHOR"), committer.env("COMMITTER")...)
	out, err := run(r.Root, env, args...)
	return strings.TrimSpace(out), err
}

// UpdateRef moves ref to newRev only if it currently points at oldRev.
func (r *Repo) UpdateRef(ref, newRev, oldRev, reason string) error {
	_, err := r.Git("update-ref", "-m", reason, ref, newRev, oldRev)
	return err
}

// WorktreeFor returns the path of a worktree that has branch checked out.
func (r *Repo) WorktreeFor(branch string) string {
	out, err := r.Git("worktree", "list", "--porcelain")
	if err != nil {
		return ""
	}
	var path string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "worktree ") {
			path = strings.TrimPrefix(l, "worktree ")
		}
		if l == "branch refs/heads/"+branch {
			return path
		}
	}
	return ""
}

// Summary gives the model a quick map of a large repo without reading it:
// file counts by extension and top-level directories.
func Summary(dir string) string {
	out, err := Git(dir, "ls-files", "-z")
	if err != nil {
		return ""
	}
	files := strings.Split(strings.TrimRight(out, "\x00"), "\x00")
	ext := map[string]int{}
	top := map[string]int{}
	for _, f := range files {
		if f == "" {
			continue
		}
		e := strings.ToLower(filepath.Ext(f))
		if e == "" {
			e = filepath.Base(f)
		}
		ext[e]++
		if i := strings.Index(f, "/"); i > 0 {
			top[f[:i]+"/"]++
		} else {
			top[f]++
		}
	}
	return fmt.Sprintf("%d tracked files. By type: %s\nTop level: %s\n", len(files), topN(ext, 12), topN(top, 20))
}

func topN(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	var xs []kv
	for k, v := range m {
		xs = append(xs, kv{k, v})
	}
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && (xs[j].v > xs[j-1].v || (xs[j].v == xs[j-1].v && xs[j].k < xs[j-1].k)); j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
	var parts []string
	for i, x := range xs {
		if i == n {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(xs)-n))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", x.k, x.v))
	}
	return strings.Join(parts, ", ")
}

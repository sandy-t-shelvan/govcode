package gitx

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Checkpoints are commits recording the worktree's agent-edited files after
// each edit. They are built with a private index, so the worktree's own
// index and the proposal branch are untouched, and stored under
// refs/govcode/checkpoints/<id>/<n>. Each checkpoint's tree is the base
// tree plus the changed paths (additions, edits and deletions).

func checkpointRef(id string, n int) string {
	return fmt.Sprintf("refs/govcode/checkpoints/%s/%d", id, n)
}

// Checkpoint records paths (repo-relative) of worktree wt as checkpoint n
// on top of base and returns the commit id.
func Checkpoint(wt, id string, n int, base string, paths []string) (string, error) {
	idx, err := os.CreateTemp("", "govcode-ckpt-index-*")
	if err != nil {
		return "", err
	}
	idx.Close()
	os.Remove(idx.Name()) // git creates it; a zero-length file is not a valid index
	defer os.Remove(idx.Name())
	env := []string{"GIT_INDEX_FILE=" + idx.Name()}
	if _, err := run(wt, env, "read-tree", base); err != nil {
		return "", err
	}
	if len(paths) > 0 {
		if _, err := run(wt, env, append([]string{"add", "-A", "--"}, paths...)...); err != nil {
			return "", err
		}
	}
	tree, err := run(wt, env, "write-tree")
	if err != nil {
		return "", err
	}
	parent := base
	if n > 1 {
		if p, err := run(wt, nil, "rev-parse", "--verify", "-q", checkpointRef(id, n-1)); err == nil {
			parent = strings.TrimSpace(p)
		}
	}
	who := []string{"GIT_AUTHOR_NAME=govcode", "GIT_AUTHOR_EMAIL=govcode@localhost", "GIT_COMMITTER_NAME=govcode", "GIT_COMMITTER_EMAIL=govcode@localhost"}
	c, err := run(wt, who, "commit-tree", strings.TrimSpace(tree), "-p", parent, "-m", fmt.Sprintf("govcode checkpoint %s #%d", id, n))
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(c)
	if _, err := run(wt, nil, "update-ref", checkpointRef(id, n), commit); err != nil {
		return "", err
	}
	return commit, nil
}

// CheckpointInfo describes one checkpoint.
type CheckpointInfo struct {
	N      int
	Commit string
	Files  []string // paths that differ from base
}

// Checkpoints lists the checkpoints of a proposal, oldest first.
func Checkpoints(dir, id, base string) ([]CheckpointInfo, error) {
	out, err := run(dir, nil, "for-each-ref", "--format=%(refname) %(objectname)", "refs/govcode/checkpoints/"+id+"/")
	if err != nil {
		return nil, err
	}
	var cs []CheckpointInfo
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		n, err := strconv.Atoi(filepath.Base(f[0]))
		if err != nil {
			continue
		}
		names, _ := run(dir, nil, "diff", "--name-only", base, f[1])
		cs = append(cs, CheckpointInfo{N: n, Commit: f[1], Files: splitLines(names)})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].N < cs[j].N })
	return cs, nil
}

// Rewind restores every path that differs between base, checkpoint n and
// the current worktree to its content at checkpoint n (removing paths that
// do not exist there), and deletes later checkpoints. It returns the paths
// that differ from base at checkpoint n. n = 0 rewinds to base.
func Rewind(wt, id, base string, n int, current []string) ([]string, error) {
	target := base
	if n > 0 {
		t, err := run(wt, nil, "rev-parse", "--verify", "-q", checkpointRef(id, n))
		if err != nil {
			return nil, fmt.Errorf("proposal %s has no checkpoint %d", id, n)
		}
		target = strings.TrimSpace(t)
	}
	atTarget, err := run(wt, nil, "diff", "--name-only", base, target)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, p := range append(splitLines(atTarget), current...) {
		set[p] = true
	}
	for p := range set {
		if strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			return nil, fmt.Errorf("refusing path %q", p)
		}
		if _, err := run(wt, nil, "cat-file", "-e", target+":"+p); err == nil {
			if _, err := run(wt, nil, "checkout", target, "--", p); err != nil {
				return nil, err
			}
			continue
		}
		os.Remove(filepath.Join(wt, p))
		run(wt, nil, "rm", "-q", "--cached", "--ignore-unmatch", "--", p)
	}
	// Restored files must not stay staged: the proposal commit stages
	// exactly the changed paths itself.
	run(wt, nil, "reset", "-q")
	later, _ := Checkpoints(wt, id, base)
	for _, c := range later {
		if c.N > n {
			run(wt, nil, "update-ref", "-d", checkpointRef(id, c.N))
		}
	}
	return splitLines(atTarget), nil
}

// DeleteCheckpoints removes all checkpoint refs of a proposal.
func DeleteCheckpoints(dir, id, base string) {
	cs, _ := Checkpoints(dir, id, base)
	for _, c := range cs {
		run(dir, nil, "update-ref", "-d", checkpointRef(id, c.N))
	}
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

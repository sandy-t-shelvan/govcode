package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/agent"
	"github.com/sandy-t-shelvan/govcode/internal/gitx"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/marking"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/secrets"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

type RunOptions struct {
	Task        string
	Interactive bool
	Verbose     bool
	Backend     llm.Backend // override (tests / eval)
}

// Run executes one task and produces a proposal. It never touches the
// target branch.
func (a *App) Run(ctx context.Context, o RunOptions) (*proposal.Proposal, error) {
	p := a.Policy
	if !p.MayPropose(a.User.Username) {
		return nil, fmt.Errorf("%s is not permitted to propose changes in this repository", a.User.Username)
	}
	backend := o.Backend
	if backend == nil {
		var err error
		if backend, err = a.Backend(); err != nil {
			return nil, err
		}
	}
	base, err := a.Repo.RevParse("refs/heads/" + p.TargetBranch)
	if err != nil {
		return nil, fmt.Errorf("target branch %s: %w", p.TargetBranch, err)
	}
	id := proposal.NewID()
	sess := a.Session(id)
	maxLevel := p.MaxLevel()
	if fs := marking.Above(o.Task, maxLevel); len(fs) > 0 && maxLevel != marking.Unknown {
		sess.Record("spillage_blocked", map[string]any{"proposal": id, "where": "task", "level": marking.Highest(fs).String(), "repository_level": maxLevel.String()})
		return nil, fmt.Errorf("task refused: it contains a %s marking, above this repository's %s accreditation. The event has been audit-logged; report it per your spillage procedure", marking.Highest(fs), maxLevel)
	}
	rules, err := p.Rules()
	if err != nil {
		return nil, err
	}
	branch := proposal.BranchFor(id)
	wt := filepath.Join(p.StateDir, "worktrees", id)
	if err := os.MkdirAll(filepath.Dir(wt), 0o2770); err != nil {
		return nil, err
	}
	th := sha256.Sum256([]byte(o.Task))
	modelID := backend.ModelName()
	digest := ""
	if a.Model != nil {
		modelID = a.Model.ID + " (" + backend.ModelName() + ")"
		digest = a.Model.Serve.OllamaDigest
	}
	taskEntry, err := sess.RecordEntry("task", map[string]any{
		"proposal": id, "task": o.Task, "task_sha256": hex.EncodeToString(th[:]), "base": base, "target": p.TargetBranch,
		"branch": branch, "model": modelID, "model_digest": digest, "num_ctx": backend.Options().NumCtx,
	})
	if err != nil {
		return nil, err
	}
	if err := a.Repo.AddWorktree(wt, branch, base); err != nil {
		return nil, err
	}
	defer a.Repo.RemoveWorktree(wt)

	runner, err := tools.NewRunner(p.Sandbox.Mode, wt, p.Sandbox.ExtraROPaths, p.Sandbox.Env)
	if err != nil {
		return nil, err
	}
	jail, err := tools.NewJail(wt)
	if err != nil {
		return nil, err
	}
	events := make(chan tools.Event, 64)
	done := make(chan struct{})
	go func() {
		for ev := range events {
			sess.Record("tool_event:"+ev.Kind, ev.Data)
		}
		close(done)
	}()
	env := &tools.Env{Jail: jail, Runner: runner, TestCommand: p.Tests.Command, TestTimeout: p.TestTimeout(),
		Perms: rules, MaxLevel: maxLevel, RequireTest: p.Tests.RequirePass, Events: events}
	if o.Interactive && p.Commands.PromptForOthers {
		env.Approver = &TTYApprover{User: a.User, Rec: sess}
	}
	fmt.Fprintf(a.Out, "govcode %s | %s | proposal %s\nmodel %s, num_ctx=%d, sandbox=%v\n",
		p.Classification, a.User, id, modelID, backend.Options().NumCtx, runner.Sandboxed())
	ag := &agent.Agent{Backend: backend, Tools: tools.NewSet(env), Rec: sess,
		Cfg: agent.Config{MaxTurns: p.MaxTurns, Out: a.Out, Verbose: o.Verbose}}
	start := time.Now()
	res, runErr := ag.Run(ctx, o.Task, agent.RepoContext{Summary: gitx.Summary(wt), TestCommand: p.Tests.Command})
	close(events)
	<-done
	if sess.Err != nil {
		return nil, fmt.Errorf("audit failure, run aborted: %w", sess.Err)
	}
	if res == nil {
		return nil, runErr
	}
	sess.Record("run_end", map[string]any{"proposal": id, "metrics": res.Metrics, "duration_s": time.Since(start).Seconds(), "error": errString(runErr)})

	status := proposal.StatusReady
	switch {
	case !res.Metrics.Finished:
		status = proposal.StatusIncomplete
	case p.Tests.Command != "" && !env.LastTestPass:
		status = proposal.StatusTestsFailed
	}
	summary := res.Summary
	if summary == "" {
		summary = "(agent stopped: " + res.Metrics.StopReason + ")"
	}
	msg := fmt.Sprintf("govcode proposal %s\n\n%s\n\nTask: %s\n", id, summary, o.Task)
	author := gitx.Author{Name: a.User.Username, Email: a.User.Username + "@" + a.User.Host}
	files := res.Changed
	sort.Strings(files)
	head, cerr := gitx.CommitPaths(wt, files, msg, author, gitx.Author{Name: "govcode", Email: "govcode@" + a.User.Host})
	if side := gitx.Untracked(wt); len(side) > 0 {
		sess.Record("side_effects_not_proposed", map[string]any{"proposal": id, "files": strings.Join(side, ",")})
	}
	if cerr != nil {
		fmt.Fprintf(a.Out, "\nNo changes were made (%s). Stop reason: %s\n", cerr, res.Metrics.StopReason)
		a.Repo.Git("branch", "-D", branch)
		return nil, runErr
	}
	diff, err := a.Repo.Diff(base, head)
	if err != nil {
		return nil, err
	}
	var blocked []string
	if maxLevel != marking.Unknown {
		if fs := marking.Above(addedLines(diff), maxLevel); len(fs) > 0 {
			blocked = append(blocked, fmt.Sprintf("spillage: %d added line(s) marked %s, above repository level %s", len(fs), marking.Highest(fs), maxLevel))
			sess.Record("spillage_blocked", map[string]any{"proposal": id, "where": "proposal diff", "lines": len(fs), "level": marking.Highest(fs).String()})
		}
	}
	for _, f := range secrets.ScanDiff(diff, p.SecretAllow()) {
		blocked = append(blocked, fmt.Sprintf("secret: %s at %s:%d", f.Kind, f.File, f.Line))
		sess.Record("secret_found", map[string]any{"proposal": id, "file": f.File, "line": f.Line, "kind": f.Kind})
	}
	if len(blocked) > 0 {
		status = proposal.StatusBlocked
	}
	prop := &proposal.Proposal{ID: id, Created: time.Now().UTC().Format(time.RFC3339), Classification: p.Classification,
		Repo: a.Repo.Root, Task: o.Task, TaskSHA256: hex.EncodeToString(th[:]), Summary: res.Summary, Proposer: a.User,
		Target: p.TargetBranch, Branch: branch, Base: base, Head: head, DiffSHA256: proposal.DiffHash(diff), Files: files,
		Tests: proposal.Tests{Command: p.Tests.Command, Runs: env.TestRuns, Passed: env.LastTestPass},
		Model: modelID, ModelDigest: digest, Status: status, Blocked: blocked, AuditSession: id, AuditTaskSeq: taskEntry.Seq, Metrics: res.Metrics}
	if err := a.Store.Save(prop, diff, a.Signer); err != nil {
		return nil, err
	}
	diffObj, _ := a.Log.PutObject([]byte(diff))
	sess.Record("proposal", map[string]any{"proposal": id, "status": status, "base": base, "head": head, "branch": branch,
		"diff_sha256": prop.DiffSHA256, "diff_object": diffObj, "files": strings.Join(files, ",")})
	return prop, runErr
}

// addedLines returns only the "+" lines of a unified diff, so the guard
// judges what the proposal introduces, not what it removes.
func addedLines(diff string) string {
	var b strings.Builder
	for _, l := range strings.Split(diff, "\n") {
		if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++ ") {
			b.WriteString(l[1:])
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

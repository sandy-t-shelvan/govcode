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
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
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
		Allowlist: p.Commands.Allowlist, RequireTest: p.Tests.RequirePass, Events: events}
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
	prop := &proposal.Proposal{ID: id, Created: time.Now().UTC().Format(time.RFC3339), Classification: p.Classification,
		Repo: a.Repo.Root, Task: o.Task, TaskSHA256: hex.EncodeToString(th[:]), Summary: res.Summary, Proposer: a.User,
		Target: p.TargetBranch, Branch: branch, Base: base, Head: head, DiffSHA256: proposal.DiffHash(diff), Files: files,
		Tests: proposal.Tests{Command: p.Tests.Command, Runs: env.TestRuns, Passed: env.LastTestPass},
		Model: modelID, ModelDigest: digest, Status: status, AuditSession: id, AuditTaskSeq: taskEntry.Seq, Metrics: res.Metrics}
	if err := a.Store.Save(prop, diff, a.Signer); err != nil {
		return nil, err
	}
	diffObj, _ := a.Log.PutObject([]byte(diff))
	sess.Record("proposal", map[string]any{"proposal": id, "status": status, "base": base, "head": head, "branch": branch,
		"diff_sha256": prop.DiffSHA256, "diff_object": diffObj, "files": strings.Join(files, ",")})
	return prop, runErr
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/agent"
	"github.com/sandy-t-shelvan/govcode/internal/analysis"
	"github.com/sandy-t-shelvan/govcode/internal/audit"
	"github.com/sandy-t-shelvan/govcode/internal/gitx"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/marking"
	"github.com/sandy-t-shelvan/govcode/internal/permissions"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/runstate"
	"github.com/sandy-t-shelvan/govcode/internal/secrets"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

type RunOptions struct {
	Task         string
	Interactive  bool
	Verbose      bool
	Plan         bool               // plan mode (forced by policy.require_plan_approval)
	Backend      llm.Backend        // override (tests / eval)
	PlanReviewer agent.PlanReviewer // override; default asks on the terminal
	Approver     tools.Approver     // override; default asks on the terminal
	// OnEvent receives every tool event (also recorded in the audit log),
	// for editors that show live activity.
	OnEvent func(kind string, data any)
	// OnToken streams model text (line by line, spillage-checked).
	OnToken func(string)
	// Resume continues an interrupted run of this proposal id. Task, if
	// set, is then a follow-up message from the proposer.
	Resume string
}

// Run executes one task and produces a proposal. It never touches the
// target branch.
func (a *App) Run(ctx context.Context, o RunOptions) (*proposal.Proposal, error) {
	p := a.Policy
	if !p.MayPropose(a.User.Username) {
		return nil, fmt.Errorf("%s is not permitted to propose changes in this repository", a.User.Username)
	}
	planMode := o.Plan || p.RequirePlanApproval
	if planMode && !o.Interactive && o.PlanReviewer == nil {
		return nil, fmt.Errorf("plan mode needs a human reviewer; run interactively")
	}
	backend := o.Backend
	if backend == nil {
		var err error
		if backend, err = a.Backend(); err != nil {
			return nil, err
		}
	}
	var st *runstate.State
	if o.Resume != "" {
		var err error
		if st, err = a.Runs.Load(o.Resume, a.Keyring, a.User); err != nil {
			return nil, err
		}
		planMode = planMode || st.PlanMode
	}
	id := proposal.NewID()
	if st != nil {
		id = st.ID
	}
	unlock, err := a.Runs.Lock(id)
	if err != nil {
		return nil, err
	}
	defer func() { unlock(); a.Runs.DiscardIfEmpty(id) }()
	sess := a.Session(id)
	maxLevel := p.MaxLevel()
	if fs := marking.Above(o.Task, maxLevel); len(fs) > 0 && maxLevel != marking.Unknown {
		sess.Record("spillage_blocked", map[string]any{"proposal": id, "where": map[bool]string{true: "follow-up", false: "task"}[st != nil], "level": marking.Highest(fs).String(), "repository_level": maxLevel.String()})
		return nil, fmt.Errorf("task refused: it contains a %s marking, above this repository's %s accreditation. The event has been audit-logged; report it per your spillage procedure", marking.Highest(fs), maxLevel)
	}
	rules, err := p.Rules()
	if err != nil {
		return nil, err
	}
	if st != nil {
		return a.runResumed(ctx, o, st, backend, sess, rules, maxLevel, planMode)
	}
	base, err := a.Repo.RevParse("refs/heads/" + p.TargetBranch)
	if err != nil {
		return nil, fmt.Errorf("target branch %s: %w", p.TargetBranch, err)
	}
	branch := proposal.BranchFor(id)
	wt := filepath.Join(p.StateDir, "worktrees", id)
	if err := os.MkdirAll(filepath.Dir(wt), 0o2770); err != nil {
		return nil, err
	}
	th := sha256.Sum256([]byte(o.Task))
	modelID := backend.ModelName()
	digest := ""
	taskFields := map[string]any{}
	if a.Model != nil {
		modelID = a.Model.ID + " (" + backend.ModelName() + ")"
		digest = a.Model.Serve.OllamaDigest
		taskFields["model_publisher"] = a.Model.Publisher
		taskFields["model_origin"] = strings.Join(a.Model.Origins(), ",")
	}
	if e := a.OriginException; e != nil {
		taskFields["origin_exception"] = map[string]any{"model_id": e.ModelID, "authorized_by": e.AuthorizedBy, "reference": e.Reference, "expires": e.Expires}
	}
	for k, v := range map[string]any{
		"proposal": id, "task": o.Task, "task_sha256": hex.EncodeToString(th[:]), "base": base, "target": p.TargetBranch,
		"branch": branch, "model": modelID, "model_digest": digest, "num_ctx": backend.Options().NumCtx,
	} {
		taskFields[k] = v
	}
	taskEntry, err := sess.RecordEntry("task", taskFields)
	if err != nil {
		return nil, err
	}
	if err := a.Repo.AddWorktree(wt, branch, base); err != nil {
		return nil, err
	}
	st = &runstate.State{ID: id, Classification: p.Classification, Proposer: a.User, Task: o.Task, TaskSHA256: hex.EncodeToString(th[:]),
		Base: base, Branch: branch, Worktree: wt, PlanMode: planMode, AuditTaskSeq: taskEntry.Seq, AuditTaskHash: taskEntry.Hash,
		ModelID: modelID, Status: runstate.StatusRunning, CheckpointMsgs: map[int]int{}}
	return a.execute(ctx, o, st, backend, sess, rules, maxLevel, planMode, nil)
}

// runResumed reopens an interrupted run's worktree and conversation.
func (a *App) runResumed(ctx context.Context, o RunOptions, st *runstate.State, backend llm.Backend, sess *audit.Session,
	rules *permissions.Rules, maxLevel marking.Level, planMode bool) (*proposal.Proposal, error) {
	if out, err := gitx.Git(st.Worktree, "symbolic-ref", "--short", "HEAD"); err != nil || strings.TrimSpace(out) != st.Branch {
		return nil, fmt.Errorf("worktree %s for %s is missing or not on %s; the run cannot be resumed", st.Worktree, st.ID, st.Branch)
	}
	history := append([]llm.Message(nil), st.Messages...)
	if len(history) < 2 {
		return nil, fmt.Errorf("run %s has no saved conversation", st.ID)
	}
	fields := map[string]any{"proposal": st.ID, "status": st.Status, "turns": len(history), "files": strings.Join(st.Changed, ","),
		"model": backend.ModelName(), "num_ctx": backend.Options().NumCtx}
	if f := strings.TrimSpace(o.Task); f != "" {
		h := sha256.Sum256([]byte(f))
		fields["follow_up_sha256"] = hex.EncodeToString(h[:])
		fields["follow_up"] = f
		history = append(history, llm.Message{Role: llm.RoleUser, Content: "Follow-up from " + a.User.Username + ": " + f})
	} else {
		history = append(history, llm.Message{Role: llm.RoleUser, Content: "The run was interrupted and has been resumed. The worktree is as you left it. Continue the task."})
	}
	if _, err := sess.RecordEntry("resume", fields); err != nil {
		return nil, err
	}
	st.Status, st.Error = runstate.StatusRunning, ""
	return a.execute(ctx, o, st, backend, sess, rules, maxLevel, planMode, history)
}

// execute runs the agent for a new or resumed run, keeps the run resumable
// if it is interrupted or fails, and otherwise turns it into a proposal.
func (a *App) execute(ctx context.Context, o RunOptions, st *runstate.State, backend llm.Backend, sess *audit.Session,
	rules *permissions.Rules, maxLevel marking.Level, planMode bool, history []llm.Message) (*proposal.Proposal, error) {
	p := a.Policy
	id, wt, base, branch := st.ID, st.Worktree, st.Base, st.Branch
	modelID := st.ModelID
	digest := ""
	if a.Model != nil {
		digest = a.Model.Serve.OllamaDigest
	}
	th := sha256.Sum256([]byte(st.Task))
	taskEntry := struct {
		Seq  uint64
		Hash string
	}{st.AuditTaskSeq, st.AuditTaskHash}
	o.Task = st.Task
	keep := false
	defer func() {
		if !keep {
			a.Repo.RemoveWorktree(wt)
			gitx.DeleteCheckpoints(a.Repo.Root, id, base)
			a.Runs.Delete(id)
		}
	}()

	runner, err := tools.NewRunner(p.Sandbox.Mode, wt, p.Sandbox.ExtraROPaths, p.Sandbox.Env)
	if err != nil {
		return nil, err
	}
	// Commands (tests, run_command, hooks, analyzers) must not read what
	// read_file may not: files read rules deny or ask for are masked in the
	// sandbox, and git history is hidden while any read rule exists.
	runner.HideReadProtected(rules, p.Sandbox.Expose, p.Sandbox.ExposeGit)
	jail, err := tools.NewJail(wt)
	if err != nil {
		return nil, err
	}
	events := make(chan tools.Event, 64)
	done := make(chan struct{})
	go func() {
		for ev := range events {
			sess.Record("tool_event:"+ev.Kind, ev.Data)
			if o.OnEvent != nil {
				o.OnEvent(ev.Kind, ev.Data)
			}
		}
		close(done)
	}()
	env := &tools.Env{Jail: jail, Runner: runner, TestCommand: p.Tests.Command, TestTimeout: p.TestTimeout(),
		Perms: rules, MaxLevel: maxLevel, RequireTest: p.Tests.RequirePass, Events: events,
		PostEditHooks: p.Hooks.PostEdit, MemoryBudget: backend.Options().NumCtx * 3 / 8}
	switch {
	case o.Approver != nil:
		env.Approver = o.Approver
	case o.Interactive && p.Commands.PromptForOthers:
		env.Approver = &TTYApprover{User: a.User, Rec: sess}
	}
	var memory string
	if history == nil {
		memory = a.loadMemory(wt, env, sess)
	} else {
		restoreEnv(st, env)
	}
	// Checkpoint after every edit; persist the run after every turn so an
	// interrupt, crash or model failure can be resumed.
	var pending []int
	var ckptErr error
	env.OnEdit = func(rel string) {
		n := env.EditGen
		c, err := gitx.Checkpoint(wt, id, n, base, changedPaths(env))
		if err != nil {
			ckptErr = err
			sess.Record("checkpoint_failed", map[string]any{"proposal": id, "n": n, "error": err.Error()})
			return
		}
		pending = append(pending, n)
		sess.Record("checkpoint", map[string]any{"proposal": id, "n": n, "commit": c, "file": rel})
	}
	saveState := func(msgs []llm.Message) {
		if msgs != nil {
			st.Messages = msgs
		}
		for _, n := range pending {
			st.CheckpointMsgs[n] = len(st.Messages)
		}
		pending = nil
		captureEnv(st, env)
		if err := a.Runs.Save(st, a.Signer); err != nil {
			fmt.Fprintf(a.Out, "warning: run state not saved (%v); this run cannot be resumed\n", err)
		}
	}
	fmt.Fprintf(a.Out, "govcode %s | %s | proposal %s\nmodel %s, num_ctx=%d, sandbox=%v\n",
		p.Classification, a.User, id, modelID, backend.Options().NumCtx, runner.Sandboxed())
	ag := &agent.Agent{Backend: backend, Tools: tools.NewSet(env), Rec: sess,
		Cfg: agent.Config{MaxTurns: p.MaxTurns, Out: a.Out, Verbose: o.Verbose, PlanMode: planMode, OnToken: o.OnToken,
			History: history, OnTurn: func(msgs []llm.Message) { saveState(msgs) }}}
	var plan *planHasher
	if planMode {
		inner := o.PlanReviewer
		if inner == nil {
			inner = &TTYPlanReviewer{}
		}
		plan = &planHasher{inner: inner}
		ag.PlanReviewer = plan
	}
	start := time.Now()
	res, runErr := ag.Run(ctx, o.Task, agent.RepoContext{Summary: gitx.Summary(wt), TestCommand: p.Tests.Command, Memory: memory})
	if plan != nil && plan.sha != "" {
		st.PlanSHA256 = plan.sha
	}
	if runErr == nil && ckptErr != nil {
		runErr = fmt.Errorf("checkpoint failed: %w", ckptErr)
	}
	if res != nil && runErr != nil && !res.Metrics.Finished {
		// Interrupted or failed: keep the worktree and conversation.
		close(events)
		<-done
		st.Status, st.Error = runstate.StatusError, runErr.Error()
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			st.Status = runstate.StatusInterrupted
		}
		saveState(nil)
		keep = true
		sess.Record("run_suspended", map[string]any{"proposal": id, "status": st.Status, "reason": errString(runErr),
			"files": strings.Join(st.Changed, ","), "turns": len(st.Messages)})
		fmt.Fprintf(a.Out, "\nRun %s %s; worktree and conversation kept.\n  Resume: govcode run --resume %s [\"follow-up\"]\n  Checkpoints: govcode rewind %s\n", id, st.Status, id, id)
		return nil, fmt.Errorf("%w (run %s kept; resume with: govcode run --resume %s)", runErr, id, id)
	}
	var hookReport string
	if res != nil && len(res.Changed) > 0 && len(p.Hooks.PreProposal) > 0 {
		hookReport = env.RunHooks(ctx, "pre_proposal", p.Hooks.PreProposal, res.Changed)
	}
	var arep *analysis.Report
	if res != nil && len(res.Changed) > 0 && (p.Analysis.Required || len(p.Analysis.Analyzers) > 0) {
		arep = analysis.Run(ctx, runner, wt, p.Analysis.Analyzers, a.Analyzers, p.Analysis.UnanalyzedOK, res.Changed, p.Analysis.Timeout())
		for _, r := range arep.Results {
			out := r.Output
			if env.Spill("analysis output", out) {
				out = "[withheld: marked above repository level]"
			}
			sess.Record("analysis", map[string]any{"proposal": id, "tool": r.Analyzer, "path": r.Tool.Path, "sha256": r.Tool.SHA256,
				"version": r.Tool.Version, "files": strings.Join(r.Files, ","), "exit_code": r.ExitCode, "findings": r.Findings,
				"blocking": r.Blocking, "passed": r.Passed, "output": out})
		}
		if len(arep.Uncovered) > 0 {
			sess.Record("analysis_uncovered", map[string]any{"proposal": id, "files": strings.Join(arep.Uncovered, ",")})
		}
	}
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
	if hookReport != "" {
		for _, h := range p.Hooks.PreProposal {
			if strings.Contains(hookReport, fmt.Sprintf("%q failed", h)) {
				blocked = append(blocked, fmt.Sprintf("site check failed: %s", h))
			}
		}
	}
	if arep != nil {
		for _, r := range arep.Results {
			if !r.Passed {
				why := fmt.Sprintf("%d blocking finding(s)", r.Blocking)
				if r.TimedOut {
					why = "timed out"
				} else if r.Blocking == 0 {
					why = fmt.Sprintf("exit %d", r.ExitCode)
				}
				blocked = append(blocked, fmt.Sprintf("static analysis: %s failed (%s)", r.Analyzer, why))
			}
		}
		if p.Analysis.Required {
			for _, f := range arep.Uncovered {
				blocked = append(blocked, fmt.Sprintf("static analysis: no analyzer covers %s (add one, or an analysis.unanalyzed_ok pattern)", f))
			}
		}
	}
	if len(blocked) > 0 {
		status = proposal.StatusBlocked
	}
	checks := a.runChecks(env, runner.Sandboxed(), maxLevel, blocked, hookReport)
	checks = append(checks, analysisChecks(arep, p.Analysis.Required)...)
	prop := &proposal.Proposal{ID: id, Created: time.Now().UTC().Format(time.RFC3339), Classification: p.Classification,
		Repo: a.Repo.Root, Task: o.Task, TaskSHA256: hex.EncodeToString(th[:]), Summary: res.Summary, Proposer: a.User,
		Target: p.TargetBranch, Branch: branch, Base: base, Head: head, DiffSHA256: proposal.DiffHash(diff), Files: files,
		Tests: proposal.Tests{Command: p.Tests.Command, Runs: env.TestRuns, Passed: env.LastTestPass},
		Model: modelID, ModelDigest: digest, Status: status, Blocked: blocked, AuditSession: id, AuditTaskSeq: taskEntry.Seq, AuditTaskHash: taskEntry.Hash, Metrics: res.Metrics,
		ModelInfo: a.modelInfo(backend), Checks: checks}
	prop.PlanSHA256 = st.PlanSHA256
	if err := a.Store.Save(prop, diff, a.Signer); err != nil {
		return nil, err
	}
	diffObj, _ := a.Log.PutObject([]byte(diff))
	sess.Record("proposal", map[string]any{"proposal": id, "status": status, "base": base, "head": head, "branch": branch,
		"diff_sha256": prop.DiffSHA256, "diff_object": diffObj, "files": strings.Join(files, ",")})
	return prop, runErr
}

// loadMemory reads the site instructions (root-owned, from policy) and
// the repository's root GOVCODE.md, records their hashes, and marks the
// root as loaded so read_file only adds subdirectory files.
func (a *App) loadMemory(wt string, env *tools.Env, sess interface {
	Record(string, any) error
}) string {
	var b strings.Builder
	add := func(label, path string) {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			return
		}
		if len(data) > env.MemoryBudget {
			data = data[:max(env.MemoryBudget, 0)]
		}
		if env.Spill("memory "+label, string(data)) || len(data) == 0 {
			return
		}
		env.MemoryBudget -= len(data)
		sum := sha256.Sum256(data)
		sess.Record("memory_loaded", map[string]any{"path": label, "sha256": hex.EncodeToString(sum[:]), "bytes": len(data)})
		fmt.Fprintf(&b, "[%s]\n%s\n\n", label, strings.TrimSpace(string(data)))
	}
	if a.Policy.SiteInstructions != "" {
		add("site instructions", a.Policy.SiteInstructions)
	}
	add(tools.MemoryFile, filepath.Join(wt, tools.MemoryFile))
	env.MemoryLoaded = map[string]bool{".": true}
	return b.String()
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

// planHasher passes plan review through and keeps the SHA-256 of the plan
// the human approved, for the evidence record.
type planHasher struct {
	inner agent.PlanReviewer
	sha   string
}

func (h *planHasher) ReviewPlan(steps []string, summary string) (bool, string) {
	ok, fb := h.inner.ReviewPlan(steps, summary)
	if ok {
		sum := sha256.Sum256([]byte(summary + "\n" + strings.Join(steps, "\n")))
		h.sha = hex.EncodeToString(sum[:])
	}
	return ok, fb
}

// modelInfo describes the model that produced the change: the signed lock
// entry when there is one, plus the generation settings actually used.
func (a *App) modelInfo(b llm.Backend) *proposal.ModelInfo {
	o := b.Options()
	mi := &proposal.ModelInfo{ID: b.ModelName(), ServedName: b.ModelName(), NumCtx: o.NumCtx, MaxTokens: o.MaxTokens, Temperature: o.Temperature, Seed: o.Seed}
	if m := a.Model; m != nil {
		mi.ID, mi.Name, mi.Publisher, mi.Origins = m.ID, m.Name, m.Publisher, m.Origins()
		mi.UpstreamRepo, mi.UpstreamRev, mi.Quantization = m.Upstream.Repo, m.Upstream.Revision, m.Artifact.Quant
		mi.OllamaDigest = m.Serve.OllamaDigest
		for _, f := range m.Artifact.Files {
			mi.ArtifactSHA256 = append(mi.ArtifactSHA256, f.SHA256)
		}
	}
	if e := a.OriginException; e != nil {
		mi.OriginException = e.Reference + " (" + e.AuthorizedBy + ", expires " + e.Expires + ")"
	}
	return mi
}

// runChecks summarises the gates the change went through. Values are
// results and counts only.
func (a *App) runChecks(env *tools.Env, sandboxed bool, maxLevel marking.Level, blocked []string, hookReport string) []proposal.Check {
	res := func(ok bool) string {
		if ok {
			return "pass"
		}
		return "fail"
	}
	count := func(prefix string) int {
		n := 0
		for _, b := range blocked {
			if strings.HasPrefix(b, prefix) {
				n++
			}
		}
		return n
	}
	p := a.Policy
	var cs []proposal.Check
	if p.Tests.Command != "" {
		cs = append(cs, proposal.Check{Name: "tests", Result: res(env.LastTestPass), Detail: fmt.Sprintf("%s (%d runs)", p.Tests.Command, env.TestRuns)})
	}
	if maxLevel == marking.Unknown {
		cs = append(cs, proposal.Check{Name: "spillage_guard", Result: "skipped", Detail: "disabled by policy"})
	} else {
		cs = append(cs, proposal.Check{Name: "spillage_guard", Result: res(count("spillage:") == 0), Detail: "ceiling " + maxLevel.String()})
	}
	n := count("secret:")
	cs = append(cs, proposal.Check{Name: "secret_scan", Result: res(n == 0), Detail: fmt.Sprintf("%d finding(s)", n)})
	for _, h := range p.Hooks.PreProposal {
		ok := !strings.Contains(hookReport, fmt.Sprintf("%q failed", h))
		cs = append(cs, proposal.Check{Name: "site_check: " + h, Result: res(ok)})
	}
	sb := "none"
	if sandboxed {
		sb = "bubblewrap"
	}
	cs = append(cs, proposal.Check{Name: "sandbox", Result: res(sandboxed || p.Sandbox.Mode != "required"), Detail: sb})
	return cs
}

// analysisChecks turns the analysis report into evidence entries: tool,
// version and hash, files and finding counts.
func analysisChecks(r *analysis.Report, required bool) []proposal.Check {
	if r == nil {
		return nil
	}
	var cs []proposal.Check
	for _, x := range r.Results {
		res := "pass"
		if !x.Passed {
			res = "fail"
		}
		cs = append(cs, proposal.Check{Name: "analysis: " + x.Analyzer, Result: res,
			Detail: fmt.Sprintf("%s sha256 %s; %d file(s), %d finding(s), %d blocking, exit %d", x.Tool.Version, x.Tool.SHA256, len(x.Files), x.Findings, x.Blocking, x.ExitCode)})
	}
	cov := "pass"
	if len(r.Uncovered) > 0 && required {
		cov = "fail"
	}
	cs = append(cs, proposal.Check{Name: "analysis coverage", Result: cov,
		Detail: fmt.Sprintf("%d uncovered, %d exempt by unanalyzed_ok", len(r.Uncovered), len(r.Exempt))})
	return cs
}

func changedPaths(env *tools.Env) []string {
	var out []string
	for p := range env.Changed {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Checkpoint is one restorable point of an interrupted run.
type Checkpoint = gitx.CheckpointInfo

// Checkpoints lists the checkpoints of a resumable run.
func (a *App) Checkpoints(id string) (*runstate.State, []Checkpoint, error) {
	st, err := a.Runs.Load(id, a.Keyring, a.User)
	if err != nil {
		return nil, nil, err
	}
	cs, err := gitx.Checkpoints(st.Worktree, id, st.Base)
	return st, cs, err
}

// Rewind restores an interrupted run's worktree to checkpoint n (0 = the
// base), trims the conversation back to that point, and records why in
// the audit session. The run is then resumed with `run --resume`.
func (a *App) Rewind(id string, n int) ([]string, error) {
	unlock, err := a.Runs.Lock(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := a.Runs.Load(id, a.Keyring, a.User)
	if err != nil {
		return nil, err
	}
	keep := 2 // system and task messages
	if n > 0 {
		k, ok := st.CheckpointMsgs[n]
		if !ok {
			return nil, fmt.Errorf("run %s has no checkpoint %d", id, n)
		}
		keep = k
	}
	if n < 0 || keep > len(st.Messages) {
		return nil, fmt.Errorf("checkpoint %d is not in the saved conversation", n)
	}
	files, err := gitx.Rewind(st.Worktree, id, st.Base, n, st.Changed)
	if err != nil {
		return nil, err
	}
	st.Messages = append(st.Messages[:keep:keep], llm.Message{Role: llm.RoleUser,
		Content: fmt.Sprintf("%s rewound the worktree to checkpoint %d. Edits made after it are gone. Files changed from the base now: %s. Re-read files before editing, and run the tests again before finishing.",
			a.User.Username, n, strings.Join(append([]string{}, files...), ", "))})
	for k := range st.CheckpointMsgs {
		if k > n {
			delete(st.CheckpointMsgs, k)
		}
	}
	st.Changed, st.EditGen = files, n
	st.TestedGen, st.LastTestPass = -1, false
	if _, err := a.Session(id).RecordEntry("rewind", map[string]any{"proposal": id, "n": n, "files": strings.Join(files, ","), "turns": len(st.Messages)}); err != nil {
		return nil, err
	}
	if err := a.Runs.Save(st, a.Signer); err != nil {
		return nil, err
	}
	return files, nil
}

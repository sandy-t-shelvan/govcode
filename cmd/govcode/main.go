// Command govcode is an air-gapped coding agent for legacy code. It runs a
// local open-weight model, confines the agent to one repository, records
// everything in a signed hash-chained audit log, and lands nothing without
// human approval.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/app"
	"github.com/sandy-t-shelvan/govcode/internal/audit"
	"github.com/sandy-t-shelvan/govcode/internal/eval"
	"github.com/sandy-t-shelvan/govcode/internal/gitx"
	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/modelpin"
	"github.com/sandy-t-shelvan/govcode/internal/policy"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
	"github.com/sandy-t-shelvan/govcode/internal/supply"
)

const usage = `govcode - air-gapped coding agent for legacy code

Developer:
  govcode run "<task>"            run the agent; produces a signed proposal (never touches the target branch)
  govcode proposals               list proposals
  govcode review <id>             show a proposal: summary, tests, diff, audit trail

Approver (a different person when two_person_rule is on):
  govcode approve <id> [-m text]  land a proposal on the target branch
  govcode reject <id> -m reason   reject a proposal

Audit:
  govcode audit verify            verify hash chain, signatures, objects and git anchors
  govcode audit show [-n N] [-session ID]
  govcode audit object <sha256>   print a stored payload

Setup and supply chain:
  govcode verify                  preflight: policy, release signature, model lock, served model, sandbox, keys, audit
  govcode keygen [--register]     create your Ed25519 signing key
  govcode init                    write a development policy for the current repo (warn mode)
  govcode sbom [-lock f] [-o f]   CycloneDX 1.6 SBOM of this binary, system tools and models
  govcode aibom -lock f [-o f]    CycloneDX 1.6 AI-BOM from a model lock
  govcode sign -key k file...     write detached signatures (release / model signing)
  govcode manifest -dir d -version v [-o f]   release manifest (SHA-256 of every file in d)
  govcode model verify -dir d [-model id] [-key pub]
  govcode model smoke             one tool-call round trip against the served model
  govcode eval [-tasks dir] [-o dir] [-only id]   tool-call/task eval on legacy-code tasks
  govcode version

Global: -policy <path> (default $GOVCODE_POLICY or /etc/govcode/policy.json)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	// Shared state (audit log, proposals) is read/written by the proposer
	// and approver through a common group; nothing is world-accessible.
	syscall.Umask(0o007)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch cmd {
	case "run":
		err = cmdRun(ctx, args)
	case "proposals", "list":
		err = cmdProposals(args)
	case "review", "show":
		err = cmdReview(args)
	case "approve":
		err = cmdApprove(args)
	case "reject":
		err = cmdReject(args)
	case "audit":
		err = cmdAudit(args)
	case "verify", "doctor":
		err = cmdVerify(args)
	case "keygen":
		err = cmdKeygen(args)
	case "init":
		err = cmdInit(args)
	case "sbom":
		err = cmdSBOM(args)
	case "aibom":
		err = cmdAIBOM(args)
	case "sign":
		err = cmdSign(args)
	case "manifest":
		err = cmdManifest(args)
	case "model":
		err = cmdModel(ctx, args)
	case "eval":
		err = cmdEval(ctx, args)
	case "version", "-v", "--version":
		fmt.Println("govcode", supply.Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "govcode:", err)
		os.Exit(1)
	}
}

func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	pol := fs.String("policy", "", "policy file")
	return fs, pol
}

// parse lets flags appear after positional args (govcode approve <id> -m x).
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		fs.Parse(args)
		if fs.NArg() == 0 {
			return pos
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func banner(a *app.App) {
	fmt.Printf("== %s ==\n", a.Policy.Classification)
}

func cmdRun(ctx context.Context, args []string) error {
	fs, pol := flags("run")
	verbose := fs.Bool("verbose", false, "show tool output")
	yes := fs.Bool("non-interactive", false, "never prompt; non-allowlisted commands are denied")
	pos := parse(fs, args)
	task := strings.Join(pos, " ")
	if strings.TrimSpace(task) == "" {
		return errors.New(`usage: govcode run "<task>"`)
	}
	a, checks, err := app.Open(*pol, os.Stdout, true)
	if err != nil {
		printChecks(checks)
		return err
	}
	for _, w := range a.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	banner(a)
	p, err := a.Run(ctx, app.RunOptions{Task: task, Interactive: !*yes, Verbose: *verbose})
	if p != nil {
		fmt.Printf("\nProposal %s: %s\n  branch %s (%s..%s)\n  files: %s\n  tests: %s runs=%d passed=%v\n",
			p.ID, p.Status, p.Branch, p.Base[:10], p.Head[:10], strings.Join(p.Files, ", "), p.Tests.Command, p.Tests.Runs, p.Tests.Passed)
		for _, b := range p.Blocked {
			fmt.Printf("  BLOCKED: %s\n", b)
		}
		if p.Status == proposal.StatusReady {
			fmt.Printf("\nNothing has landed. A reviewer must run:\n  govcode review %s\n  govcode approve %s\n", p.ID, p.ID)
		}
	}
	return err
}

func cmdProposals(args []string) error {
	fs, pol := flags("proposals")
	parse(fs, args)
	a, _, err := app.Open(*pol, os.Stdout, false)
	if err != nil {
		return err
	}
	banner(a)
	ids, err := a.Store.List()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tPROPOSER\tFILES\tTASK")
	for _, id := range ids {
		p, err := a.Store.Load(id, a.Keyring)
		if err != nil {
			fmt.Fprintf(tw, "%s\tINVALID\t\t\t%v\n", id, err)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", id, p.Status, p.Proposer.Username, len(p.Files), oneLine(p.Task, 60))
	}
	return tw.Flush()
}

func cmdReview(args []string) error {
	fs, pol := flags("review")
	stat := fs.Bool("stat", false, "diffstat only")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: govcode review <proposal-id>")
	}
	a, _, err := app.Open(*pol, os.Stdout, false)
	if err != nil {
		return err
	}
	banner(a)
	p, err := a.Store.Load(pos[0], a.Keyring)
	if err != nil {
		return err
	}
	fmt.Printf("Proposal   %s  [%s]\nProposer   %s  (signature verified, key %s)\nTask       %s\nSummary    %s\nModel      %s\nTarget     %s  base %s  head %s\nTests      %s  runs=%d  passed=%v\n",
		p.ID, p.Status, p.Proposer, p.ProposerKey, p.Task, p.Summary, p.Model, p.Target, p.Base[:12], p.Head[:12], p.Tests.Command, p.Tests.Runs, p.Tests.Passed)
	for _, b := range p.Blocked {
		fmt.Printf("BLOCKED    %s\n", b)
	}
	diff, verr := proposal.VerifyBranch(a.Repo, p)
	if verr != nil {
		fmt.Printf("INTEGRITY  FAILED: %v\n", verr)
		return verr
	}
	fmt.Printf("Integrity  branch head and diff SHA-256 %s… match the signed proposal\n", p.DiffSHA256[:16])
	if d, _ := a.Store.Decision(p.ID); d != nil {
		fmt.Printf("Decision   %s by %s at %s %s %s\n", d.Decision, d.By.Username, d.Time, d.Commit, d.Reason)
	}
	if m, ok := p.Metrics.(map[string]any); ok {
		b, _ := json.Marshal(m)
		fmt.Printf("Metrics    %s\n", b)
	}
	fmt.Println("\nAudit trail:")
	a.Log.Each(func(e *audit.Entry, _ []byte) error {
		if e.Session == p.ID {
			fmt.Printf("  #%-5d %s %-10s %-26s %s\n", e.Seq, e.Time[:19], e.Actor.Username, e.Kind, summaryLine(e.Summary))
		}
		return nil
	})
	st, _ := a.Repo.DiffStat(p.Base, p.Head)
	fmt.Println("\n" + st)
	if !*stat {
		fmt.Println(diff)
	}
	return nil
}

func cmdApprove(args []string) error {
	fs, pol := flags("approve")
	comment := fs.String("m", "", "review comment")
	yes := fs.Bool("yes", false, "skip typed confirmation (only if policy allow_non_interactive_approval)")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: govcode approve <proposal-id> [-m comment]")
	}
	a, checks, err := app.Open(*pol, os.Stdout, true)
	if err != nil {
		printChecks(checks)
		return err
	}
	banner(a)
	p, err := a.Store.Load(pos[0], a.Keyring)
	if err != nil {
		return err
	}
	rules := proposal.Rules{TwoPersonRule: a.Policy.TwoPersonRule, Approvers: a.Policy.Approvers, Classification: a.Policy.Classification}
	if err := proposal.CheckApprover(rules, p, a.User); err != nil {
		a.Session(p.ID).Record("approval_refused", map[string]any{"proposal": p.ID, "approver": a.User.Username, "reason": err.Error()})
		return err
	}
	if _, err := proposal.VerifyBranch(a.Repo, p); err != nil {
		return err
	}
	st, _ := a.Repo.DiffStat(p.Base, p.Head)
	prompt := fmt.Sprintf("Approve %s by %s onto %s?\n  %s\n%s", p.ID, p.Proposer.Username, p.Target, oneLine(p.Task, 100), st)
	if *yes {
		if !a.Policy.AllowNonInteractiveApproval {
			return errors.New("--yes is not permitted by policy; approval must be confirmed at a terminal")
		}
	} else if !app.ConfirmTTY(prompt, "approve") {
		return errors.New("not confirmed; nothing landed")
	}
	sess := a.Session(p.ID)
	res, err := a.Store.Approve(a.Repo, rules, p, a.User, a.Signer, *comment, func(kind string, payload map[string]any) (string, error) {
		e, err := sess.RecordEntry(kind, payload)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d:%s", e.Seq, e.Hash), nil
	})
	if err != nil {
		sess.Record("approval_failed", map[string]any{"proposal": p.ID, "error": err.Error()})
		return err
	}
	sess.Record("landed", map[string]any{"proposal": p.ID, "commit": res.Commit, "target": p.Target, "base": res.TargetWas})
	fmt.Printf("Landed %s on %s as %s (audit anchor %s)\n", p.ID, p.Target, res.Commit[:12], res.Anchor[:20])
	return nil
}

func cmdReject(args []string) error {
	fs, pol := flags("reject")
	reason := fs.String("m", "", "reason (required)")
	pos := parse(fs, args)
	if len(pos) != 1 || *reason == "" {
		return errors.New("usage: govcode reject <proposal-id> -m <reason>")
	}
	a, checks, err := app.Open(*pol, os.Stdout, true)
	if err != nil {
		printChecks(checks)
		return err
	}
	p, err := a.Store.Load(pos[0], a.Keyring)
	if err != nil {
		return err
	}
	sess := a.Session(p.ID)
	err = a.Store.Reject(proposal.Rules{Approvers: a.Policy.Approvers}, p, a.User, a.Signer, *reason, func(kind string, payload map[string]any) (string, error) {
		e, err := sess.RecordEntry(kind, payload)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d:%s", e.Seq, e.Hash), nil
	})
	if err == nil {
		fmt.Printf("Rejected %s\n", p.ID)
	}
	return err
}

func cmdAudit(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: govcode audit verify|show|object")
	}
	sub, args := args[0], args[1:]
	fs, pol := flags("audit " + sub)
	n := fs.Int("n", 50, "entries to show")
	session := fs.String("session", "", "only this session/proposal")
	noObjects := fs.Bool("no-objects", false, "skip object hash checks (faster)")
	pos := parse(fs, args)
	a, _, err := app.Open(*pol, os.Stdout, false)
	if err != nil {
		return err
	}
	banner(a)
	switch sub {
	case "verify":
		anchors, err := proposal.Anchors(a.Repo, []string{a.Policy.TargetBranch})
		if err != nil {
			return err
		}
		r, err := a.Log.Verify(a.Keyring, anchors, !*noObjects)
		if err != nil {
			return err
		}
		fmt.Printf("entries: %d   anchors checked: %d   actors: %v\n", r.Entries, r.Anchors, r.Actors)
		if r.Head != nil {
			fmt.Printf("head: #%d %s\n", r.Head.Seq, r.Head.Hash)
		}
		if !r.OK() {
			for _, p := range r.Problems {
				fmt.Println("  FAIL", p)
			}
			return fmt.Errorf("audit log verification FAILED (%d problems)", len(r.Problems))
		}
		fmt.Println("audit log verified: chain intact, all signatures valid, all anchors present")
	case "show":
		var es []*audit.Entry
		a.Log.Each(func(e *audit.Entry, _ []byte) error {
			if *session == "" || e.Session == *session {
				es = append(es, e)
			}
			return nil
		})
		if len(es) > *n {
			es = es[len(es)-*n:]
		}
		for _, e := range es {
			fmt.Printf("#%-5d %s %-10s %-14s %-26s %s\n", e.Seq, e.Time[:19], e.Actor.Username, e.Session, e.Kind, summaryLine(e.Summary))
		}
	case "object":
		if len(pos) != 1 {
			return errors.New("usage: govcode audit object <sha256>")
		}
		b, err := a.Log.GetObject(pos[0])
		if err != nil {
			return err
		}
		os.Stdout.Write(b)
		fmt.Println()
	default:
		return fmt.Errorf("unknown audit subcommand %q", sub)
	}
	return nil
}

func printChecks(checks []app.Check) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, c := range checks {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.Status, c.Name, c.Detail)
	}
	tw.Flush()
}

func cmdVerify(args []string) error {
	fs, pol := flags("verify")
	parse(fs, args)
	a, checks, err := app.Open(*pol, os.Stdout, true)
	printChecks(checks)
	if err != nil {
		return err
	}
	for _, c := range checks {
		if c.Status == "FAIL" {
			return errors.New("preflight has failures")
		}
	}
	fmt.Printf("all preflight checks passed for %s\n", a.Repo.Root)
	return nil
}

func cmdKeygen(args []string) error {
	fs, pol := flags("keygen")
	register := fs.Bool("register", false, "copy the public key into the policy keyring")
	out := fs.String("o", app.KeyPath(), "private key path")
	parse(fs, args)
	base := strings.TrimSuffix(*out, ".key")
	pub, err := sign.GenerateKeyFiles(base)
	if err != nil {
		return err
	}
	if base+".key" != *out {
		os.Rename(base+".key", *out)
	}
	fmt.Printf("wrote %s (0600) and %s.pub\nkey id %s\n", *out, base, sign.KeyID(pub))
	if *register {
		p, _, err := policy.Load(policy.Locate(*pol))
		if err != nil {
			return err
		}
		u, _ := identity.Current()
		path, err := keyring.Register(p.Trust.KeyringDir, u, pub)
		if err != nil {
			return fmt.Errorf("register: %w (in strict deployments the ISSO installs keys; send them %s.pub)", err, base)
		}
		fmt.Println("registered", path)
	}
	return nil
}

func cmdInit(args []string) error {
	fs, _ := flags("init")
	out := fs.String("o", "", "policy path (default <state>/policy.json)")
	parse(fs, args)
	cwd, _ := os.Getwd()
	repo, err := gitx.Open(cwd)
	if err != nil {
		return err
	}
	u, _ := identity.Current()
	state := filepath.Join(filepath.Dir(repo.Root), ".govcode-state", filepath.Base(repo.Root))
	p := policy.Dev(repo.Root, state, u.Username)
	if br := repo.CurrentBranch(); br != "" {
		p.TargetBranch = br
	}
	if *out == "" {
		*out = filepath.Join(state, "policy.json")
	}
	os.MkdirAll(filepath.Dir(*out), 0o755)
	b, _ := json.MarshalIndent(p, "", "  ")
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	f.Write(append(b, '\n'))
	f.Close()
	fmt.Printf("wrote development policy %s (trust.enforce=warn)\nexport GOVCODE_POLICY=%s\nThen: govcode keygen --register && govcode verify\n", *out, *out)
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(append(b, '\n'))
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func cmdSBOM(args []string) error {
	fs := flag.NewFlagSet("sbom", flag.ExitOnError)
	lock := fs.String("lock", "", "include models from this lock")
	out := fs.String("o", "-", "output file")
	fs.Parse(args)
	var l *modelpin.Lock
	if *lock != "" {
		var err error
		if l, err = modelpin.Load(*lock); err != nil {
			return err
		}
	}
	b, err := supply.SBOM(l)
	if err != nil {
		return err
	}
	return writeJSON(*out, b)
}

func cmdAIBOM(args []string) error {
	fs := flag.NewFlagSet("aibom", flag.ExitOnError)
	lock := fs.String("lock", "models/models.lock.json", "model lock")
	out := fs.String("o", "-", "output file")
	fs.StringVar(out, "out", "-", "output file")
	fs.Parse(args)
	l, err := modelpin.Load(*lock)
	if err != nil {
		return err
	}
	return writeJSON(*out, supply.AIBOM(l))
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	key := fs.String("key", "", "private key (release or model-signing key)")
	fs.Parse(args)
	if *key == "" || fs.NArg() == 0 {
		return errors.New("usage: govcode sign -key <k> <file> [file ...]")
	}
	s, err := sign.LoadSigner(*key)
	if err != nil {
		return err
	}
	for _, f := range fs.Args() {
		if err := sign.SignFile(s, f); err != nil {
			return err
		}
		fmt.Printf("signed %s (key %s)\n", f, s.KeyID())
	}
	return nil
}

func cmdManifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	dir := fs.String("dir", "", "release directory")
	version := fs.String("version", supply.Version, "release version")
	out := fs.String("o", "", "output (default <dir>/manifest.json)")
	fs.Parse(args)
	if *dir == "" {
		return errors.New("usage: govcode manifest -dir <release dir> -version <v>")
	}
	if *out == "" {
		*out = filepath.Join(*dir, "manifest.json")
	}
	files := map[string]string{}
	err := filepath.Walk(*dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(*dir, p)
		if rel == "manifest.json" || rel == "manifest.json.sig" {
			return nil
		}
		role := "file"
		switch {
		case strings.HasPrefix(rel, "bin/"):
			role = "binary"
		case strings.HasSuffix(rel, ".cdx.json"):
			role = "sbom"
		case strings.HasSuffix(rel, ".sig"):
			role = "signature"
		case strings.HasSuffix(rel, ".pub"):
			role = "public-key"
		}
		files[filepath.ToSlash(rel)] = role
		return nil
	})
	if err != nil {
		return err
	}
	m, err := supply.BuildManifest(*dir, *version, files)
	if err != nil {
		return err
	}
	if err := writeJSON(*out, m); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d files)\n", *out, len(m.Files))
	return nil
}

func cmdModel(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: govcode model verify|smoke")
	}
	switch args[0] {
	case "verify":
		fs := flag.NewFlagSet("model verify", flag.ExitOnError)
		dir := fs.String("dir", ".", "staged directory (contains models.lock.json and weights/)")
		id := fs.String("model", "", "model id (default: lock default)")
		var keys multi
		fs.Var(&keys, "key", "trusted model-signing public key (repeatable)")
		fs.Parse(args[1:])
		lockPath := filepath.Join(*dir, "models.lock.json")
		var l *modelpin.Lock
		if len(keys) > 0 {
			trusted, err := loadPubs(keys)
			if err != nil {
				return err
			}
			lk, kid, err := modelpin.LoadVerified(lockPath, trusted)
			if err != nil {
				return err
			}
			fmt.Println("lock signature OK, key", kid)
			l = lk
		} else {
			fmt.Fprintln(os.Stderr, "warning: no -key given; checking hashes only, not the lock signature")
			var err error
			if l, err = modelpin.Load(lockPath); err != nil {
				return err
			}
		}
		m, err := l.Find(*id)
		if err != nil {
			return err
		}
		probs := modelpin.VerifyArtifacts(m, *dir, func(p string) { fmt.Println("hashing", p) })
		for _, p := range probs {
			fmt.Println("  FAIL", p.Path, p.Msg)
		}
		if len(probs) > 0 {
			return fmt.Errorf("%d artifact(s) failed verification", len(probs))
		}
		fmt.Printf("%s: all artifacts match the lock\n", m.ID)
		return nil
	case "smoke":
		fs, pol := flags("model smoke")
		fs.Parse(args[1:])
		a, checks, err := app.Open(*pol, os.Stdout, false)
		if err != nil {
			printChecks(checks)
			return err
		}
		b, err := a.Backend()
		if err != nil {
			return err
		}
		return eval.Smoke(ctx, b, os.Stdout)
	}
	return fmt.Errorf("unknown model subcommand %q", args[0])
}

func cmdEval(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	tasks := fs.String("tasks", "eval/tasks", "task directory")
	out := fs.String("o", "eval/results", "results directory")
	only := fs.String("only", "", "run only tasks whose id contains this")
	backend := fs.String("backend", "ollama", "ollama | openai | oracle")
	endpoint := fs.String("endpoint", "http://127.0.0.1:11434", "model server (loopback)")
	model := fs.String("model", "govcode-qwen3-coder:30b-q4km", "served model name")
	numCtx := fs.Int("num-ctx", 32768, "context length (must match server)")
	maxTok := fs.Int("max-tokens", 4096, "max output tokens per turn")
	temp := fs.Float64("temperature", 0.2, "temperature")
	turns := fs.Int("max-turns", 30, "max agent turns per task")
	verbose := fs.Bool("verbose", false, "stream agent output")
	fs.Parse(args)
	cfg := eval.Config{TasksDir: *tasks, OutDir: *out, Only: *only, MaxTurns: *turns}
	if *verbose {
		cfg.Log = os.Stdout
	} else {
		cfg.Log = io.Discard
	}
	opts := llm.Options{NumCtx: *numCtx, MaxTokens: *maxTok, Temperature: *temp, Seed: 42}
	switch *backend {
	case "ollama":
		cfg.NewBackend = func() (llm.Backend, error) { return llm.NewOllama(*endpoint, *model, opts) }
	case "openai":
		cfg.NewBackend = func() (llm.Backend, error) { return llm.NewOpenAICompat(*endpoint, *model, opts) }
	case "oracle":
		cfg.Oracle = true
	default:
		return fmt.Errorf("unknown backend %q", *backend)
	}
	start := time.Now()
	rep, err := eval.Run(ctx, cfg)
	if err != nil {
		return err
	}
	rep.Print(os.Stdout)
	fmt.Printf("\nresults: %s (%.0fs)\n", rep.Path, time.Since(start).Seconds())
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func loadPubs(paths []string) ([]ed25519PublicKey, error) {
	var out []ed25519PublicKey
	for _, p := range paths {
		k, err := sign.LoadPublic(p)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func summaryLine(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for _, k := range []string{"tool", "path", "command", "tool_calls", "status", "decision", "approver", "commit", "files", "error"} {
		if v, ok := m[k]; ok && fmt.Sprint(v) != "" {
			parts = append(parts, fmt.Sprintf("%s=%v", k, oneLine(fmt.Sprint(v), 60)))
		}
	}
	return strings.Join(parts, " ")
}

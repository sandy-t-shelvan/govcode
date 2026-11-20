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
	"github.com/sandy-t-shelvan/govcode/internal/ato"
	"github.com/sandy-t-shelvan/govcode/internal/audit"
	"github.com/sandy-t-shelvan/govcode/internal/eval"
	"github.com/sandy-t-shelvan/govcode/internal/evidence"
	"github.com/sandy-t-shelvan/govcode/internal/gitx"
	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/modelpin"
	"github.com/sandy-t-shelvan/govcode/internal/policy"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/rpc"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
	"github.com/sandy-t-shelvan/govcode/internal/supply"
)

const usage = `govcode - air-gapped coding agent for legacy code

Developer:
  govcode run [--plan] "<task>"   run the agent; produces a signed proposal (never touches the target branch)
  govcode run --resume <id> ["follow-up"]   continue an interrupted run (same proposal and audit session)
  govcode runs                    list interrupted runs that can be resumed
  govcode rewind <id> [n]         list checkpoints, or restore the worktree to checkpoint n (0 = base)
  govcode proposals               list proposals
  govcode review <id>             show a proposal: summary, tests, diff, audit trail

Approver (a different person when two_person_rule is on):
  govcode approve <id> [-m text]  land a proposal on the target branch
  govcode reject <id> -m reason   reject a proposal

Audit:
  govcode evidence <proposal|commit>           verify and print a landed change's AI evidence record
  govcode evidence export -since YYYY-MM-DD [-until D] -o f   verified records for an ATO package
  govcode audit verify            verify hash chain, signatures, objects and git anchors
  govcode audit show [-n N] [-session ID]
  govcode audit object <sha256>   print a stored payload

Editor integration:
  govcode serve --stdio           JSON-RPC 2.0 over stdin/stdout for the VS Code extension (no sockets)

Assessment:
  govcode ato -o dir [-stig xccdf] [-stig-map f] [-govulncheck f] [-test-json f]
                                  ATO evidence package (800-53 statements, DoWI 8430.01, STIG CKLB, VEX); self-assessment only

Setup and supply chain:
  govcode verify                  preflight: policy, release signature, model lock, served model, sandbox, keys, audit
  govcode keygen [--register]     create your Ed25519 signing key
  govcode init                    write a development policy for the current repo (warn mode)
  govcode sbom [-lock f] [-o f]   CycloneDX 1.6 SBOM of this binary, system tools and models
  govcode aibom -lock f [-o f]    CycloneDX 1.6 AI-BOM from a model lock
  govcode sign -key k file...     write detached signatures (release / model signing)
  govcode manifest -dir d -version v [-o f]   release manifest (SHA-256 of every file in d)
  govcode provenance -dir d -key k -source u -commit c -builder b   signed SLSA v1 provenance + SBOM attestation
  govcode attest verify -key pub -bundle f (-subject file | -sha256 h) [-type slsa|sbom]   offline check
  govcode model verify -dir d [-model id] [-key pub]   hashes, formats (GGUF/safetensors only) and staging scan
  govcode model sniff [-lock f] file...            refuse pickle-based or unknown weight formats
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
	case "evidence":
		err = cmdEvidence(args)
	case "rewind":
		err = cmdRewind(args)
	case "runs":
		err = cmdRuns(args)
	case "ato":
		err = cmdATO(args)
	case "provenance":
		err = cmdProvenance(args)
	case "attest":
		err = cmdAttest(args)
	case "manifest":
		err = cmdManifest(args)
	case "model":
		err = cmdModel(ctx, args)
	case "eval":
		err = cmdEval(ctx, args)
	case "serve":
		err = cmdServe(ctx, args)
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
	plan := fs.Bool("plan", false, "plan mode: read-only until you approve the model's plan")
	resume := fs.String("resume", "", "continue an interrupted run; any text given is a follow-up message")
	pos := parse(fs, args)
	task := strings.Join(pos, " ")
	if strings.TrimSpace(task) == "" && *resume == "" {
		return errors.New(`usage: govcode run "<task>" | govcode run --resume <id> ["follow-up"]`)
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
	p, err := a.Run(ctx, app.RunOptions{Task: task, Interactive: !*yes, Verbose: *verbose, Plan: *plan, Resume: *resume,
		OnToken: func(s string) { fmt.Print(s) }})
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
	res, err := a.Land(p, rules, *comment)
	if err != nil {
		return err
	}
	fmt.Printf("Landed %s on %s as %s (audit anchor %s, evidence %s)\n", p.ID, p.Target, res.Commit[:12], res.Anchor[:20], res.Evidence[:16])
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
			head := ""
			if r.Head != nil {
				head = fmt.Sprintf("%d:%s", r.Head.Seq, r.Head.Hash)
			}
			a.ReportAuditFailure(len(r.Problems), head)
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
	if _, err := os.Stat(app.SignerConfigPath()); err == nil && !flagSet(fs, "o") {
		// A PIV/CAC token is configured: nothing to generate; the key lives
		// on the card. Show it, and register its certificate if asked.
		s, err := app.LoadUserSigner()
		if err != nil {
			return err
		}
		pemData, err := sign.CertificatePEM(s)
		if err != nil {
			return err
		}
		fmt.Printf("PKCS#11 token key (%s), key id %s\n", app.SignerConfigPath(), s.KeyID())
		if *register {
			p, _, err := policy.Load(policy.Locate(*pol))
			if err != nil {
				return err
			}
			u, _ := identity.Current()
			path, err := keyring.RegisterPEM(p.Trust.KeyringDir, u, pemData)
			if err != nil {
				return fmt.Errorf("register: %w (in strict deployments the ISSO installs the certificate)", err)
			}
			fmt.Println("registered", path)
		} else {
			os.Stdout.Write(pemData)
		}
		return nil
	}
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
	vsix := fs.String("vsix", "", "include the VS Code extension package")
	fs.Parse(args)
	var extras []supply.Extra
	if *vsix != "" {
		extras = append(extras, supply.Extra{Name: "govcode-vscode", Type: "application", Path: *vsix,
			Description: "VS Code extension (plain JavaScript, zero npm dependencies); UI over govcode serve --stdio"})
	}
	var l *modelpin.Lock
	if *lock != "" {
		var err error
		if l, err = modelpin.Load(*lock); err != nil {
			return err
		}
	}
	b, err := supply.SBOM(l, extras...)
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
		case strings.HasSuffix(rel, ".vsix"):
			role = "vscode-extension"
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
		probs := m.CheckFormats()
		probs = append(probs, modelpin.VerifyArtifacts(m, *dir, func(p string) { fmt.Println("hashing", p) })...)
		if s := m.StagingScan; s == nil {
			fmt.Println("  WARN no staging malware scan recorded in the lock")
		} else if s.Result != "clean" {
			probs = append(probs, modelpin.Problem{Path: m.ID, Msg: fmt.Sprintf("staging scan by %s %s: %s", s.Scanner, s.Version, s.Result)})
		} else {
			fmt.Printf("staging scan clean (%s %s, signatures %s, %s)\n", s.Scanner, s.Version, s.Signatures, s.ScannedAt)
		}
		for _, p := range probs {
			fmt.Println("  FAIL", p.Path, p.Msg)
		}
		if len(probs) > 0 {
			return fmt.Errorf("%d artifact(s) failed verification", len(probs))
		}
		fmt.Printf("%s: all artifacts match the lock\n", m.ID)
		return nil
	case "sniff":
		// Used by stage-models.sh: refuse any file that is not GGUF or
		// safetensors by content, and any lock entry naming a pickle format.
		fs := flag.NewFlagSet("model sniff", flag.ExitOnError)
		lock := fs.String("lock", "", "also check every lock entry's declared formats")
		fs.Parse(args[1:])
		bad := 0
		if *lock != "" {
			l, err := modelpin.Load(*lock)
			if err != nil {
				return err
			}
			for i := range l.Models {
				for _, p := range l.Models[i].CheckFormats() {
					fmt.Println("REFUSED", p.Path, p.Msg)
					bad++
				}
			}
		}
		for _, f := range fs.Args() {
			if err := modelpin.CheckWeightFile(f); err != nil {
				fmt.Println("REFUSED", f, err)
				bad++
			} else {
				kind, _ := modelpin.SniffFile(f)
				fmt.Println("ok     ", f, kind)
			}
		}
		if bad > 0 {
			return fmt.Errorf("%d refused", bad)
		}
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

func cmdServe(ctx context.Context, args []string) error {
	fs, pol := flags("serve")
	stdio := fs.Bool("stdio", false, "serve JSON-RPC on stdin/stdout (the only transport)")
	parse(fs, args)
	if !*stdio {
		return errors.New("usage: govcode serve --stdio (network listeners are not supported)")
	}
	s := &rpc.Server{PolicyPath: *pol}
	return s.Serve(ctx, os.Stdin, os.Stdout)
}

func cmdEval(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	tasks := fs.String("tasks", "eval/tasks", "task directory")
	out := fs.String("o", "eval/results", "results directory")
	only := fs.String("only", "", "run only tasks whose id contains this (comma-separated list allowed)")
	backend := fs.String("backend", "ollama", "ollama | openai | oracle")
	endpoint := fs.String("endpoint", "http://127.0.0.1:11434", "model server (loopback)")
	model := fs.String("model", "govcode-devstral:24b-q4km", "served model name")
	numCtx := fs.Int("num-ctx", 32768, "context length (must match server)")
	maxTok := fs.Int("max-tokens", 4096, "max output tokens per turn")
	temp := fs.Float64("temperature", 0.2, "temperature")
	turns := fs.Int("max-turns", 30, "max agent turns per task")
	verbose := fs.Bool("verbose", false, "stream agent output")
	toolPrompt := fs.String("tool-prompt", "", "text appended to the system prompt when tools are offered (the lock's serve.tool_prompt)")
	seed := fs.Int("seed", 42, "sampling seed sent with every request; vary it to measure run-to-run spread")
	fs.Parse(args)
	cfg := eval.Config{TasksDir: *tasks, OutDir: *out, Only: *only, MaxTurns: *turns}
	if *verbose {
		cfg.Log = os.Stdout
	} else {
		cfg.Log = io.Discard
	}
	opts := llm.Options{NumCtx: *numCtx, MaxTokens: *maxTok, Temperature: *temp, Seed: *seed, ToolPrompt: *toolPrompt}
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

// cmdProvenance writes the signed SLSA v1 provenance and the SBOM
// attestation for a release directory (called by build-release.sh).
func cmdProvenance(args []string) error {
	fs := flag.NewFlagSet("provenance", flag.ExitOnError)
	dir := fs.String("dir", "", "release directory")
	key := fs.String("key", "", "release signing key")
	bi := supply.BuildInfo{}
	fs.StringVar(&bi.Version, "version", supply.Version, "release version")
	fs.StringVar(&bi.SourceRepo, "source", "", "source repository URI (git+https://...)")
	fs.StringVar(&bi.Commit, "commit", "", "full source commit")
	fs.BoolVar(&bi.TreeClean, "clean", false, "the work tree had no uncommitted changes")
	fs.StringVar(&bi.GoVersion, "go-version", "", "`go version` output")
	fs.StringVar(&bi.GoToolSHA256, "go-sha256", "", "SHA-256 of the go tool")
	fs.BoolVar(&bi.Reproducible, "reproducible", false, "two builds produced the same binary")
	fs.StringVar(&bi.ReproSHA256, "repro-sha256", "", "binary hash both builds produced")
	fs.StringVar(&bi.BuilderID, "builder", "", "builder identity (URI of the build host or pipeline)")
	started := fs.Int64("started", 0, "build start, Unix seconds")
	var env multi
	fs.Var(&env, "env", "build environment KEY=VALUE (repeatable)")
	fs.Parse(args)
	if *dir == "" || *key == "" || bi.BuilderID == "" {
		return errors.New("usage: govcode provenance -dir <release> -key <release.key> -source <uri> -commit <sha> -builder <id> [...]")
	}
	bi.Env = map[string]string{}
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		bi.Env[k] = v
	}
	if *started > 0 {
		bi.StartedOn, bi.FinishedOn = time.Unix(*started, 0), time.Now()
	}
	s, err := sign.LoadSigner(*key)
	if err != nil {
		return err
	}
	st, err := supply.BuildProvenance(*dir, bi)
	if err != nil {
		return err
	}
	line, err := supply.SignStatement(s, st)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, supply.ProvenanceFile), line, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d subjects, key %s)\n", supply.ProvenanceFile, len(st.Subject), s.KeyID())

	sbom, err := os.ReadFile(filepath.Join(*dir, "sbom.cdx.json"))
	if err != nil {
		return err
	}
	var subs []supply.Subject
	for _, sub := range st.Subject {
		if strings.HasPrefix(sub.Name, "bin/") || strings.HasSuffix(sub.Name, ".vsix") {
			subs = append(subs, sub)
		}
	}
	sst, err := supply.SBOMStatement(sbom, subs)
	if err != nil {
		return err
	}
	if line, err = supply.SignStatement(s, sst); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, supply.SBOMAttestationFile), line, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d subjects)\n", supply.SBOMAttestationFile, len(subs))
	return nil
}

// cmdAttest verifies an attestation offline: govcode attest verify
// -key release.pub -bundle provenance.intoto.jsonl -subject bin/govcode
func cmdAttest(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: govcode attest verify -key <pub> -bundle <file.intoto.jsonl> (-subject <file> | -sha256 <hex>) [-type slsa|sbom]")
	}
	fs := flag.NewFlagSet("attest verify", flag.ExitOnError)
	var keys multi
	fs.Var(&keys, "key", "trusted release public key (repeatable)")
	bundle := fs.String("bundle", "", "attestation bundle")
	subject := fs.String("subject", "", "file that must be a subject")
	sum := fs.String("sha256", "", "SHA-256 that must be a subject")
	typ := fs.String("type", "slsa", "slsa (build provenance) or sbom")
	fs.Parse(args[1:])
	if len(keys) == 0 || *bundle == "" || (*subject == "") == (*sum == "") {
		return errors.New("usage: govcode attest verify -key <pub> -bundle <file> (-subject <file> | -sha256 <hex>)")
	}
	pt := supply.SLSAProvenanceType
	if *typ == "sbom" {
		pt = supply.CycloneDXPredicate
	} else if *typ != "slsa" {
		return fmt.Errorf("unknown -type %q", *typ)
	}
	trusted, err := loadPubs(keys)
	if err != nil {
		return err
	}
	if *subject != "" {
		if *sum, _, err = modelpin.HashFile(*subject); err != nil {
			return err
		}
	}
	data, err := os.ReadFile(*bundle)
	if err != nil {
		return err
	}
	r, err := supply.VerifyAttestation(data, pt, trusted, *sum)
	if err != nil {
		return err
	}
	fmt.Printf("PASS  %s is subject %q, signed by %s\n", (*sum)[:16], r.Subject.Name, r.KeyID)
	if pt == supply.SLSAProvenanceType {
		fmt.Printf("      built by %s from %s@%s (reproducible=%v)\n", r.Builder, r.Source, r.Commit, r.Repro)
	}
	return nil
}

func cmdEvidence(args []string) error {
	if len(args) > 0 && args[0] == "export" {
		return cmdEvidenceExport(args[1:])
	}
	fs, pol := flags("evidence")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: govcode evidence <proposal-id|commit> | govcode evidence export -since YYYY-MM-DD -o file")
	}
	a, checks, err := app.Open(*pol, os.Stdout, false)
	if err != nil {
		printChecks(checks)
		return err
	}
	banner(a)
	v, err := a.VerifyEvidence(pos[0])
	if err != nil {
		return err
	}
	r := v.Record
	fmt.Printf("PASS  evidence %s for %s\n", v.SHA256, r.Proposal)
	fmt.Printf("      signed by approver %s (key %s); audit %d:%.12s .. %d:%.12s present in the log\n",
		r.Approver.Username, r.Approver.KeyID, r.Audit.FirstSeq, r.Audit.FirstHash, r.Audit.LastSeq, r.Audit.LastHash)
	fmt.Printf("      model %s (%s, origin %s) num_ctx=%d temperature=%g\n\n", r.Model.ID, r.Model.Publisher, strings.Join(r.Model.Origins, ","), r.Model.NumCtx, r.Model.Temperature)
	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(b))
	return nil
}

func cmdEvidenceExport(args []string) error {
	fs, pol := flags("evidence export")
	since := fs.String("since", "", "first approval date, YYYY-MM-DD (inclusive)")
	until := fs.String("until", "", "last approval date, YYYY-MM-DD (inclusive; default today)")
	out := fs.String("o", "", "output file")
	parse(fs, args)
	if *since == "" || *out == "" {
		return errors.New("usage: govcode evidence export -since YYYY-MM-DD [-until YYYY-MM-DD] -o file")
	}
	from, err := time.Parse("2006-01-02", *since)
	if err != nil {
		return fmt.Errorf("-since: %w", err)
	}
	to := time.Now().UTC()
	if *until != "" {
		if to, err = time.Parse("2006-01-02", *until); err != nil {
			return fmt.Errorf("-until: %w", err)
		}
	}
	to = to.Truncate(24 * time.Hour).Add(24 * time.Hour)
	a, checks, err := app.Open(*pol, os.Stdout, false)
	if err != nil {
		printChecks(checks)
		return err
	}
	ids, err := a.Evidence.List()
	if err != nil {
		return err
	}
	type item struct {
		SHA256 string           `json:"sha256"`
		Record *evidence.Record `json:"record"`
	}
	exp := struct {
		Schema         string `json:"schema"`
		Classification string `json:"classification"`
		Generated      string `json:"generated"`
		Since          string `json:"since"`
		Until          string `json:"until"`
		Records        []item `json:"records"`
	}{Schema: "govcode.evidence.export/v1", Classification: a.Policy.Classification, Generated: time.Now().UTC().Format(time.RFC3339),
		Since: from.Format("2006-01-02"), Until: to.Add(-time.Second).Format("2006-01-02"), Records: []item{}}
	for _, id := range ids {
		v, err := a.VerifyEvidence(id)
		if err != nil {
			return fmt.Errorf("%s: %w (export stopped; nothing written)", id, err)
		}
		at, _ := time.Parse(time.RFC3339, v.Record.ApprovedAt)
		if at.Before(from) || !at.Before(to) {
			continue
		}
		exp.Records = append(exp.Records, item{v.SHA256, v.Record})
	}
	if err := writeJSON(*out, exp); err != nil {
		return err
	}
	sum, _, _ := modelpin.HashFile(*out)
	fmt.Printf("== %s ==\nwrote %s: %d verified record(s), sha256 %s\nThe export is classified at %s; handle it like the audit log.\n",
		a.Policy.Classification, *out, len(exp.Records), sum, a.Policy.Classification)
	return nil
}

func cmdATO(args []string) error {
	fs, pol := flags("ato")
	out := fs.String("o", "", "output directory (must not exist or be empty)")
	stig := fs.String("stig", "", "official ASD STIG XCCDF (from DISA) to build the checklist from")
	stigMap := fs.String("stig-map", "", "site rule map JSON: statuses and comments by V-ID")
	vuln := fs.String("govulncheck", "", "`govulncheck -json ./...` output for the VEX document")
	testJSON := fs.String("test-json", "", "`go test -json ./...` output for the test summary")
	auditN := fs.Int("audit-n", 20, "audit entries to sample")
	parse(fs, args)
	if *out == "" {
		return errors.New("usage: govcode ato -o <dir> [-stig xccdf] [-stig-map f] [-govulncheck f] [-test-json f]")
	}
	host, _ := os.Hostname()
	in := ato.Inputs{Version: supply.Version, Host: host, Now: time.Now()}

	a, checks, oerr := app.Open(*pol, io.Discard, false)
	for _, c := range checks {
		in.Preflight = append(in.Preflight, map[string]any{"name": c.Name, "status": c.Status, "detail": c.Detail})
	}
	if oerr != nil {
		in.Preflight = append(in.Preflight, map[string]any{"name": "open", "status": "FAIL", "detail": oerr.Error()})
		fmt.Fprintln(os.Stderr, "warning: policy not loaded; configuration and audit sample omitted:", oerr)
	}
	if a != nil && a.Policy != nil {
		p := a.Policy
		in.Classification = p.Classification
		var analyzers []string
		for _, x := range p.Analysis.Analyzers {
			analyzers = append(analyzers, x.Name)
		}
		in.Policy = map[string]any{
			"path": p.Path, "classification": p.Classification, "enforce": p.Trust.Enforce, "repo_root": p.RepoRoot,
			"target_branch": p.TargetBranch, "sensitive": p.Sensitive, "two_person_rule": p.TwoPersonRule,
			"approvers": len(p.Approvers), "sandbox_mode": p.Sandbox.Mode, "spillage_guard": p.SpillageGuard == nil || *p.SpillageGuard,
			"require_plan_approval": p.RequirePlanApproval, "audit_require_append_only": p.Audit.RequireAppendOnly,
			"analysis_required": p.Analysis.Required, "analyzers": analyzers, "model_id": p.Model.ID,
			"denied_origins": p.Model.DeniedOrigins, "allowed_origins": p.Model.AllowedOrigins,
			"origin_exception": p.Model.OriginException != nil, "siem_syslog": p.SIEM.Syslog,
			"release_provenance": p.Trust.ReleaseProvenance != "",
		}
		if a.Log != nil && *auditN > 0 {
			var ring []map[string]any
			a.Log.Each(func(e *audit.Entry, _ []byte) error {
				ring = append(ring, map[string]any{"seq": e.Seq, "ts": e.Time, "kind": e.Kind, "actor": e.Actor.Username,
					"uid": e.Actor.UID, "session": e.Session, "summary": e.Summary, "hash": e.Hash})
				if len(ring) > *auditN {
					ring = ring[1:]
				}
				return nil
			})
			in.AuditSample = append([]map[string]any{}, ring...)
		}
	}
	if *stig != "" {
		f, err := os.Open(*stig)
		if err != nil {
			return err
		}
		in.Benchmark, err = ato.ParseXCCDF(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", *stig, err)
		}
	}
	if *stigMap != "" {
		m, err := ato.LoadSiteRuleMap(*stigMap)
		if err != nil {
			return err
		}
		in.Site = m
	}
	if *vuln != "" {
		f, err := os.Open(*vuln)
		if err != nil {
			return err
		}
		doc, sum, err := ato.VEX(f, "github.com/sandy-t-shelvan/govcode", supply.Version, in.Now)
		f.Close()
		if err != nil {
			return err
		}
		in.VEX, in.VEXSummary = doc, &sum
	}
	if *testJSON != "" {
		f, err := os.Open(*testJSON)
		if err != nil {
			return err
		}
		in.Tests, err = ato.SummarizeGoTest(f)
		f.Close()
		if err != nil {
			return err
		}
	}
	files, err := ato.Write(*out, in)
	if err != nil {
		return err
	}
	if in.Classification != "" {
		fmt.Printf("== %s ==\n", in.Classification)
	}
	fmt.Printf("wrote %d files to %s\n%s\n", len(files), *out, ato.Disclaimer)
	return nil
}

func cmdRuns(args []string) error {
	fs, pol := flags("runs")
	parse(fs, args)
	a, checks, err := app.Open(*pol, os.Stdout, false)
	if err != nil {
		printChecks(checks)
		return err
	}
	rs, err := a.Runs.List()
	if err != nil {
		return err
	}
	if len(rs) == 0 {
		fmt.Println("no interrupted runs")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tPROPOSER\tCHECKPOINTS\tUPDATED\tTASK")
	for _, r := range rs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", r.ID, r.Status, r.Proposer, r.Checkpoints, r.Updated, oneLine(r.Task, 60))
	}
	return tw.Flush()
}

func cmdRewind(args []string) error {
	fs, pol := flags("rewind")
	pos := parse(fs, args)
	if len(pos) < 1 || len(pos) > 2 {
		return errors.New("usage: govcode rewind <id> [n]")
	}
	a, checks, err := app.Open(*pol, os.Stdout, true)
	if err != nil {
		printChecks(checks)
		return err
	}
	banner(a)
	if len(pos) == 1 {
		st, cs, err := a.Checkpoints(pos[0])
		if err != nil {
			return err
		}
		fmt.Printf("run %s (%s), base %.10s\n  0  base\n", st.ID, st.Status, st.Base)
		for _, c := range cs {
			fmt.Printf("  %d  %.10s  %s\n", c.N, c.Commit, strings.Join(c.Files, ", "))
		}
		return nil
	}
	var n int
	if _, err := fmt.Sscan(pos[1], &n); err != nil || n < 0 {
		return fmt.Errorf("checkpoint must be a number >= 0")
	}
	files, err := a.Rewind(pos[0], n)
	if err != nil {
		return err
	}
	fmt.Printf("rewound %s to checkpoint %d; changed files: %s\nResume: govcode run --resume %s\n", pos[0], n, strings.Join(files, ", "), pos[0])
	return nil
}

// flagSet reports whether the named flag was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// Package app wires policy, identity, keys, audit, model and tools into the
// govcode commands.
package app

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/audit"
	"github.com/sandy-t-shelvan/govcode/internal/gitx"
	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/modelpin"
	"github.com/sandy-t-shelvan/govcode/internal/policy"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/siem"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
	"github.com/sandy-t-shelvan/govcode/internal/supply"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

type App struct {
	Policy  *policy.Policy
	User    identity.User
	Repo    *gitx.Repo
	Keyring *keyring.Keyring
	Signer  sign.Signer
	Log     *audit.Log
	Store   proposal.Store
	Lock    *modelpin.Lock
	Model   *modelpin.Model
	// OriginException is set when the selected model's origin is denied
	// but the policy records an AO exception for it; every task records it.
	OriginException *policy.OriginException
	Out             io.Writer
	Warnings        []string
	siemExp         *siem.Exporter
}

// KeyPath is the invoking user's private signing key.
func KeyPath() string {
	if k := os.Getenv("GOVCODE_KEY"); k != "" {
		return k
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "govcode", "signing.key")
}

type Check struct {
	Name   string
	Status string // PASS | WARN | FAIL | SKIP
	Detail string
}

// Open loads everything and runs preflight checks. In strict mode any FAIL
// aborts. needSigner=false is used by read-only commands.
func Open(policyPath string, out io.Writer, needSigner bool) (*App, []Check, error) {
	a := &App{Out: out}
	var checks []Check
	add := func(name, status, detail string) { checks = append(checks, Check{name, status, detail}) }

	p, warns, err := policy.Load(policy.Locate(policyPath))
	if err != nil {
		return nil, nil, err
	}
	a.Policy, a.Warnings = p, warns
	add("policy", "PASS", fmt.Sprintf("%s (enforce=%s, classification=%s)", p.Path, p.Trust.Enforce, p.Classification))
	for _, w := range warns {
		add("policy", "WARN", w)
	}

	if a.User, err = identity.Current(); err != nil {
		return nil, nil, err
	}
	add("identity", "PASS", a.User.String())

	cwd, _ := os.Getwd()
	repo, err := gitx.Open(cwd)
	if err != nil {
		repo, err = gitx.Open(p.RepoRoot)
		if err != nil {
			return nil, nil, err
		}
	}
	if err := p.CheckRepo(repo.Root); err != nil {
		return nil, nil, err
	}
	a.Repo = repo
	add("repository", "PASS", repo.Root+" (the only repository this policy grants)")

	// Supply chain: binary
	if p.Trust.ReleaseManifest != "" {
		keys, kerr := loadKeys(p.Trust.ReleaseKeys)
		if kerr != nil {
			add("release signature", "FAIL", kerr.Error())
		} else if msg, err := supply.VerifySelf(p.Trust.ReleaseManifest, keys); err != nil {
			add("release signature", "FAIL", err.Error())
		} else {
			add("release signature", "PASS", msg)
		}
	} else {
		add("release signature", "SKIP", "no trust.release_manifest configured (development)")
	}

	// Supply chain: model lock
	if p.Model.Lock != "" {
		var l *modelpin.Lock
		if len(p.Trust.ModelKeys) > 0 {
			keys, kerr := loadKeys(p.Trust.ModelKeys)
			if kerr != nil {
				add("model lock signature", "FAIL", kerr.Error())
			} else if lk, kid, err := modelpin.LoadVerified(p.Model.Lock, keys); err != nil {
				add("model lock signature", "FAIL", err.Error())
			} else {
				l = lk
				add("model lock signature", "PASS", "signed by "+kid)
			}
		} else if lk, err := modelpin.Load(p.Model.Lock); err == nil {
			l = lk
			add("model lock signature", "WARN", "no trust.model_keys; lock loaded unsigned")
		} else {
			add("model lock", "FAIL", err.Error())
		}
		if l != nil {
			a.Lock = l
			if m, err := l.Find(p.Model.ID); err != nil {
				add("model", "FAIL", err.Error())
			} else {
				a.Model = m
				a.checkOrigin(m, add)
				if m.Serve.NumCtx != p.Model.NumCtx {
					add("num_ctx", "FAIL", fmt.Sprintf("policy num_ctx %d != lock num_ctx %d", p.Model.NumCtx, m.Serve.NumCtx))
				} else {
					add("num_ctx", "PASS", fmt.Sprint(p.Model.NumCtx))
				}
			}
		}
	} else {
		add("model lock", "SKIP", "no model.lock configured (development)")
	}
	if p.Model.VerifyDigest && p.Model.Backend == "ollama" && a.Model != nil {
		if err := modelpin.CheckOllama(context.Background(), p.Model.Endpoint, a.Model); err != nil {
			add("served model digest", "FAIL", err.Error())
		} else {
			add("served model digest", "PASS", a.Model.Serve.OllamaName+" "+a.Model.Serve.OllamaDigest)
		}
	}

	// Sandbox availability
	if _, err := tools.NewRunner(p.Sandbox.Mode, repo.Root, p.Sandbox.ExtraROPaths, p.Sandbox.Env); err != nil {
		add("sandbox", "FAIL", err.Error())
	} else {
		add("sandbox", "PASS", "mode="+p.Sandbox.Mode)
	}

	// git >= 2.38 for merge-tree --write-tree
	if v, err := gitx.Git(repo.Root, "version"); err == nil {
		add("git", "PASS", strings.TrimSpace(v))
	}

	// Keys
	if a.Keyring, err = keyring.Load(p.Trust.KeyringDir); err != nil {
		return nil, nil, err
	}
	for _, s := range a.Keyring.Skipped {
		add("keyring", "WARN", "ignored "+s)
	}
	if needSigner {
		s, err := sign.LoadSigner(KeyPath())
		if err != nil {
			add("signing key", "FAIL", err.Error())
		} else {
			a.Signer = s
			registered := false
			for _, e := range a.Keyring.ForUser(a.User.Username) {
				if e.KeyID == s.KeyID() {
					registered = true
				}
			}
			if registered {
				add("signing key", "PASS", "key "+s.KeyID()+" registered for "+a.User.Username)
			} else {
				add("signing key", "FAIL", fmt.Sprintf("key %s is not in the keyring %s for %s (run `govcode keygen --register` or ask the ISSO to install your .pub)", s.KeyID(), p.Trust.KeyringDir, a.User.Username))
			}
		}
	}

	// Audit
	a.Log = &audit.Log{Dir: filepath.Join(p.StateDir, "audit"), Classification: p.Classification, Repo: repo.Root, RequireAppend: p.Audit.RequireAppendOnly}
	if err := a.Log.Open(); err != nil {
		add("audit log", "FAIL", err.Error())
	} else if ok, ferr := audit.AppendOnlyFlag(a.Log.LogPath()); ferr == nil && ok {
		add("audit log", "PASS", a.Log.LogPath()+" (append-only inode flag set)")
	} else {
		st := "WARN"
		if p.Audit.RequireAppendOnly {
			st = "FAIL"
		}
		add("audit log", st, a.Log.LogPath()+" is not chattr +a")
	}
	a.Store = proposal.Store{Dir: filepath.Join(p.StateDir, "proposals")}

	for _, c := range checks {
		if c.Status == "FAIL" && (p.Strict() || isAlwaysFatal(c.Name)) {
			return a, checks, fmt.Errorf("preflight failed: %s: %s", c.Name, c.Detail)
		}
	}
	return a, checks, nil
}

// checkOrigin applies model.allowed_origins / denied_origins to the model
// and its lineage. A denial is fatal in every mode unless the policy holds an
// unexpired AO exception naming this exact model.
func (a *App) checkOrigin(m *modelpin.Model, add func(name, status, detail string)) {
	pm := a.Policy.Model
	op := pm.Origins()
	if !op.Active() {
		add("model origin", "SKIP", "no origin restriction in policy; lock records "+strings.Join(m.Origins(), ","))
		return
	}
	err := modelpin.CheckOrigin(m, op)
	if err == nil {
		add("model origin", "PASS", m.ID+" origin "+strings.Join(m.Origins(), ","))
		return
	}
	if e := pm.OriginException; e != nil && e.ModelID == m.ID {
		exp, _ := time.Parse("2006-01-02", e.Expires)
		if time.Now().Before(exp.AddDate(0, 0, 1)) {
			a.OriginException = e
			add("model origin", "WARN", fmt.Sprintf("%v; permitted by AO exception (%s, ref %s, expires %s)", err, e.AuthorizedBy, e.Reference, e.Expires))
			return
		}
		add("model origin", "FAIL", fmt.Sprintf("%v; AO exception %s expired on %s", err, e.Reference, e.Expires))
		return
	}
	add("model origin", "FAIL", err.Error())
}

// Some failures are fatal even in warn mode.
func isAlwaysFatal(name string) bool {
	switch name {
	case "signing key", "audit log", "sandbox", "num_ctx", "served model digest", "model origin":
		return true
	}
	return false
}

func loadKeys(paths []string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, p := range paths {
		k, err := sign.LoadPublic(p)
		if err != nil {
			return nil, fmt.Errorf("trusted key %s: %w", p, err)
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no trusted keys configured")
	}
	return out, nil
}

// Backend builds the model client from policy (and the lock, if any).
func (a *App) Backend() (llm.Backend, error) {
	p := a.Policy.Model
	opts := llm.Options{NumCtx: p.NumCtx, MaxTokens: p.MaxTokens, Temperature: p.Temperature, Seed: 42}
	name := p.ServedName
	if name == "" && a.Model != nil {
		name = a.Model.Serve.OllamaName
		if p.Backend == "openai" {
			name = a.Model.ID
		}
	}
	if name == "" {
		name = p.ID
	}
	if p.Backend == "openai" {
		return llm.NewOpenAICompat(p.Endpoint, name, opts)
	}
	return llm.NewOllama(p.Endpoint, name, opts)
}

func (a *App) Session(id string) *audit.Session {
	return &audit.Session{Log: a.Log, Signer: a.Signer, Actor: a.User, ID: id, OnRecord: a.forward}
}

// TTYApprover asks the human at the controlling terminal. It reads
// /dev/tty, not stdin, so piped input cannot approve commands.
type TTYApprover struct {
	User identity.User
	Rec  *audit.Session
}

func (t *TTYApprover) Approve(cmd string) (bool, string) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, "no-terminal"
	}
	defer tty.Close()
	fmt.Fprintf(tty, "\n  Policy requires your approval for:\n\n      %s\n\n  Allow it? [y/N] ", cmd)
	ans, _ := bufio.NewReader(tty).ReadString('\n')
	ok := strings.EqualFold(strings.TrimSpace(ans), "y") || strings.EqualFold(strings.TrimSpace(ans), "yes")
	if t.Rec != nil {
		t.Rec.Record("approval_prompt", map[string]any{"action": cmd, "decision": map[bool]string{true: "allow", false: "deny"}[ok], "approver": t.User.Username})
	}
	return ok, t.User.Username
}

// TTYPlanReviewer shows the plan on the terminal and asks for a decision.
type TTYPlanReviewer struct{}

func (TTYPlanReviewer) ReviewPlan(steps []string, summary string) (bool, string) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, "no terminal attached"
	}
	defer tty.Close()
	fmt.Fprintf(tty, "\n  Proposed plan: %s\n", summary)
	for i, s := range steps {
		fmt.Fprintf(tty, "    %d. %s\n", i+1, s)
	}
	fmt.Fprint(tty, "\n  [a]pprove, [r]eject with feedback: ")
	r := bufio.NewReader(tty)
	ans, _ := r.ReadString('\n')
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ans)), "a") {
		fmt.Fprint(tty, "  Notes for the model (optional): ")
		notes, _ := r.ReadString('\n')
		return true, strings.TrimSpace(notes)
	}
	fmt.Fprint(tty, "  What should change? ")
	fb, _ := r.ReadString('\n')
	if strings.TrimSpace(fb) == "" {
		fb = "rejected without comment"
	}
	return false, strings.TrimSpace(fb)
}

// ConfirmTTY requires the human to type a word at the terminal.
func ConfirmTTY(prompt, word string) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer tty.Close()
	fmt.Fprintf(tty, "%s\nType %q to confirm: ", prompt, word)
	ans, _ := bufio.NewReader(tty).ReadString('\n')
	return strings.TrimSpace(ans) == word
}

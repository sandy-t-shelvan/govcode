// Package policy loads the site policy that governs one repository.
//
// The policy is the administrator's (ISSO's) file. In strict mode it must be
// owned by root and not writable by group/other, so the developer running
// govcode cannot loosen it (add themselves as approver, disable the
// sandbox, point at a different repo).
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/marking"
	"github.com/sandy-t-shelvan/govcode/internal/netguard"
	"github.com/sandy-t-shelvan/govcode/internal/permissions"
)

const Schema = "govcode.policy/v1"

type Model struct {
	Backend      string  `json:"backend"`  // "ollama" | "openai"
	Endpoint     string  `json:"endpoint"` // loopback only
	Lock         string  `json:"lock"`     // signed models.lock.json
	ID           string  `json:"id"`       // model id in the lock
	ServedName   string  `json:"served_name,omitempty"`
	NumCtx       int     `json:"num_ctx"`
	MaxTokens    int     `json:"max_tokens"`
	Temperature  float64 `json:"temperature"`
	VerifyDigest bool    `json:"verify_digest"`
}

type Tests struct {
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	RequirePass    bool   `json:"require_pass"`
}

type Commands struct {
	Allowlist       []string `json:"allowlist"`
	PromptForOthers bool     `json:"prompt_for_others"`
}

type Sandbox struct {
	Mode         string   `json:"mode"` // required | best-effort | off
	ExtraROPaths []string `json:"extra_ro_paths"`
	Env          []string `json:"env"`
}

type Trust struct {
	Enforce         string   `json:"enforce"` // strict | warn
	ReleaseKeys     []string `json:"release_keys"`
	ReleaseManifest string   `json:"release_manifest"`
	ModelKeys       []string `json:"model_keys"`
	KeyringDir      string   `json:"keyring_dir"`
}

// Permissions are allow/ask/deny rules, e.g. "run_command(make *)",
// "edit_file(src/**)". Precedence deny > ask > allow (internal/permissions).
type Permissions struct {
	Allow []string `json:"allow"`
	Ask   []string `json:"ask"`
	Deny  []string `json:"deny"`
}

// Secrets configures the proposal secret scan. Allow holds regexps for
// known-safe lines (test fixtures); it exists only here, never in the repo.
type Secrets struct {
	Allow []string `json:"allow"`
}

type Audit struct {
	RequireAppendOnly bool `json:"require_append_only"`
}

type Policy struct {
	Schema                      string      `json:"schema"`
	Classification              string      `json:"classification"`
	RepoRoot                    string      `json:"repo_root"`
	StateDir                    string      `json:"state_dir"`
	TargetBranch                string      `json:"target_branch"`
	Sensitive                   bool        `json:"sensitive"`
	TwoPersonRule               bool        `json:"two_person_rule"`
	Approvers                   []string    `json:"approvers"`
	Proposers                   []string    `json:"proposers"`
	AllowNonInteractiveApproval bool        `json:"allow_non_interactive_approval"`
	MaxTurns                    int         `json:"max_turns"`
	Model                       Model       `json:"model"`
	Tests                       Tests       `json:"tests"`
	Commands                    Commands    `json:"commands"`
	Permissions                 Permissions `json:"permissions"`
	Secrets                     Secrets     `json:"secrets"`
	// SpillageGuard withholds content marked above Classification from
	// the model and blocks proposals that contain it. Default true; it
	// cannot be turned off in strict mode.
	SpillageGuard *bool   `json:"spillage_guard,omitempty"`
	Sandbox       Sandbox `json:"sandbox"`
	Trust         Trust   `json:"trust"`
	Audit         Audit   `json:"audit"`

	Path string `json:"-"`
}

func (p *Policy) Strict() bool { return p.Trust.Enforce != "warn" }

func (p *Policy) TestTimeout() time.Duration {
	if p.Tests.TimeoutSeconds <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(p.Tests.TimeoutSeconds) * time.Second
}

// Locate finds the policy: explicit path, $GOVCODE_POLICY, then
// /etc/govcode/policy.json.
func Locate(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if e := os.Getenv("GOVCODE_POLICY"); e != "" {
		return e
	}
	return "/etc/govcode/policy.json"
}

func Load(path string) (*Policy, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("policy: %w (an administrator must install one; `govcode init` writes a development policy)", err)
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("policy %s: %w", path, err)
	}
	p.Path = path
	warnings, err := p.validate()
	if err != nil {
		return nil, nil, fmt.Errorf("policy %s: %w", path, err)
	}
	if w, err := p.checkFilePerms(); err != nil {
		return nil, nil, err
	} else if w != "" {
		warnings = append(warnings, w)
	}
	return &p, warnings, nil
}

func (p *Policy) validate() ([]string, error) {
	var warn []string
	if p.Schema != Schema {
		return nil, fmt.Errorf("schema must be %q", Schema)
	}
	if p.Classification == "" {
		return nil, fmt.Errorf("classification marking is required (it is stamped on every audit entry)")
	}
	if p.RepoRoot == "" || !filepath.IsAbs(p.RepoRoot) {
		return nil, fmt.Errorf("repo_root must be an absolute path to exactly one repository")
	}
	if p.StateDir == "" || !filepath.IsAbs(p.StateDir) {
		return nil, fmt.Errorf("state_dir must be an absolute path")
	}
	if rel, err := filepath.Rel(p.RepoRoot, p.StateDir); err == nil && !strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("state_dir must be outside repo_root (the model must not be able to reach the audit log)")
	}
	if p.TargetBranch == "" {
		p.TargetBranch = "main"
	}
	switch p.Trust.Enforce {
	case "strict", "warn":
	case "":
		p.Trust.Enforce = "strict"
	default:
		return nil, fmt.Errorf("trust.enforce must be strict or warn")
	}
	if p.Sensitive && !p.TwoPersonRule {
		return nil, fmt.Errorf("sensitive repositories require two_person_rule: true")
	}
	if p.TwoPersonRule && len(p.Approvers) == 0 {
		return nil, fmt.Errorf("two_person_rule requires a non-empty approvers list")
	}
	switch p.Model.Backend {
	case "ollama", "openai":
	default:
		return nil, fmt.Errorf("model.backend must be ollama or openai")
	}
	if err := netguard.CheckURL(p.Model.Endpoint); err != nil {
		return nil, fmt.Errorf("model.endpoint: %w", err)
	}
	if p.Model.NumCtx < 4096 {
		return nil, fmt.Errorf("model.num_ctx must be set explicitly (>= 4096); it must match the server's context length")
	}
	if p.Model.MaxTokens <= 0 || p.Model.MaxTokens >= p.Model.NumCtx/2 {
		return nil, fmt.Errorf("model.max_tokens must be > 0 and < num_ctx/2")
	}
	switch p.Sandbox.Mode {
	case "required", "best-effort":
	case "off":
		if p.Strict() {
			return nil, fmt.Errorf("sandbox.mode off is not allowed with trust.enforce strict")
		}
		warn = append(warn, "sandbox disabled: commands run with the user's full privileges")
	case "":
		p.Sandbox.Mode = "required"
	default:
		return nil, fmt.Errorf("sandbox.mode must be required, best-effort or off")
	}
	if p.Strict() {
		if len(p.Trust.ReleaseKeys) == 0 || p.Trust.ReleaseManifest == "" {
			return nil, fmt.Errorf("strict mode requires trust.release_keys and trust.release_manifest")
		}
		if len(p.Trust.ModelKeys) == 0 || p.Model.Lock == "" {
			return nil, fmt.Errorf("strict mode requires trust.model_keys and model.lock")
		}
		if !p.Audit.RequireAppendOnly {
			warn = append(warn, "audit.require_append_only is false; the log is tamper-evident but not tamper-resistant")
		}
	}
	if p.SpillageGuard == nil {
		t := true
		p.SpillageGuard = &t
	}
	if !*p.SpillageGuard {
		if p.Strict() {
			return nil, fmt.Errorf("spillage_guard cannot be disabled with trust.enforce strict")
		}
		warn = append(warn, "spillage guard disabled")
	} else if marking.ParseLevel(p.Classification) == marking.Unknown {
		return nil, fmt.Errorf("classification %q does not start with a recognised level (UNCLASSIFIED, CONFIDENTIAL, SECRET, TOP SECRET)", p.Classification)
	}
	if _, err := p.Rules(); err != nil {
		return nil, err
	}
	for _, a := range p.Secrets.Allow {
		if _, err := regexp.Compile(a); err != nil {
			return nil, fmt.Errorf("secrets.allow %q: %v", a, err)
		}
	}
	if p.Trust.KeyringDir == "" {
		p.Trust.KeyringDir = filepath.Join(p.StateDir, "keys")
	}
	if p.MaxTurns == 0 {
		p.MaxTurns = 40
	}
	return warn, nil
}

func (p *Policy) checkFilePerms() (string, error) {
	fi, err := os.Stat(p.Path)
	if err != nil {
		return "", err
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	bad := ""
	if fi.Mode().Perm()&0o022 != 0 {
		bad = fmt.Sprintf("is group/world writable (mode %o)", fi.Mode().Perm())
	} else if st != nil && st.Uid != 0 {
		bad = fmt.Sprintf("is owned by uid %d, not root", st.Uid)
	}
	if bad == "" {
		return "", nil
	}
	if p.Strict() {
		return "", fmt.Errorf("policy %s %s; in strict mode the policy must be root-owned and not writable by users", p.Path, bad)
	}
	return fmt.Sprintf("policy file %s %s (allowed only because trust.enforce=warn)", p.Path, bad), nil
}

func (p *Policy) IsApprover(user string) bool { return contains(p.Approvers, user) }

// Rules returns the permission rules, with the legacy commands.allowlist
// folded in as allow rules.
func (p *Policy) Rules() (*permissions.Rules, error) {
	allow := append(permissions.FromAllowlist(p.Commands.Allowlist), p.Permissions.Allow...)
	return permissions.Parse(allow, p.Permissions.Ask, p.Permissions.Deny)
}

// MaxLevel is the classification ceiling for the spillage guard.
func (p *Policy) MaxLevel() marking.Level {
	if p.SpillageGuard != nil && !*p.SpillageGuard {
		return marking.Unknown
	}
	return marking.ParseLevel(p.Classification)
}

// SecretAllow compiles secrets.allow (validated at load).
func (p *Policy) SecretAllow() []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, a := range p.Secrets.Allow {
		out = append(out, regexp.MustCompile(a))
	}
	return out
}

func (p *Policy) MayPropose(user string) bool {
	return len(p.Proposers) == 0 || contains(p.Proposers, user)
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// CheckRepo confirms dir is the one repository this policy grants.
func (p *Policy) CheckRepo(repoRoot string) error {
	want, err := filepath.EvalSymlinks(p.RepoRoot)
	if err != nil {
		return fmt.Errorf("policy repo_root %s: %w", p.RepoRoot, err)
	}
	got, _ := filepath.EvalSymlinks(repoRoot)
	if got != want {
		return fmt.Errorf("this policy grants access only to %s; refusing to operate on %s", want, got)
	}
	return nil
}

// Dev returns a development policy for `govcode init`.
func Dev(repoRoot, stateDir, user string) *Policy {
	return &Policy{
		Schema: Schema, Classification: "UNCLASSIFIED//DEVELOPMENT", RepoRoot: repoRoot, StateDir: stateDir,
		TargetBranch: "main", Sensitive: false, TwoPersonRule: false, Approvers: []string{user},
		MaxTurns: 40,
		Model: Model{Backend: "ollama", Endpoint: "http://127.0.0.1:11434", ID: "qwen3-coder-30b-a3b",
			ServedName: "govcode-qwen3-coder:30b-q4km", NumCtx: 32768, MaxTokens: 4096, Temperature: 0.2},
		Tests:    Tests{Command: "make test", TimeoutSeconds: 600, RequirePass: true},
		Commands: Commands{Allowlist: []string{"make", "cmake --build", "gcc", "g++", "cc", "gnatmake", "gprbuild", "cobc", "gfortran", "git status", "git diff", "git log"}, PromptForOthers: true},
		Sandbox:  Sandbox{Mode: "best-effort"},
		Trust:    Trust{Enforce: "warn"},
	}
}

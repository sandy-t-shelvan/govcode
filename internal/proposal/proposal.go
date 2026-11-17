// Package proposal holds the human-approval workflow. The agent never
// writes to a protected branch. Its output is a Proposal: a branch in the
// repository plus a record signed by the proposer that pins the base
// commit, the head commit and the SHA-256 of the diff. A different human
// (two-person rule) approves; only then is a merge commit created on the
// target branch, carrying provenance trailers and an audit anchor.
package proposal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/gitx"
	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

const (
	StatusReady       = "ready"        // finished, tests passed
	StatusTestsFailed = "tests_failed" // agent stopped with failing tests
	StatusIncomplete  = "incomplete"   // agent did not finish
	StatusBlocked     = "blocked"      // spillage or secret found; see Blocked
	StatusApproved    = "approved"
	StatusRejected    = "rejected"
)

type Tests struct {
	Command string `json:"command"`
	Runs    int    `json:"runs"`
	Passed  bool   `json:"passed"`
}

type Proposal struct {
	Schema         string        `json:"schema"`
	ID             string        `json:"id"`
	Created        string        `json:"created"`
	Classification string        `json:"classification"`
	Repo           string        `json:"repo"`
	Task           string        `json:"task"`
	TaskSHA256     string        `json:"task_sha256"`
	Summary        string        `json:"summary"`
	Proposer       identity.User `json:"proposer"`
	ProposerKey    string        `json:"proposer_key_id"`
	Target         string        `json:"target"`
	Branch         string        `json:"branch"`
	Base           string        `json:"base"`
	Head           string        `json:"head"`
	DiffSHA256     string        `json:"diff_sha256"`
	Files          []string      `json:"files"`
	Tests          Tests         `json:"tests"`
	Model          string        `json:"model"`
	ModelDigest    string        `json:"model_digest,omitempty"`
	Status         string        `json:"status"`
	Blocked        []string      `json:"blocked,omitempty"` // reasons, location and kind only
	AuditSession   string        `json:"audit_session"`
	AuditTaskSeq   uint64        `json:"audit_task_seq"`
	AuditTaskHash  string        `json:"audit_task_hash,omitempty"`
	Metrics        any           `json:"metrics,omitempty"`
	// Evidence inputs, recorded at run time and copied into the evidence
	// record when the proposal lands.
	ModelInfo  *ModelInfo `json:"model_info,omitempty"`
	PlanSHA256 string     `json:"plan_sha256,omitempty"`
	Checks     []Check    `json:"checks,omitempty"`
}

// ModelInfo identifies exactly which model produced a change.
type ModelInfo struct {
	ID              string   `json:"id"`
	Name            string   `json:"name,omitempty"`
	Publisher       string   `json:"publisher,omitempty"`
	Origins         []string `json:"origins,omitempty"` // model then lineage
	UpstreamRepo    string   `json:"upstream_repo,omitempty"`
	UpstreamRev     string   `json:"upstream_revision,omitempty"`
	Quantization    string   `json:"quantization,omitempty"`
	ArtifactSHA256  []string `json:"artifact_sha256,omitempty"`
	ServedName      string   `json:"served_name"`
	OllamaDigest    string   `json:"ollama_digest,omitempty"`
	NumCtx          int      `json:"num_ctx"`
	MaxTokens       int      `json:"max_tokens"`
	Temperature     float64  `json:"temperature"`
	Seed            int      `json:"seed,omitempty"`
	OriginException string   `json:"origin_exception,omitempty"`
}

// Check is the result of one gate the change went through.
type Check struct {
	Name   string `json:"name"`
	Result string `json:"result"` // pass | fail | skipped
	Detail string `json:"detail,omitempty"`
}

type Decision struct {
	Schema      string        `json:"schema"`
	Proposal    string        `json:"proposal"`
	Decision    string        `json:"decision"` // approved | rejected
	By          identity.User `json:"by"`
	KeyID       string        `json:"key_id"`
	Time        string        `json:"time"`
	Reason      string        `json:"reason,omitempty"`
	Commit      string        `json:"commit,omitempty"`
	AuditAnchor string        `json:"audit_anchor,omitempty"`
}

type Store struct{ Dir string } // <state>/proposals

func (s Store) dir(id string) string { return filepath.Join(s.Dir, id) }

func NewID() string {
	var b [3]byte
	rand.Read(b[:])
	return "p" + time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

func BranchFor(id string) string { return "govcode/proposal/" + id }

func DiffHash(diff string) string {
	h := sha256.Sum256([]byte(diff))
	return hex.EncodeToString(h[:])
}

// Save writes proposal.json + diff.patch and signs proposal.json.
func (s Store) Save(p *Proposal, diff string, signer sign.Signer) error {
	d := s.dir(p.ID)
	if err := os.MkdirAll(d, 0o2770); err != nil {
		return err
	}
	p.Schema = "govcode.proposal/v1"
	p.ProposerKey = signer.KeyID()
	b, _ := json.MarshalIndent(p, "", "  ")
	if err := os.WriteFile(filepath.Join(d, "proposal.json"), append(b, '\n'), 0o440); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(d, "diff.patch"), []byte(diff), 0o440); err != nil {
		return err
	}
	return sign.SignFile(signer, filepath.Join(d, "proposal.json"))
}

// Load reads a proposal and verifies the proposer's signature using the
// proposer's key from the keyring (ownership-bound to their uid).
func (s Store) Load(id string, kr *keyring.Keyring) (*Proposal, error) {
	if strings.ContainsAny(id, "/\\") || strings.HasPrefix(id, ".") {
		return nil, fmt.Errorf("bad proposal id")
	}
	path := filepath.Join(s.dir(id), "proposal.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("proposal %s: %w", id, err)
	}
	var p Proposal
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	entries := kr.ForUser(p.Proposer.Username)
	if len(entries) == 0 {
		return nil, fmt.Errorf("proposer %s has no key in the keyring", p.Proposer.Username)
	}
	var trusted []keyring.Entry
	for _, e := range entries {
		if e.UID == p.Proposer.UID {
			trusted = append(trusted, e)
		}
	}
	if len(trusted) == 0 {
		return nil, fmt.Errorf("proposer uid %d does not match keyring owner of %s", p.Proposer.UID, p.Proposer.Username)
	}
	ok := false
	for _, e := range trusted {
		if _, _, err := sign.VerifyFileWith(path, e.Pub); err == nil {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("proposal %s: signature does not verify against %s's key (record altered or forged)", id, p.Proposer.Username)
	}
	if d, err := s.Decision(id); err == nil && d != nil {
		p.Status = d.Decision
	}
	return &p, nil
}

func (s Store) Diff(id string) (string, error) {
	b, err := os.ReadFile(filepath.Join(s.dir(id), "diff.patch"))
	return string(b), err
}

func (s Store) Decision(id string) (*Decision, error) {
	b, err := os.ReadFile(filepath.Join(s.dir(id), "decision.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var d Decision
	return &d, json.Unmarshal(b, &d)
}

// recordDecision is exclusive-create: a proposal is decided exactly once.
func (s Store) recordDecision(d *Decision, signer sign.Signer) error {
	d.Schema = "govcode.decision/v1"
	b, _ := json.MarshalIndent(d, "", "  ")
	p := filepath.Join(s.dir(d.Proposal), "decision.json")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("proposal %s has already been decided", d.Proposal)
		}
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return sign.SignFile(signer, p)
}

func (s Store) List() ([]string, error) {
	ents, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "p") {
			ids = append(ids, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids, nil
}

// ---- approval ----

// Rules are the access-control inputs from policy.
type Rules struct {
	TwoPersonRule  bool
	Approvers      []string
	Classification string
}

var ErrSelfApproval = errors.New("two-person rule: the proposer cannot approve their own change")

// CheckApprover enforces who may decide a proposal.
func CheckApprover(r Rules, p *Proposal, approver identity.User) error {
	if r.TwoPersonRule {
		if approver.UID == p.Proposer.UID || approver.Username == p.Proposer.Username {
			return ErrSelfApproval
		}
	}
	if len(r.Approvers) > 0 {
		for _, a := range r.Approvers {
			if a == approver.Username {
				return nil
			}
		}
		return fmt.Errorf("%s is not an approver for this repository (policy approvers: %s)", approver.Username, strings.Join(r.Approvers, ", "))
	}
	return nil
}

// VerifyBranch confirms the branch still points at the proposed head and
// the diff is byte-identical to what the proposer signed. This catches a
// branch force-pushed or amended after the proposal was made.
func VerifyBranch(repo *gitx.Repo, p *Proposal) (string, error) {
	head, err := repo.RevParse("refs/heads/" + p.Branch)
	if err != nil {
		return "", fmt.Errorf("proposal branch %s is missing", p.Branch)
	}
	if head != p.Head {
		return "", fmt.Errorf("proposal branch %s moved: now %s, proposal signed %s", p.Branch, head[:12], p.Head[:12])
	}
	diff, err := repo.Diff(p.Base, p.Head)
	if err != nil {
		return "", err
	}
	if DiffHash(diff) != p.DiffSHA256 {
		return "", fmt.Errorf("diff for %s..%s does not match the signed diff hash", p.Base[:12], p.Head[:12])
	}
	return diff, nil
}

// Anchorer appends the approval to the audit log and returns "<seq>:<hash>".
type Anchorer func(kind string, payload map[string]any) (string, error)

type LandResult struct {
	Commit    string
	TargetWas string
	Anchor    string
	Evidence  string // SHA-256 of the evidence record, if one was made
	FastPath  bool
}

// Evidencer is called after the approval is in the audit log and before
// the merge commit. It writes the evidence record and returns its SHA-256,
// which becomes the Govcode-Evidence trailer. A failure lands nothing.
type Evidencer func(targetTip, anchor string) (string, error)

// Approve lands p on its target branch. Order matters: authorization and
// integrity checks, then the audit entry (so a landed commit always has a
// matching log entry), then the merge commit and an atomic ref update.
func (s Store) Approve(repo *gitx.Repo, r Rules, p *Proposal, approver identity.User, signer sign.Signer, comment string, anchor Anchorer, evidence Evidencer) (*LandResult, error) {
	if p.Status != StatusReady {
		return nil, fmt.Errorf("proposal %s is %s; only ready proposals (agent finished, tests passed) can be approved", p.ID, p.Status)
	}
	if err := CheckApprover(r, p, approver); err != nil {
		return nil, err
	}
	if _, err := VerifyBranch(repo, p); err != nil {
		return nil, err
	}
	tip, err := repo.RevParse("refs/heads/" + p.Target)
	if err != nil {
		return nil, fmt.Errorf("target branch %s: %w", p.Target, err)
	}
	var tree string
	if tip == p.Base {
		tree, err = repo.TreeOf(p.Head)
	} else {
		var conflict bool
		tree, conflict, err = repo.MergeTree(tip, p.Head)
		if err == nil && conflict {
			return nil, fmt.Errorf("%s has moved since the proposal and the change no longer merges cleanly; re-run the task on the new base", p.Target)
		}
	}
	if err != nil {
		return nil, err
	}
	wt := repo.WorktreeFor(p.Target)
	if wt != "" {
		if out, _ := gitx.Git(wt, "status", "--porcelain", "--untracked-files=no"); strings.TrimSpace(out) != "" {
			return nil, fmt.Errorf("%s is checked out at %s with uncommitted changes; commit or stash them first", p.Target, wt)
		}
	}
	anc, err := anchor("approval", map[string]any{
		"proposal": p.ID, "decision": StatusApproved, "proposer": p.Proposer.Username, "approver": approver.Username,
		"base": p.Base, "head": p.Head, "target": p.Target, "target_tip": tip, "diff_sha256": p.DiffSHA256, "comment": comment,
	})
	if err != nil {
		return nil, fmt.Errorf("audit append failed; nothing landed: %w", err)
	}
	var ev string
	if evidence != nil {
		if ev, err = evidence(tip, anc); err != nil {
			return nil, fmt.Errorf("evidence record failed; nothing landed: %w", err)
		}
	}
	msg := commitMessage(p, approver, anc, ev, r.Classification, comment)
	author := gitx.Author{Name: p.Proposer.Username, Email: p.Proposer.Username + "@" + p.Proposer.Host}
	committer := gitx.Author{Name: approver.Username, Email: approver.Username + "@" + approver.Host}
	commit, err := repo.CommitTree(tree, []string{tip, p.Head}, msg, author, committer)
	if err != nil {
		return nil, err
	}
	if wt != "" {
		if _, err := gitx.Git(wt, "merge", "--ff-only", "-q", commit); err != nil {
			return nil, fmt.Errorf("fast-forward of %s at %s failed: %w", p.Target, wt, err)
		}
	} else if err := repo.UpdateRef("refs/heads/"+p.Target, commit, tip, "govcode approve "+p.ID); err != nil {
		return nil, fmt.Errorf("target moved during approval, nothing landed: %w", err)
	}
	if err := s.recordDecision(&Decision{Proposal: p.ID, Decision: StatusApproved, By: approver, KeyID: signer.KeyID(),
		Time: time.Now().UTC().Format(time.RFC3339), Reason: comment, Commit: commit, AuditAnchor: anc}, signer); err != nil {
		return nil, err
	}
	return &LandResult{Commit: commit, TargetWas: tip, Anchor: anc, Evidence: ev, FastPath: tip == p.Base}, nil
}

func (s Store) Reject(r Rules, p *Proposal, by identity.User, signer sign.Signer, reason string, anchor Anchorer) error {
	if p.Status == StatusApproved || p.Status == StatusRejected {
		return fmt.Errorf("proposal %s is already %s", p.ID, p.Status)
	}
	// Anyone allowed to approve may reject; the proposer may withdraw their own.
	if by.UID != p.Proposer.UID {
		if err := CheckApprover(Rules{Approvers: r.Approvers}, p, by); err != nil {
			return err
		}
	}
	anc, err := anchor("rejection", map[string]any{"proposal": p.ID, "decision": StatusRejected, "approver": by.Username, "reason": reason})
	if err != nil {
		return err
	}
	return s.recordDecision(&Decision{Proposal: p.ID, Decision: StatusRejected, By: by, KeyID: signer.KeyID(),
		Time: time.Now().UTC().Format(time.RFC3339), Reason: reason, AuditAnchor: anc}, signer)
}

const (
	TrailerAnchor   = "Govcode-Audit-Anchor"
	TrailerEvidence = "Govcode-Evidence"
)

func commitMessage(p *Proposal, approver identity.User, anchor, evidence, classification, comment string) string {
	title := strings.TrimSpace(strings.SplitN(p.Task, "\n", 2)[0])
	if len(title) > 68 {
		title = title[:68] + "…"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "govcode: %s\n\n", title)
	if p.Summary != "" {
		b.WriteString(strings.TrimSpace(p.Summary) + "\n\n")
	}
	if comment != "" {
		fmt.Fprintf(&b, "Reviewer: %s\n\n", strings.TrimSpace(comment))
	}
	fmt.Fprintf(&b, "Govcode-Proposal: %s\n", p.ID)
	fmt.Fprintf(&b, "Govcode-Proposed-By: %s (uid %d) key %s\n", p.Proposer.Username, p.Proposer.UID, p.ProposerKey)
	fmt.Fprintf(&b, "Govcode-Approved-By: %s (uid %d)\n", approver.Username, approver.UID)
	fmt.Fprintf(&b, "Govcode-Model: %s\n", p.Model)
	fmt.Fprintf(&b, "Govcode-Diff-SHA256: %s\n", p.DiffSHA256)
	fmt.Fprintf(&b, "Govcode-Tests: %s (passed=%v)\n", p.Tests.Command, p.Tests.Passed)
	fmt.Fprintf(&b, "Govcode-Classification: %s\n", classification)
	if evidence != "" {
		fmt.Fprintf(&b, "%s: %s\n", TrailerEvidence, evidence)
	}
	fmt.Fprintf(&b, "%s: %s\n", TrailerAnchor, anchor)
	return b.String()
}

// Anchors scans the history of branches for audit anchors (seq -> hash).
func Anchors(repo *gitx.Repo, branches []string) (map[uint64]string, error) {
	out := map[uint64]string{}
	for _, br := range branches {
		if _, err := repo.RevParse("refs/heads/" + br); err != nil {
			continue
		}
		log, err := repo.Git("log", "--format=%(trailers:key="+TrailerAnchor+",valueonly)", "refs/heads/"+br)
		if err != nil {
			return nil, err
		}
		for _, l := range strings.Split(log, "\n") {
			l = strings.TrimSpace(l)
			seq, hash, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			var n uint64
			if _, err := fmt.Sscan(seq, &n); err == nil && len(hash) == 64 {
				out[n] = hash
			}
		}
	}
	return out, nil
}

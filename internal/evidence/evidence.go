// Package evidence builds the per-change AI evidence record: which model
// produced a landed change, under which settings, what checks it passed,
// who proposed and approved it, and which audit entries cover it.
//
// The record holds hashes and references only, never code, prompts or
// model text, so it can go into an ATO evidence package. It is signed by
// the approver, and its SHA-256 is written into the landed commit as the
// Govcode-Evidence trailer.
package evidence

import (
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

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

const (
	Schema  = "govcode.evidence/v1"
	Trailer = "Govcode-Evidence"
)

type Record struct {
	Schema         string `json:"schema"`
	Proposal       string `json:"proposal"`
	Classification string `json:"classification"`
	Repo           string `json:"repo"`
	Target         string `json:"target"`
	TargetTip      string `json:"target_tip"`
	Base           string `json:"base"`
	Head           string `json:"head"`

	Model proposal.ModelInfo `json:"model"`

	TaskSHA256 string   `json:"task_sha256"`
	PlanSHA256 string   `json:"plan_sha256,omitempty"`
	Files      []string `json:"files"`
	DiffSHA256 string   `json:"diff_sha256"`

	Tests  proposal.Tests   `json:"tests"`
	Checks []proposal.Check `json:"checks"`

	Proposer    Person `json:"proposer"`
	Approver    Person `json:"approver"`
	ProposedAt  string `json:"proposed_at"`
	ApprovedAt  string `json:"approved_at"`
	ReviewNotes bool   `json:"review_comment_present"`

	Audit AuditRange `json:"audit"`
}

type Person struct {
	Username string `json:"username"`
	UID      int    `json:"uid"`
	Host     string `json:"host"`
	KeyID    string `json:"key_id"`
}

// AuditRange is the span of the hash-chained log that covers the change:
// from the task entry to the approval entry (the commit's audit anchor).
type AuditRange struct {
	Session   string `json:"session"`
	FirstSeq  uint64 `json:"first_seq"`
	FirstHash string `json:"first_hash"`
	LastSeq   uint64 `json:"last_seq"`
	LastHash  string `json:"last_hash"`
}

// Build assembles the record for p at approval time. anchor is the approval
// entry's "<seq>:<hash>".
func Build(p *proposal.Proposal, approver identity.User, approverKey, tip, anchor string, comment bool, now time.Time) (*Record, error) {
	seq, hash, err := parseAnchor(anchor)
	if err != nil {
		return nil, err
	}
	if p.ModelInfo == nil {
		return nil, errors.New("proposal has no model information (created by an older govcode); re-run the task")
	}
	checks := append([]proposal.Check(nil), p.Checks...)
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	return &Record{
		Schema: Schema, Proposal: p.ID, Classification: p.Classification, Repo: p.Repo,
		Target: p.Target, TargetTip: tip, Base: p.Base, Head: p.Head,
		Model:      *p.ModelInfo,
		TaskSHA256: p.TaskSHA256, PlanSHA256: p.PlanSHA256, Files: p.Files, DiffSHA256: p.DiffSHA256,
		Tests: p.Tests, Checks: checks,
		Proposer:    Person{p.Proposer.Username, p.Proposer.UID, p.Proposer.Host, p.ProposerKey},
		Approver:    Person{approver.Username, approver.UID, approver.Host, approverKey},
		ProposedAt:  p.Created,
		ApprovedAt:  now.UTC().Format(time.RFC3339),
		ReviewNotes: comment,
		Audit:       AuditRange{Session: p.AuditSession, FirstSeq: p.AuditTaskSeq, FirstHash: p.AuditTaskHash, LastSeq: seq, LastHash: hash},
	}, nil
}

func parseAnchor(a string) (uint64, string, error) {
	s, h, ok := strings.Cut(a, ":")
	var seq uint64
	if _, err := fmt.Sscan(s, &seq); !ok || err != nil || len(h) != 64 {
		return 0, "", fmt.Errorf("bad audit anchor %q", a)
	}
	return seq, h, nil
}

// Store keeps records under <state>/evidence/<proposal>.json with a
// detached approver signature.
type Store struct{ Dir string }

func (s Store) path(id string) string { return filepath.Join(s.Dir, id+".json") }

// Save writes and signs the record and returns its SHA-256 (the trailer
// value). Records are created exclusively: one per proposal.
func (s Store) Save(r *Record, signer sign.Signer) (string, error) {
	if err := os.MkdirAll(s.Dir, 0o2770); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	f, err := os.OpenFile(s.path(r.Proposal), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440)
	if err != nil {
		return "", fmt.Errorf("evidence record: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := sign.SignFile(signer, s.path(r.Proposal)); err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Verified is a record whose signature and binding checks passed.
type Verified struct {
	Record *Record
	SHA256 string
	Signer string
}

// Load reads a record and verifies that the approver named in it signed it
// with their uid-bound key. If wantSHA is set, the file must hash to it.
func (s Store) Load(id string, kr *keyring.Keyring, wantSHA string) (*Verified, error) {
	p := s.path(id)
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if wantSHA != "" && !strings.EqualFold(wantSHA, got) {
		return nil, fmt.Errorf("evidence %s hashes to %s, commit trailer says %s", p, got, wantSHA)
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil || r.Schema != Schema {
		return nil, fmt.Errorf("%s is not a %s record", p, Schema)
	}
	if r.Proposal != id {
		return nil, fmt.Errorf("%s names proposal %s", p, r.Proposal)
	}
	// Only keys the keyring binds to the approver's uid count, so one user
	// cannot sign evidence in another's name.
	var ok bool
	for _, e := range kr.ForUser(r.Approver.Username) {
		if e.UID != r.Approver.UID {
			continue
		}
		if _, kid, err := sign.VerifyFile(p, e.Pub); err == nil && kid == r.Approver.KeyID {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("evidence %s: signature does not verify against approver %s's uid-bound key %s", id, r.Approver.Username, r.Approver.KeyID)
	}
	return &Verified{Record: &r, SHA256: got, Signer: r.Approver.Username}, nil
}

// List returns the proposal ids that have records, sorted.
func (s Store) List() ([]string, error) {
	es, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		if n := e.Name(); strings.HasSuffix(n, ".json") {
			out = append(out, strings.TrimSuffix(n, ".json"))
		}
	}
	sort.Strings(out)
	return out, nil
}

// CheckAudit confirms the audit range the record cites exists in the log
// with the same hashes. hashAt returns the hash of the entry at seq.
func CheckAudit(r *Record, hashAt func(seq uint64) (string, bool)) error {
	for _, e := range []struct {
		seq  uint64
		hash string
	}{{r.Audit.FirstSeq, r.Audit.FirstHash}, {r.Audit.LastSeq, r.Audit.LastHash}} {
		if e.hash == "" {
			return fmt.Errorf("record has no audit hash for seq %d", e.seq)
		}
		h, ok := hashAt(e.seq)
		if !ok {
			return fmt.Errorf("audit entry %d is missing from the log", e.seq)
		}
		if h != e.hash {
			return fmt.Errorf("audit entry %d hash %s, record says %s", e.seq, h, e.hash)
		}
	}
	if r.Audit.LastSeq < r.Audit.FirstSeq {
		return errors.New("audit range is reversed")
	}
	return nil
}

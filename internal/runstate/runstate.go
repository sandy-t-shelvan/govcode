// Package runstate keeps what an interrupted run needs to resume: the
// conversation, the files the agent changed, test and plan state, and the
// checkpoint count. The state file is signed by the proposer and only that
// user (by kernel uid, with their keyring key) can resume it, so nobody else
// with write access to the shared state directory can feed the model text.
//
// The conversation contains code and model output: it is classified at the
// repository's level, like the audit log, and lives in the same state_dir.
package runstate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

const Schema = "govcode.runstate/v1"

const (
	StatusRunning     = "running"
	StatusInterrupted = "interrupted"
	StatusError       = "error"
)

type State struct {
	Schema         string        `json:"schema"`
	ID             string        `json:"id"`
	Classification string        `json:"classification"`
	Proposer       identity.User `json:"proposer"`
	KeyID          string        `json:"key_id"`
	Task           string        `json:"task"`
	TaskSHA256     string        `json:"task_sha256"`
	Base           string        `json:"base"`
	Branch         string        `json:"branch"`
	Worktree       string        `json:"worktree"`
	PlanMode       bool          `json:"plan_mode"`
	PlanSHA256     string        `json:"plan_sha256,omitempty"`
	Plan           []string      `json:"plan,omitempty"`
	Messages       []llm.Message `json:"messages"`
	// CheckpointMsgs[n] is len(Messages) when checkpoint n was taken, so a
	// rewind can trim the conversation back to that point.
	CheckpointMsgs map[int]int `json:"checkpoint_messages"`
	Changed        []string    `json:"changed"`
	EditGen        int         `json:"edit_gen"`
	TestedGen      int         `json:"tested_gen"`
	TestRuns       int         `json:"test_runs"`
	LastTestPass   bool        `json:"last_test_pass"`
	MemoryLoaded   []string    `json:"memory_loaded"`
	MemoryBudget   int         `json:"memory_budget"`
	AuditTaskSeq   uint64      `json:"audit_task_seq"`
	AuditTaskHash  string      `json:"audit_task_hash"`
	ModelID        string      `json:"model_id"`
	Status         string      `json:"status"`
	Error          string      `json:"error,omitempty"`
	Updated        string      `json:"updated"`
}

type Store struct{ Dir string } // <state>/runs

func (s Store) path(id string) string { return filepath.Join(s.Dir, id, "state.json") }

func validID(id string) error {
	if id == "" || strings.ContainsAny(id, "/\\") || strings.HasPrefix(id, ".") {
		return fmt.Errorf("bad proposal id %q", id)
	}
	return nil
}

// Save writes the state atomically and signs it.
func (s Store) Save(st *State, signer sign.Signer) error {
	if err := validID(st.ID); err != nil {
		return err
	}
	st.Schema, st.KeyID, st.Updated = Schema, signer.KeyID(), time.Now().UTC().Format(time.RFC3339)
	d := filepath.Dir(s.path(st.ID))
	if err := os.MkdirAll(d, 0o2770); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(d, ".state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Chmod(0o660)
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), s.path(st.ID)); err != nil {
		return err
	}
	return sign.SignFile(signer, s.path(st.ID))
}

// Load reads the state and checks that user is its proposer and that the
// proposer's uid-bound key signed it.
func (s Store) Load(id string, kr *keyring.Keyring, user identity.User) (*State, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(s.path(id))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no resumable run %s (it finished, or was never interrupted)", id)
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil || st.Schema != Schema || st.ID != id {
		return nil, fmt.Errorf("%s is not a valid run state", s.path(id))
	}
	if st.Proposer.UID != user.UID {
		return nil, fmt.Errorf("run %s belongs to %s (uid %d); only its proposer can resume or rewind it", id, st.Proposer.Username, st.Proposer.UID)
	}
	ok := false
	for _, e := range kr.ForUser(st.Proposer.Username) {
		if e.UID != st.Proposer.UID {
			continue
		}
		if _, _, err := sign.VerifyFile(s.path(id), e.Pub); err == nil {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("run state %s: signature does not verify against %s's key (altered or forged)", id, st.Proposer.Username)
	}
	return &st, nil
}

// Delete removes the run state once the run has produced a proposal.
func (s Store) Delete(id string) error {
	if err := validID(id); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Dir(s.path(id)))
}

// Summary is one resumable run, for listing.
type Summary struct {
	ID, Status, Proposer, Updated, Task, Error string
	Checkpoints                                int
}

// List returns resumable runs (unverified; Load verifies).
func (s Store) List() ([]Summary, error) {
	es, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Summary
	for _, e := range es {
		raw, err := os.ReadFile(filepath.Join(s.Dir, e.Name(), "state.json"))
		if err != nil {
			continue
		}
		var st State
		if json.Unmarshal(raw, &st) != nil {
			continue
		}
		out = append(out, Summary{ID: st.ID, Status: st.Status, Proposer: st.Proposer.Username, Updated: st.Updated,
			Task: st.Task, Error: st.Error, Checkpoints: len(st.CheckpointMsgs)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Lock takes an exclusive, non-blocking lock on a run so that a resume or
// rewind cannot race with a run that is still in progress. The lock is
// released by the returned function or when the process exits.
func (s Store) Lock(id string) (func(), error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	d := filepath.Dir(s.path(id))
	if err := os.MkdirAll(d, 0o2770); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(d, "lock"), os.O_CREATE|os.O_RDWR, 0o660)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("run %s is in use by another govcode process", id)
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// DiscardIfEmpty removes the run directory if no state was ever saved (a
// run refused before it started).
func (s Store) DiscardIfEmpty(id string) {
	if validID(id) != nil {
		return
	}
	if _, err := os.Stat(s.path(id)); os.IsNotExist(err) {
		os.RemoveAll(filepath.Dir(s.path(id)))
	}
}

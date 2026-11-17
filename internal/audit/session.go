package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

// Session binds a log to one actor and one govcode invocation. It
// implements agent.Recorder: each payload is stored as an object and a
// small summary goes in the entry.
type Session struct {
	Log    *Log
	Signer sign.Signer
	Actor  identity.User
	ID     string
	mu     sync.Mutex
	Err    error // first append failure; callers must stop on it
	// OnRecord, if set, is called after each entry is appended (SIEM export).
	OnRecord func(*Entry)
}

func (s *Session) Record(kind string, payload any) error {
	_, err := s.RecordEntry(kind, payload)
	return err
}

func (s *Session) RecordEntry(kind string, payload any) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Err != nil {
		return nil, s.Err
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	objs := map[string]string{}
	if len(b) > 0 && string(b) != "null" {
		id, err := s.Log.PutObject(b)
		if err != nil {
			s.Err = fmt.Errorf("audit object write failed: %w", err)
			return nil, s.Err
		}
		objs["payload"] = id
	}
	e, err := s.Log.Append(s.Signer, s.Actor, s.ID, kind, summarize(kind, payload), objs)
	if err != nil {
		s.Err = fmt.Errorf("audit append failed: %w", err)
		return nil, s.Err
	}
	if s.OnRecord != nil {
		s.OnRecord(e)
	}
	return e, nil
}

// summarize keeps short, non-content fields readable in the log line
// itself (tool names, paths, exit codes) so `audit show` is useful without
// opening objects.
func summarize(kind string, payload any) map[string]any {
	m, ok := toMap(payload)
	if !ok {
		return nil
	}
	out := map[string]any{}
	for _, k := range []string{"turn", "tool", "call_id", "model", "proposal", "decision", "base", "head", "branch", "target", "commit", "reason", "finish_reason", "exit_code", "status", "task_sha256", "diff_sha256", "files", "approver", "proposer", "where", "level", "repository_level", "kind", "file", "line", "rule", "subject", "stage", "passed"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	if a, ok := m["args"].(map[string]any); ok {
		for _, k := range []string{"path", "command", "pattern"} {
			if v, ok := a[k]; ok {
				out[k] = trunc(fmt.Sprint(v), 200)
			}
		}
	}
	if tc, ok := m["tool_calls"].([]any); ok {
		var names []string
		for _, c := range tc {
			if cm, ok := c.(map[string]any); ok {
				names = append(names, fmt.Sprint(cm["name"]))
			}
		}
		out["tool_calls"] = strings.Join(names, ",")
	}
	if e, ok := m["error"]; ok {
		out["error"] = trunc(fmt.Sprint(e), 200)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func toMap(v any) (map[string]any, bool) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil, false
	}
	return m, true
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

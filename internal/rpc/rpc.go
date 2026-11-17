// Package rpc serves govcode to editors over stdin/stdout.
//
// Wire format: newline-delimited JSON-RPC 2.0. No sockets, no ports: the
// editor starts `govcode serve --stdio` as the invoking user and owns the
// pipes. All policy, sandboxing, signing and audit stay in this process;
// the editor is an untrusted UI.
//
// Client -> server requests: initialize, run, cancel, proposals.list,
// proposals.get, proposals.reject, audit.verify.
// Server -> client notifications: event, run.finished.
// Server -> client requests (the client must answer): permission.request,
// plan.review.
//
// There is deliberately no approve method. Approval requires a typed
// confirmation on a real terminal (`govcode approve <id>`), which the
// editor opens for the human; the two-person rule and every integrity
// check run there.
package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/app"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/supply"
)

const maxMessage = 16 << 20

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	codeParse     = -32700
	codeInvalid   = -32600
	codeNoMethod  = -32601
	codeParams    = -32602
	codeInternal  = -32603
	codeNotReady  = -32001
	codeBusy      = -32002
	codeForbidden = -32003
)

type Server struct {
	PolicyPath string
	// NewBackend overrides the model client (tests).
	NewBackend func() (llm.Backend, error)
	// PermissionTimeout bounds how long a permission prompt waits for the
	// human before it is treated as a denial.
	PermissionTimeout time.Duration

	in  *bufio.Reader
	out io.Writer
	wmu sync.Mutex

	app     *app.App
	checks  []app.Check
	openErr error

	runMu     sync.Mutex
	runCancel context.CancelFunc

	nextID  atomic.Int64
	pending sync.Map // server request id -> chan message
}

func (s *Server) send(m message) error {
	m.JSONRPC = "2.0"
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err = s.out.Write(append(b, '\n'))
	return err
}

func (s *Server) notify(method string, params any) {
	b, _ := json.Marshal(params)
	s.send(message{Method: method, Params: b})
}

func (s *Server) reply(id json.RawMessage, result any, err error) {
	if err != nil {
		code := codeInternal
		var re *rpcError
		if errors.As(err, &re) {
			code = re.Code
		}
		s.send(message{ID: id, Error: &rpcError{Code: code, Message: err.Error()}})
		return
	}
	b, _ := json.Marshal(result)
	s.send(message{ID: id, Result: b})
}

func (e *rpcError) Error() string { return e.Message }

func fail(code int, format string, a ...any) error {
	return &rpcError{Code: code, Message: fmt.Sprintf(format, a...)}
}

// request sends a server->client request and waits for the response.
func (s *Server) request(ctx context.Context, method string, params any, timeout time.Duration) (json.RawMessage, error) {
	id := fmt.Sprintf(`"s-%d"`, s.nextID.Add(1))
	ch := make(chan message, 1)
	s.pending.Store(id, ch)
	defer s.pending.Delete(id)
	b, _ := json.Marshal(params)
	if err := s.send(message{ID: json.RawMessage(id), Method: method, Params: b}); err != nil {
		return nil, err
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case m := <-ch:
		if m.Error != nil {
			return nil, errors.New(m.Error.Message)
		}
		return m.Result, nil
	case <-t.C:
		return nil, fmt.Errorf("%s: no answer within %s", method, timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Serve reads requests until in is closed.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.in = bufio.NewReaderSize(in, 64<<10)
	s.out = out
	if s.PermissionTimeout == 0 {
		s.PermissionTimeout = 10 * time.Minute
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	// Read in a goroutine so a cancelled context (SIGTERM from the editor
	// closing) stops the server even while it is waiting for input.
	type readResult struct {
		line []byte
		err  error
	}
	lines := make(chan readResult)
	go func() {
		for {
			line, err := s.in.ReadBytes('\n')
			select {
			case lines <- readResult{line, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		var rr readResult
		select {
		case <-ctx.Done():
			s.cancelRun()
			return nil
		case rr = <-lines:
		}
		line, err := rr.line, rr.err
		if len(line) > maxMessage {
			s.send(message{Error: &rpcError{Code: codeInvalid, Message: "message too large"}})
			continue
		}
		if len(strings.TrimSpace(string(line))) > 0 {
			var m message
			if jerr := json.Unmarshal(line, &m); jerr != nil {
				s.send(message{Error: &rpcError{Code: codeParse, Message: "parse error"}})
			} else if m.Method == "" && m.ID != nil {
				// response to a server->client request
				if ch, ok := s.pending.Load(string(m.ID)); ok {
					ch.(chan message) <- m
				}
			} else if m.Method != "" {
				if m.Method == "run" {
					// long-running: handled asynchronously so the reader keeps
					// receiving permission answers and cancel requests.
					wg.Add(1)
					go func() { defer wg.Done(); s.dispatch(ctx, m) }()
				} else {
					s.dispatch(ctx, m)
				}
			}
		}
		if err != nil {
			s.cancelRun()
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (s *Server) dispatch(ctx context.Context, m message) {
	var res any
	var err error
	switch m.Method {
	case "initialize":
		res, err = s.initialize()
	case "run":
		res, err = s.run(ctx, m.Params)
	case "cancel":
		res, err = map[string]bool{"cancelled": s.cancelRun()}, nil
	case "proposals.list":
		res, err = s.list()
	case "proposals.get":
		res, err = s.get(m.Params)
	case "proposals.reject":
		res, err = s.reject(m.Params)
	case "audit.verify":
		res, err = s.verify()
	default:
		err = fail(codeNoMethod, "unknown method %q", m.Method)
	}
	if m.ID != nil {
		s.reply(m.ID, res, err)
	}
}

func (s *Server) ready() (*app.App, error) {
	if s.app == nil {
		if s.openErr != nil {
			return nil, fail(codeNotReady, "govcode is not ready: %v", s.openErr)
		}
		return nil, fail(codeNotReady, "call initialize first")
	}
	return s.app, nil
}

type initResult struct {
	Version        string      `json:"version"`
	Ready          bool        `json:"ready"`
	Error          string      `json:"error,omitempty"`
	Classification string      `json:"classification,omitempty"`
	User           string      `json:"user,omitempty"`
	Repo           string      `json:"repo,omitempty"`
	TwoPersonRule  bool        `json:"two_person_rule"`
	PlanRequired   bool        `json:"plan_required"`
	Checks         []app.Check `json:"checks"`
}

func (s *Server) initialize() (any, error) {
	a, checks, err := app.Open(s.PolicyPath, io.Discard, true)
	s.checks = checks
	r := initResult{Version: supply.Version, Checks: checks}
	if err != nil {
		s.openErr = err
		r.Error = err.Error()
		return r, nil
	}
	s.app = a
	r.Ready = true
	r.Classification = a.Policy.Classification
	r.User = a.User.String()
	r.Repo = a.Repo.Root
	r.TwoPersonRule = a.Policy.TwoPersonRule
	r.PlanRequired = a.Policy.RequirePlanApproval
	return r, nil
}

func (s *Server) cancelRun() bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.runCancel != nil {
		s.runCancel()
		return true
	}
	return false
}

type runParams struct {
	Task string `json:"task"`
	Plan bool   `json:"plan"`
}

// eventWriter turns the agent's text output into "event" notifications.
type eventWriter struct{ s *Server }

func (w eventWriter) Write(p []byte) (int, error) {
	w.s.notify("event", map[string]any{"kind": "log", "text": string(p)})
	return len(p), nil
}

type rpcApprover struct {
	s   *Server
	ctx context.Context
}

func (r rpcApprover) Approve(action string) (bool, string) {
	res, err := r.s.request(r.ctx, "permission.request", map[string]string{"action": action}, r.s.PermissionTimeout)
	if err != nil {
		return false, "editor (" + err.Error() + ")"
	}
	var ans struct {
		Allow bool `json:"allow"`
	}
	json.Unmarshal(res, &ans)
	return ans.Allow, "editor user"
}

type rpcPlanReviewer struct {
	s   *Server
	ctx context.Context
}

func (r rpcPlanReviewer) ReviewPlan(steps []string, summary string) (bool, string) {
	res, err := r.s.request(r.ctx, "plan.review", map[string]any{"steps": steps, "summary": summary}, r.s.PermissionTimeout)
	if err != nil {
		return false, "no decision: " + err.Error()
	}
	var ans struct {
		Approved bool   `json:"approved"`
		Feedback string `json:"feedback"`
	}
	json.Unmarshal(res, &ans)
	return ans.Approved, ans.Feedback
}

func (s *Server) run(ctx context.Context, raw json.RawMessage) (any, error) {
	a, err := s.ready()
	if err != nil {
		return nil, err
	}
	var p runParams
	if err := json.Unmarshal(raw, &p); err != nil || strings.TrimSpace(p.Task) == "" {
		return nil, fail(codeParams, "run needs {\"task\": \"...\"}")
	}
	s.runMu.Lock()
	if s.runCancel != nil {
		s.runMu.Unlock()
		return nil, fail(codeBusy, "a run is already in progress")
	}
	rctx, cancel := context.WithCancel(ctx)
	s.runCancel = cancel
	s.runMu.Unlock()
	defer func() {
		s.runMu.Lock()
		s.runCancel = nil
		s.runMu.Unlock()
		cancel()
	}()
	opts := app.RunOptions{Task: p.Task, Plan: p.Plan, Interactive: true,
		Approver: rpcApprover{s, rctx}, PlanReviewer: rpcPlanReviewer{s, rctx},
		OnEvent: func(kind string, data any) { s.notify("event", map[string]any{"kind": kind, "data": data}) }}
	if s.NewBackend != nil {
		b, err := s.NewBackend()
		if err != nil {
			return nil, err
		}
		opts.Backend = b
	}
	a.Out = eventWriter{s}
	prop, runErr := a.Run(rctx, opts)
	fin := map[string]any{"proposal": prop}
	if runErr != nil {
		fin["error"] = runErr.Error()
	}
	s.notify("run.finished", fin)
	if prop == nil && runErr != nil {
		return nil, runErr
	}
	return map[string]any{"proposal": prop}, nil
}

type summary struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Proposer string   `json:"proposer"`
	Task     string   `json:"task"`
	Files    []string `json:"files"`
	Created  string   `json:"created"`
	Error    string   `json:"error,omitempty"`
}

func (s *Server) list() (any, error) {
	a, err := s.ready()
	if err != nil {
		return nil, err
	}
	ids, err := a.Store.List()
	if err != nil {
		return nil, err
	}
	out := []summary{}
	for _, id := range ids {
		p, err := a.Store.Load(id, a.Keyring)
		if err != nil {
			out = append(out, summary{ID: id, Status: "invalid", Error: err.Error()})
			continue
		}
		out = append(out, summary{ID: p.ID, Status: p.Status, Proposer: p.Proposer.Username, Task: p.Task, Files: p.Files, Created: p.Created})
	}
	return out, nil
}

type idParams struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

func (s *Server) get(raw json.RawMessage) (any, error) {
	a, err := s.ready()
	if err != nil {
		return nil, err
	}
	var p idParams
	if json.Unmarshal(raw, &p) != nil || p.ID == "" {
		return nil, fail(codeParams, "need {\"id\"}")
	}
	prop, err := a.Store.Load(p.ID, a.Keyring)
	if err != nil {
		return nil, err
	}
	res := map[string]any{"proposal": prop}
	if diff, verr := proposal.VerifyBranch(a.Repo, prop); verr != nil {
		res["integrity"] = "FAILED: " + verr.Error()
	} else {
		res["integrity"] = "ok"
		res["diff"] = diff
	}
	if d, _ := a.Store.Decision(p.ID); d != nil {
		res["decision"] = d
	}
	return res, nil
}

func (s *Server) reject(raw json.RawMessage) (any, error) {
	a, err := s.ready()
	if err != nil {
		return nil, err
	}
	var p idParams
	if json.Unmarshal(raw, &p) != nil || p.ID == "" || strings.TrimSpace(p.Reason) == "" {
		return nil, fail(codeParams, "need {\"id\", \"reason\"}")
	}
	prop, err := a.Store.Load(p.ID, a.Keyring)
	if err != nil {
		return nil, err
	}
	sess := a.Session(prop.ID)
	err = a.Store.Reject(proposal.Rules{Approvers: a.Policy.Approvers}, prop, a.User, a.Signer, p.Reason, func(kind string, payload map[string]any) (string, error) {
		e, err := sess.RecordEntry(kind, payload)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d:%s", e.Seq, e.Hash), nil
	})
	if err != nil {
		return nil, fail(codeForbidden, "%v", err)
	}
	return map[string]any{"rejected": p.ID}, nil
}

func (s *Server) verify() (any, error) {
	a, err := s.ready()
	if err != nil {
		return nil, err
	}
	anchors, err := proposal.Anchors(a.Repo, []string{a.Policy.TargetBranch})
	if err != nil {
		return nil, err
	}
	r, err := a.Log.Verify(a.Keyring, anchors, true)
	if err != nil {
		return nil, err
	}
	head := ""
	if r.Head != nil {
		head = fmt.Sprintf("#%d %s", r.Head.Seq, r.Head.Hash)
	}
	return map[string]any{"ok": r.OK(), "entries": r.Entries, "anchors": r.Anchors, "actors": r.Actors, "head": head, "problems": r.Problems}, nil
}

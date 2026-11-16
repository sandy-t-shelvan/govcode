package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/policy"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

// client is a minimal editor: it sends requests, collects notifications,
// and answers server->client requests with canned decisions.
type client struct {
	t       *testing.T
	w       io.Writer
	r       *bufio.Scanner
	next    int
	notes   []message
	asked   []string
	allow   bool
	approve bool
}

func (c *client) call(method string, params any) message {
	c.t.Helper()
	c.next++
	p, _ := json.Marshal(params)
	id := json.RawMessage(strings.TrimSpace(string(mustJSON(c.next))))
	b, _ := json.Marshal(message{JSONRPC: "2.0", ID: id, Method: method, Params: p})
	c.w.Write(append(b, '\n'))
	for c.r.Scan() {
		var m message
		if err := json.Unmarshal(c.r.Bytes(), &m); err != nil {
			c.t.Fatalf("bad line from server: %q", c.r.Text())
		}
		switch {
		case m.Method != "" && m.ID != nil: // server->client request
			c.asked = append(c.asked, m.Method)
			var res any = map[string]bool{"allow": c.allow}
			if m.Method == "plan.review" {
				res = map[string]any{"approved": c.approve, "feedback": "ok"}
			}
			rb, _ := json.Marshal(res)
			ans, _ := json.Marshal(message{JSONRPC: "2.0", ID: m.ID, Result: rb})
			c.w.Write(append(ans, '\n'))
		case m.Method != "":
			c.notes = append(c.notes, m)
		case string(m.ID) == string(id):
			return m
		}
	}
	c.t.Fatalf("server closed before answering %s", method)
	return message{}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func setup(t *testing.T, backend *llm.Scripted) (*client, func()) {
	t.Helper()
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	os.MkdirAll(repo, 0o755)
	os.WriteFile(filepath.Join(repo, "cfg.c"), []byte("int port = 1;\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "Makefile"), []byte("test:\n\t@true\n"), 0o644)
	for _, a := range [][]string{{"init", "-q", "-b", "main"}, {"add", "-A"}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base"}} {
		exec.Command("git", append([]string{"-C", repo}, a...)...).Run()
	}
	u, _ := identity.Current()
	p := policy.Dev(repo, filepath.Join(base, "state"), u.Username)
	p.Classification = "SECRET//NOFORN"
	p.Tests.Command = "make -s test"
	b, _ := json.Marshal(p)
	pol := filepath.Join(base, "policy.json")
	os.WriteFile(pol, b, 0o644)
	key := filepath.Join(base, "me.key")
	pub, _ := sign.GenerateKeyFiles(strings.TrimSuffix(key, ".key"))
	keyring.Register(filepath.Join(base, "state", "keys"), u, pub)
	t.Setenv("GOVCODE_KEY", key)
	wd, _ := os.Getwd()
	os.Chdir(repo)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &Server{PolicyPath: pol, PermissionTimeout: 5 * time.Second,
		NewBackend: func() (llm.Backend, error) { return backend, nil }}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), inR, outW); outW.Close() }()
	sc := bufio.NewScanner(outR)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	c := &client{t: t, w: inW, r: sc}
	return c, func() {
		inW.Close()
		<-done
		os.Chdir(wd)
	}
}

func tc(name string, args any) llm.ToolCall {
	b, _ := json.Marshal(args)
	return llm.ToolCall{Name: name, Args: b, Source: llm.SourceNative}
}

func TestEditorSession(t *testing.T) {
	model := &llm.Scripted{Responses: []llm.Response{
		{ToolCalls: []llm.ToolCall{tc("propose_plan", map[string]any{"steps": []string{"set port"}, "summary": "s"})}},
		{ToolCalls: []llm.ToolCall{tc("run_command", map[string]any{"command": "git log -1"})}}, // not allowlisted in dev policy? -> ask
		{ToolCalls: []llm.ToolCall{tc("edit_file", map[string]any{"path": "cfg.c", "old_text": "int port = 1;", "new_text": "int port = 2;"})}},
		{ToolCalls: []llm.ToolCall{tc("run_tests", map[string]any{})}},
		{ToolCalls: []llm.ToolCall{tc("finish", map[string]any{"summary": "port 2"})}},
	}}
	c, stop := setup(t, model)
	defer stop()
	c.allow, c.approve = true, true

	init := c.call("initialize", nil)
	var ir initResult
	json.Unmarshal(init.Result, &ir)
	if !ir.Ready || ir.Classification != "SECRET//NOFORN" {
		t.Fatalf("initialize: %s %+v", init.Result, init.Error)
	}

	res := c.call("run", map[string]any{"task": "set port to 2", "plan": true})
	if res.Error != nil {
		t.Fatalf("run: %+v", res.Error)
	}
	var rr struct {
		Proposal struct{ ID, Status string } `json:"proposal"`
	}
	json.Unmarshal(res.Result, &rr)
	if rr.Proposal.Status != "ready" {
		t.Fatalf("proposal %s", res.Result)
	}
	if strings.Join(c.asked, ",") != "plan.review" && !strings.Contains(strings.Join(c.asked, ","), "plan.review") {
		t.Fatalf("server->client requests %v", c.asked)
	}
	kinds := map[string]int{}
	for _, n := range c.notes {
		kinds[n.Method]++
	}
	if kinds["event"] == 0 || kinds["run.finished"] != 1 {
		t.Fatalf("notifications %v", kinds)
	}

	list := c.call("proposals.list", nil)
	if !strings.Contains(string(list.Result), rr.Proposal.ID) {
		t.Fatalf("list %s", list.Result)
	}
	get := c.call("proposals.get", map[string]string{"id": rr.Proposal.ID})
	if !strings.Contains(string(get.Result), `"integrity":"ok"`) || !strings.Contains(string(get.Result), "+int port = 2;") {
		t.Fatalf("get %s", get.Result)
	}
	v := c.call("audit.verify", nil)
	if !strings.Contains(string(v.Result), `"ok":true`) {
		t.Fatalf("verify %s", v.Result)
	}
	if r := c.call("approve", map[string]string{"id": rr.Proposal.ID}); r.Error == nil || r.Error.Code != codeNoMethod {
		t.Fatalf("approve must not exist over RPC: %+v", r)
	}
	if r := c.call("proposals.reject", map[string]string{"id": rr.Proposal.ID, "reason": "testing"}); r.Error != nil {
		t.Fatalf("reject: %+v", r.Error)
	}
}

func TestPermissionDeniedByEditor(t *testing.T) {
	model := &llm.Scripted{Responses: []llm.Response{
		{ToolCalls: []llm.ToolCall{tc("run_command", map[string]any{"command": "curl http://example.com"})}},
		{Content: "giving up"}, {Content: "."}, {Content: "."}, {Content: "."},
	}}
	c, stop := setup(t, model)
	defer stop()
	c.allow = false
	c.call("initialize", nil)
	c.call("run", map[string]any{"task": "fetch something"})
	if len(c.asked) != 1 || c.asked[0] != "permission.request" {
		t.Fatalf("asked %v", c.asked)
	}
	denied := false
	for _, n := range c.notes {
		if n.Method == "event" && strings.Contains(string(n.Params), `"decision":"deny"`) {
			denied = true
		}
	}
	if !denied {
		t.Fatal("deny decision not streamed to the editor")
	}
}

func TestProtocolErrors(t *testing.T) {
	c, stop := setup(t, &llm.Scripted{})
	defer stop()
	if r := c.call("proposals.list", nil); r.Error == nil || r.Error.Code != codeNotReady {
		t.Fatalf("list before initialize: %+v", r)
	}
	c.call("initialize", nil)
	if r := c.call("run", map[string]any{"task": ""}); r.Error == nil || r.Error.Code != codeParams {
		t.Fatalf("empty task: %+v", r)
	}
	if r := c.call("nope", nil); r.Error == nil || r.Error.Code != codeNoMethod {
		t.Fatalf("unknown method: %+v", r)
	}
	c.w.Write([]byte("{not json\n"))
	if !c.r.Scan() || !strings.Contains(c.r.Text(), "parse error") {
		t.Fatalf("garbage input: %q", c.r.Text())
	}
}

func FuzzServeInput(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n"))
	f.Add([]byte("{}\n[]\nnull\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		s := &Server{PolicyPath: "/nonexistent/policy.json"}
		var out strings.Builder
		s.Serve(context.Background(), strings.NewReader(string(in)), &out)
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			if line != "" && !json.Valid([]byte(line)) {
				t.Fatalf("server wrote invalid JSON %q", line)
			}
		}
	})
}

package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/marking"
	"github.com/sandy-t-shelvan/govcode/internal/permissions"
)

type approveAll struct{ asked []string }

func (a *approveAll) Approve(s string) (bool, string) {
	a.asked = append(a.asked, s)
	return true, "reviewer"
}

// collect captures events; call the returned func to close and drain.
func collect(e *Env) func() []Event {
	ch := make(chan Event, 256)
	e.Events = ch
	var evs []Event
	done := make(chan struct{})
	go func() {
		for ev := range ch {
			evs = append(evs, ev)
		}
		close(done)
	}()
	return func() []Event { close(ch); <-done; return evs }
}

func TestDenyRulesHidePaths(t *testing.T) {
	e := repo(t, map[string]string{"keys/prod.key": "k", "src/a.c": "int key_len;\n", "src/b.c": "int key_len;\n"})
	e.Perms, _ = permissions.Parse(nil, nil, []string{"read_file(keys/**)", "read_file(src/b.c)"})
	s := NewSet(e)
	if _, err := call(t, s, "read_file", map[string]any{"path": "keys/prod.key"}); err == nil || !strings.Contains(err.Error(), "denied by policy") {
		t.Fatalf("read of denied path: %v", err)
	}
	out, _ := call(t, s, "list_files", map[string]any{})
	if strings.Contains(out, "keys/") || strings.Contains(out, "src/b.c") || !strings.Contains(out, "src/a.c") {
		t.Errorf("list_files leaked denied paths:\n%s", out)
	}
	out, _ = call(t, s, "search", map[string]any{"pattern": "key"})
	if strings.Contains(out, "src/b.c") || strings.Contains(out, "keys/") || !strings.Contains(out, "src/a.c") {
		t.Errorf("search leaked denied paths:\n%s", out)
	}
	if _, err := call(t, s, "outline", map[string]any{"path": "src/b.c"}); err != nil {
		t.Logf("outline denied only by explicit outline rule; got %v", err)
	}
}

func TestAskRuleUsesApprover(t *testing.T) {
	e := repo(t, map[string]string{"crypto/aes.c": "int r = 10;\n"})
	e.Perms, _ = permissions.Parse(nil, []string{"edit_file(crypto/**)"}, nil)
	ap := &approveAll{}
	e.Approver = ap
	if _, err := call(t, NewSet(e), "edit_file", map[string]any{"path": "crypto/aes.c", "old_text": "10", "new_text": "14"}); err != nil {
		t.Fatal(err)
	}
	if len(ap.asked) != 1 || ap.asked[0] != "edit_file(crypto/aes.c)" {
		t.Fatalf("approver asked %v", ap.asked)
	}
	e.Approver = nil // ask with no human attached must deny
	if _, err := call(t, NewSet(e), "edit_file", map[string]any{"path": "crypto/aes.c", "old_text": "14", "new_text": "10"}); err == nil {
		t.Fatal("ask rule with no approver allowed the edit")
	}
}

const tsDoc = "/* TOP SECRET//SI//NOFORN */\nint mode = 3;\n"

func TestSpillageWithheldFromModel(t *testing.T) {
	e := repo(t, map[string]string{"ts.c": tsDoc, "ok.c": "// (S//NF) radar\nint mode = 3;\n", "Makefile": "test:\n\t@cat ts.c\n"})
	e.MaxLevel = marking.S
	e.TestCommand = "make -s test"
	evs := collect(e)
	s := NewSet(e)

	out, err := call(t, s, "read_file", map[string]any{"path": "ts.c"})
	if err != nil || strings.Contains(out, "mode") || !strings.Contains(out, "withheld") {
		t.Fatalf("TS file reached the model: %v %q", err, out)
	}
	if out, _ := call(t, s, "read_file", map[string]any{"path": "ok.c"}); !strings.Contains(out, "int mode") {
		t.Fatalf("SECRET file in SECRET repo was withheld: %q", out)
	}
	out, _ = call(t, s, "search", map[string]any{"pattern": "TOP SECRET|mode"})
	if strings.Contains(out, "TOP SECRET") || !strings.Contains(out, "withheld") || !strings.Contains(out, "ok.c") {
		t.Fatalf("search spillage handling wrong:\n%s", out)
	}
	if out, _ := call(t, s, "run_tests", nil); strings.Contains(out, "int mode") {
		t.Fatalf("command output spilled: %q", out)
	}
	if _, err := call(t, s, "create_file", map[string]any{"path": "new.c", "content": "(TS) leaked paragraph\n"}); err == nil {
		t.Fatal("model wrote a TS marking into a SECRET repo")
	}
	if _, err := call(t, s, "edit_file", map[string]any{"path": "ok.c", "old_text": "int mode = 3;", "new_text": "// TOP SECRET//SI\nint mode = 3;"}); err == nil {
		t.Fatal("edit introduced TS marking")
	}
	n := 0
	for _, ev := range evs() {
		if ev.Kind == "spillage_blocked" {
			n++
			b, _ := json.Marshal(ev.Data)
			if strings.Contains(string(b), "mode") || strings.Contains(string(b), "SI//NOFORN") {
				t.Errorf("spillage event carries content: %s", b)
			}
		}
	}
	if n < 5 {
		t.Errorf("expected >= 5 spillage events, got %d", n)
	}
}

// git grep -n prefixes every hit with "path:lineno:". Portion marks and
// banner lines are recognised only at the start of a line, so the guard
// has to see the file text, not the lineno prefix. Otherwise a search
// hands the model markings that read_file would withhold.
func TestSearchSpillageIgnoresLineNumberPrefix(t *testing.T) {
	e := repo(t, map[string]string{
		"banner.txt":  "TOP SECRET\n",
		"portion.txt": "(TS) payload coordinates\n// (S) allowed in this repo\n",
	})
	e.MaxLevel = marking.S
	out, err := call(t, NewSet(e), "search", map[string]any{"pattern": "SECRET|payload|allowed"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "TOP SECRET") || strings.Contains(out, "payload") {
		t.Fatalf("search leaked markings above the repository level:\n%s", out)
	}
	if !strings.Contains(out, "withheld") || !strings.Contains(out, "allowed") {
		t.Fatalf("search dropped a permitted line or the withhold notice:\n%s", out)
	}
}

func TestPermissionDecisionsAudited(t *testing.T) {
	e := repo(t, map[string]string{"a": "x"})
	e.Allowlist = []string{"make"}
	evs := collect(e)
	call(t, NewSet(e), "run_command", map[string]any{"command": "make --version"})
	call(t, NewSet(e), "run_command", map[string]any{"command": "curl http://x"})
	var got []string
	for _, ev := range evs() {
		if ev.Kind == "permission" {
			m := ev.Data.(map[string]any)
			got = append(got, m["decision"].(string)+":"+m["rule"].(string))
		}
	}
	if len(got) != 2 || !strings.HasPrefix(got[0], "allow:run_command(make *)") || !strings.HasPrefix(got[1], "deny:default") {
		t.Fatalf("permission events %v", got)
	}
}

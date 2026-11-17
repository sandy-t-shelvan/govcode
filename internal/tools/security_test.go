package tools

import (
	"encoding/json"
	"fmt"
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

// A broad search on a large repository is capped: the shown lines stop at
// maxSearchResults, the rest are counted, and matches in denied paths are
// neither shown nor counted (the count must not reveal what is hidden).
func TestSearchCapsAndCountsWithoutLeaking(t *testing.T) {
	var big, hid strings.Builder
	for i := 0; i < maxSearchResults+250; i++ {
		fmt.Fprintf(&big, "int match_%d;\n", i)
	}
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&hid, "int match_secret_%d;\n", i)
	}
	long := "int match_long = 1; /* " + strings.Repeat("x", 2*maxLineWidth) + " */\n"
	e := repo(t, map[string]string{"a_long.c": long, "big.c": big.String(), "keys/hidden.c": hid.String()})
	e.Perms, _ = permissions.Parse(nil, nil, []string{"read_file(keys/**)"})
	out, err := call(t, NewSet(e), "search", map[string]any{"pattern": "match_"})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != maxSearchResults+1 {
		t.Fatalf("got %d lines, want %d results + 1 summary", len(lines), maxSearchResults)
	}
	// a_long.c (1) + big.c (cap+250) matches in total, cap shown: 251 more.
	if want := "[... 251 more matches"; !strings.HasPrefix(lines[len(lines)-1], want) {
		t.Fatalf("summary %q, want prefix %q", lines[len(lines)-1], want)
	}
	if strings.Contains(out, "hidden.c") || strings.Contains(out, "secret") {
		t.Fatal("denied path leaked")
	}
	if !strings.HasPrefix(lines[0], "a_long.c:1:") || !strings.HasSuffix(lines[0], " [...]") || len(lines[0]) > maxLineWidth+len(" [...]") {
		t.Fatalf("long line not truncated: %d chars", len(lines[0]))
	}
}

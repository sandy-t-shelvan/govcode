package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	if _, err := call(t, s, "outline", map[string]any{"path": "src/b.c"}); err == nil || !strings.Contains(err.Error(), "denied by policy") {
		t.Errorf("outline of a read-denied file: %v", err)
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

// An ask rule on read_file withholds the file until a human approves, and
// with no approver it denies. Search returns the same text, so it must not
// treat that rule as an allow, and it must not count the hidden lines.
func TestSearchAskRuleIsNotABypass(t *testing.T) {
	e := repo(t, map[string]string{
		"credentials/token.txt": "token = supersecret\ntoken = second\n",
		"src/a.c":               "int token_len;\n",
	})
	e.Perms, _ = permissions.Parse(nil, []string{"read_file(credentials/**)"}, nil)
	evs := collect(e)
	s := NewSet(e)

	if _, err := call(t, s, "read_file", map[string]any{"path": "credentials/token.txt"}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("read_file ask with no approver: %v", err)
	}
	out, err := call(t, s, "search", map[string]any{"pattern": "token"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "supersecret") || strings.Contains(out, "credentials/") {
		t.Fatalf("search leaked an ask path with no approver:\n%s", out)
	}
	if !strings.Contains(out, "src/a.c") || strings.Contains(out, "more matches") {
		t.Fatalf("allowed match missing or hidden match counted:\n%s", out)
	}

	ap := &approveAll{}
	e.Approver = ap
	out, err = call(t, s, "search", map[string]any{"pattern": "token"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "supersecret") || !strings.Contains(out, "second") || !strings.Contains(out, "src/a.c") {
		t.Fatalf("approved search hid the file:\n%s", out)
	}
	if len(ap.asked) != 1 || ap.asked[0] != "search(credentials/token.txt)" {
		t.Fatalf("approver asked %v, want one prompt for the file", ap.asked)
	}

	no := &denyAll{}
	e.Approver = no
	out, err = call(t, s, "search", map[string]any{"pattern": "token"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "supersecret") || strings.Contains(out, "credentials/") {
		t.Fatalf("search showed a file the human denied:\n%s", out)
	}
	if len(no.asked) != 1 {
		t.Fatalf("denying approver asked %v", no.asked)
	}

	var decisions []string
	for _, ev := range evs() {
		if ev.Kind != "permission" {
			continue
		}
		m := ev.Data.(map[string]any)
		if m["tool"] == "search" {
			decisions = append(decisions, m["decision"].(string)+":"+m["subject"].(string))
		}
	}
	if strings.Join(decisions, ",") != "deny:credentials/token.txt,allow:credentials/token.txt,deny:credentials/token.txt" {
		t.Fatalf("search permission events %v", decisions)
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

// git grep -n prefixes every hit with "path:lineno:". Portion marks and
// banner lines are recognised only at the start of a line, so the guard has
// to see the file text, not the prefix; otherwise search hands the model
// markings that read_file would withhold. (Test from PR #19.)
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
	if !strings.Contains(out, "withheld") || !strings.Contains(out, "portion.txt:2:// (S) allowed in this repo") {
		t.Fatalf("search dropped a permitted line or the withhold notice:\n%s", out)
	}
}

// read_file withholds a file that carries a banner, and search returns the
// unmarked line next to it. Editing that line runs git diff -U2, whose
// context contains the banner. The diff is tool output, so it has to be
// withheld too. A portion mark removed by the edit is a diff deletion
// ("-(TS) …"); the leading '-' must not hide it, including from a later
// allowlisted `git diff`.
func TestEditDiffDoesNotLeakMarkings(t *testing.T) {
	e := repo(t, map[string]string{"doc.c": "TOP SECRET\nint mode = 3;\n"})
	e.MaxLevel = marking.S
	s := NewSet(e)
	found, err := call(t, s, "search", map[string]any{"pattern": "mode"})
	if err != nil || strings.Contains(found, "TOP SECRET") || !strings.Contains(found, "doc.c:2:int mode = 3;") {
		t.Fatalf("search of the unmarked line: %v\n%s", err, found)
	}
	out, err := call(t, s, "edit_file", map[string]any{"path": "doc.c", "old_text": "int mode = 3;", "new_text": "int mode = 4;"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "TOP SECRET") || !strings.Contains(out, "Edited") || !strings.Contains(out, "withheld") {
		t.Fatalf("edit diff leaked or was not withheld:\n%s", out)
	}
	body, _ := os.ReadFile(filepath.Join(e.Jail.Root, "doc.c"))
	if !strings.Contains(string(body), "int mode = 4;") || !strings.Contains(string(body), "TOP SECRET") {
		t.Fatalf("edit did not apply:\n%s", body)
	}

	clean := repo(t, map[string]string{"ok.c": "int mode = 3;\n"})
	clean.MaxLevel = marking.S
	out, err = call(t, NewSet(clean), "edit_file", map[string]any{"path": "ok.c", "old_text": "int mode = 3;", "new_text": "int mode = 4;"})
	if err != nil || strings.Contains(out, "withheld") || !strings.Contains(out, "int mode = 4") {
		t.Fatalf("clean edit diff: %v\n%s", err, out)
	}

	e = repo(t, map[string]string{"portion.c": "(TS) payload coordinates\nint mode = 3;\n"})
	e.MaxLevel = marking.S
	e.Allowlist = []string{"git diff"}
	s = NewSet(e)
	out, err = call(t, s, "edit_file", map[string]any{
		"path": "portion.c", "old_text": "(TS) payload coordinates", "new_text": "// (S) allowed in this repo",
	})
	if err != nil || strings.Contains(out, "payload") || strings.Contains(out, "(TS)") || !strings.Contains(out, "withheld") {
		t.Fatalf("deleted portion mark returned to the model: %v\n%s", err, out)
	}
	out, err = call(t, s, "run_command", map[string]any{"command": "git diff"})
	if err != nil || strings.Contains(out, "payload") || strings.Contains(out, "(TS)") || !strings.Contains(out, "withheld") {
		t.Fatalf("git diff returned the deleted portion mark: %v\n%s", err, out)
	}
}

// A path containing ':' must not shift the line-number field: the hit keeps
// its real path (so deny rules match it) and the marking is still caught.
func TestSearchPathWithColons(t *testing.T) {
	e := repo(t, map[string]string{
		"a:1:b.txt":      "TOP SECRET\nok line\n",
		"keys/x:2:y.txt": "ok line\n",
	})
	e.MaxLevel = marking.S
	e.Perms, _ = permissions.Parse(nil, nil, []string{"read_file(keys/**)"})
	out, err := call(t, NewSet(e), "search", map[string]any{"pattern": "SECRET|ok"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "TOP SECRET") || strings.Contains(out, "keys/") {
		t.Fatalf("colon path leaked:\n%s", out)
	}
	if !strings.Contains(out, "a:1:b.txt:2:ok line") || !strings.Contains(out, "withheld") {
		t.Fatalf("colon path hit missing or misparsed:\n%s", out)
	}
}

// Every tool that shows file content (or discovers file names) must honor the
// read_file rules for that path, not only its own tool's rules. Permission
// rules match the exact tool name, so a policy that denies read_file(keys/**)
// must still keep keys/ out of outline, edit_file diffs and file listings.
func TestReadRulesCoverEveryContentTool(t *testing.T) {
	const secret = "int secret_fn(void)\n{\n    return 4242;\n}\n"
	type tc struct {
		tool string
		args map[string]any
		// discovers: the tool finds paths itself (search, list_files), so the
		// protected path must not appear at all. Tools given the path by the
		// model may name it in their refusal.
		discovers bool
	}
	calls := []tc{
		{"read_file", map[string]any{"path": "keys/creds.h"}, false},
		{"outline", map[string]any{"path": "keys/creds.h"}, false},
		{"edit_file", map[string]any{"path": "keys/creds.h", "old_text": "return", "new_text": "return  "}, false},
		{"search", map[string]any{"pattern": "secret_fn|4242|ok_fn"}, true},
		{"list_files", map[string]any{}, true},
	}
	setups := []struct {
		name     string
		rules    func() (*permissions.Rules, error)
		approver func() Approver
	}{
		{"deny", func() (*permissions.Rules, error) { return permissions.Parse(nil, nil, []string{"read_file(keys/**)"}) }, nil},
		{"ask, no approver", func() (*permissions.Rules, error) { return permissions.Parse(nil, []string{"read_file(keys/**)"}, nil) }, nil},
		{"ask, human denies", func() (*permissions.Rules, error) { return permissions.Parse(nil, []string{"read_file(keys/**)"}, nil) }, func() Approver { return &denyAll{} }},
	}
	for _, su := range setups {
		for _, c := range calls {
			t.Run(su.name+"/"+c.tool, func(t *testing.T) {
				e := repo(t, map[string]string{"keys/creds.h": secret, "src/ok.c": "int ok_fn(void) { return 1; }\n"})
				var err error
				if e.Perms, err = su.rules(); err != nil {
					t.Fatal(err)
				}
				var ap Approver
				if su.approver != nil {
					ap = su.approver()
					e.Approver = ap
				}
				out, cerr := call(t, NewSet(e), c.tool, c.args)
				seen := out
				if cerr != nil {
					seen += "\n" + cerr.Error()
				}
				if strings.Contains(seen, "secret_fn") || strings.Contains(seen, "4242") {
					t.Fatalf("%s revealed protected content:\n%s", c.tool, seen)
				}
				// list_files with an approver attached lists names without
				// asking (read_file still asks for the content); everywhere
				// else a protected path must not be discovered.
				namesOK := c.tool == "list_files" && su.approver != nil
				if c.discovers && !namesOK && strings.Contains(seen, "keys/") {
					t.Fatalf("%s revealed a protected path:\n%s", c.tool, seen)
				}
				if d, ok := ap.(*denyAll); ok && c.tool == "list_files" && len(d.asked) != 0 {
					t.Fatalf("list_files prompted the approver: %v", d.asked)
				}
				if c.discovers && !strings.Contains(seen, "src/ok.c") {
					t.Fatalf("%s hid an unprotected file:\n%s", c.tool, seen)
				}
				got, _ := os.ReadFile(filepath.Join(e.Jail.Root, "keys/creds.h"))
				if string(got) != secret {
					t.Fatalf("%s modified a file it may not read", c.tool)
				}
			})
		}
	}
	// With a human approving the ask, the content tools work as before.
	for _, c := range calls[:4] {
		t.Run("ask, human approves/"+c.tool, func(t *testing.T) {
			e := repo(t, map[string]string{"keys/creds.h": secret})
			e.Perms, _ = permissions.Parse(nil, []string{"read_file(keys/**)"}, nil)
			e.Approver = &approveAll{}
			out, err := call(t, NewSet(e), c.tool, c.args)
			if err != nil {
				t.Fatalf("%s refused after approval: %v", c.tool, err)
			}
			if !strings.Contains(out, "secret_fn") && !strings.Contains(out, "keys/creds.h") {
				t.Fatalf("%s output after approval:\n%s", c.tool, out)
			}
		})
	}
}

// Commands must not read what read_file may not (GOV-47): read-protected
// worktree files are masked inside the sandbox, and git is hidden so history
// cannot reveal them either. Exposed paths stay visible to commands only.
func TestSandboxHidesReadProtectedFiles(t *testing.T) {
	const secret = "int secret_fn(void) { return 4242; }\n"
	newEnv := func(t *testing.T) *Env {
		e := repo(t, map[string]string{"keys/creds.h": secret, "src/ok.c": "int ok_fn(void) { return 1; }\n"})
		if !e.Runner.Sandboxed() {
			t.Skip("bubblewrap not available")
		}
		return e
	}
	run := func(e *Env, c string) ExecResult { return e.Runner.Run(context.Background(), c, 30*time.Second) }
	deny, _ := permissions.Parse(nil, nil, []string{"read_file(keys/**)"})

	t.Run("deny hides file and git", func(t *testing.T) {
		e := newEnv(t)
		e.Runner.HideReadProtected(deny, nil, false)
		if r := run(e, "cat keys/creds.h"); strings.Contains(r.Output, "4242") || r.HiddenPaths != 1 {
			t.Fatalf("cat of a read-denied file: hidden=%d\n%s", r.HiddenPaths, r.Output)
		}
		if r := run(e, "cat src/ok.c"); r.ExitCode != 0 || !strings.Contains(r.Output, "ok_fn") {
			t.Fatalf("unprotected file not readable: %+v", r)
		}
		for _, c := range []string{"git show HEAD:keys/creds.h", "git log --all -p", "cat .git/HEAD"} {
			if r := run(e, c); strings.Contains(r.Output, "4242") || strings.Contains(r.Output, "refs/heads") {
				t.Fatalf("%q reached git data:\n%s", c, r.Output)
			}
		}
		if r := run(e, "echo x > keys/creds.h"); r.ExitCode == 0 {
			t.Fatal("a command overwrote a read-denied file")
		}
	})

	// govcode runs commands in a linked worktree: .git there is a file and
	// the object store is the main repository's (bound separately).
	t.Run("linked worktree hides file and git", func(t *testing.T) {
		e := newEnv(t)
		wt := filepath.Join(t.TempDir(), "wt")
		if out, err := exec.Command("git", "-C", e.Jail.Root, "worktree", "add", "-q", "--detach", wt).CombinedOutput(); err != nil {
			t.Fatalf("worktree add: %s", out)
		}
		r, err := NewRunner(SandboxBestEffort, wt, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.HideReadProtected(deny, nil, false)
		for _, c := range []string{"cat keys/creds.h", "git show HEAD:keys/creds.h", "git log --all -p"} {
			if res := r.Run(context.Background(), c, 30*time.Second); strings.Contains(res.Output, "4242") {
				t.Fatalf("%q in a linked worktree revealed protected content:\n%s", c, res.Output)
			}
		}
		if res := r.Run(context.Background(), "cat src/ok.c", 30*time.Second); !strings.Contains(res.Output, "ok_fn") {
			t.Fatalf("unprotected file in linked worktree: %+v", res)
		}
	})

	t.Run("ask counts as hidden", func(t *testing.T) {
		e := newEnv(t)
		ask, _ := permissions.Parse(nil, []string{"read_file(keys/**)"}, nil)
		e.Runner.HideReadProtected(ask, nil, false)
		if r := run(e, "cat keys/creds.h"); strings.Contains(r.Output, "4242") {
			t.Fatalf("ask-protected file readable by a command:\n%s", r.Output)
		}
	})

	t.Run("history of a deleted protected file stays hidden", func(t *testing.T) {
		e := newEnv(t)
		for _, a := range [][]string{{"rm", "-q", "keys/creds.h"}, {"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "rm"}} {
			if out, err := exec.Command("git", append([]string{"-C", e.Jail.Root}, a...)...).CombinedOutput(); err != nil {
				t.Fatalf("git %v: %s", a, out)
			}
		}
		e.Runner.HideReadProtected(deny, nil, false)
		if r := run(e, "git log --all -p"); strings.Contains(r.Output, "4242") {
			t.Fatalf("git history revealed a deleted protected file:\n%s", r.Output)
		}
	})

	t.Run("expose keeps paths visible to commands only", func(t *testing.T) {
		e := newEnv(t)
		e.Perms = deny
		e.Runner.HideReadProtected(deny, []string{"keys/**"}, true)
		if r := run(e, "cat keys/creds.h"); !strings.Contains(r.Output, "4242") || r.HiddenPaths != 0 {
			t.Fatalf("exposed file hidden: %+v", r)
		}
		if r := run(e, "git show HEAD:keys/creds.h"); !strings.Contains(r.Output, "4242") {
			t.Fatalf("expose_git did not expose git:\n%s", r.Output)
		}
		if _, err := call(t, NewSet(e), "read_file", map[string]any{"path": "keys/creds.h"}); err == nil {
			t.Fatal("expose changed what read_file allows")
		}
	})

	t.Run("no read rules changes nothing", func(t *testing.T) {
		e := newEnv(t)
		none, _ := permissions.Parse(nil, nil, []string{"edit_file(keys/**)"})
		e.Runner.HideReadProtected(none, nil, false)
		if e.Runner.Hide != nil || e.Runner.HideGit {
			t.Fatal("hiding enabled without read rules")
		}
		if r := run(e, "git show HEAD:keys/creds.h"); !strings.Contains(r.Output, "4242") {
			t.Fatalf("git unexpectedly hidden:\n%s", r.Output)
		}
	})
}

// Without bubblewrap nothing can be hidden, so best-effort refuses commands
// while read rules protect files; with no rules, or in mode off, they run.
func TestNoSandboxRefusesWhenFilesAreProtected(t *testing.T) {
	e := repo(t, map[string]string{"keys/creds.h": "x 4242\n", "a.c": "int a;\n"})
	deny, _ := permissions.Parse(nil, nil, []string{"read_file(keys/**)"})
	r := &Runner{Mode: SandboxBestEffort, Worktree: e.Jail.Root, MaxOutput: 30000, shell: "/bin/sh"}
	if res := r.Run(context.Background(), "cat a.c", 10*time.Second); res.ExitCode != 0 {
		t.Fatalf("no rules: %+v", res)
	}
	r.HideReadProtected(deny, nil, false)
	res := r.Run(context.Background(), "cat keys/creds.h", 10*time.Second)
	if res.ExitCode == 0 || strings.Contains(res.Output, "4242") || !strings.Contains(res.Output, "refused") {
		t.Fatalf("best-effort without bubblewrap ran a command over protected files: %+v", res)
	}
	r.Mode = SandboxOff
	if res := r.Run(context.Background(), "cat a.c", 10*time.Second); res.ExitCode != 0 {
		t.Fatalf("mode off refused: %+v", res)
	}
}

// Thousands of masks must not exceed the kernel's argument-size limit
// (ARG_MAX, 2 MiB): bubblewrap options are passed through a file descriptor.
func TestSandboxManyMasksFitArgLimit(t *testing.T) {
	long := strings.Repeat("d", 200)
	files := map[string]string{"ok.c": "int ok;\n"}
	for i := 0; i < 8000; i++ {
		files[fmt.Sprintf("big/%s/f%05d.c", long, i)] = "int x;\n"
	}
	e := repo(t, files)
	if !e.Runner.Sandboxed() {
		t.Skip("bubblewrap not available")
	}
	deny, _ := permissions.Parse(nil, nil, []string{"read_file(big/**)"})
	e.Runner.HideReadProtected(deny, nil, false)
	r := e.Runner.Run(context.Background(), "cat ok.c", 60*time.Second)
	if r.ExitCode != 0 || r.HiddenPaths != 8000 || !strings.Contains(r.Output, "int ok") {
		t.Fatalf("exit=%d hidden=%d output=%q", r.ExitCode, r.HiddenPaths, r.Output)
	}
}

// Edge cases of masking: what collapses to a whole-directory mask, what stays
// per-file, and that too many scattered masks end in govcode's own refusal.
func TestSandboxMaskShapes(t *testing.T) {
	run := func(e *Env, c string) ExecResult { return e.Runner.Run(context.Background(), c, 60*time.Second) }
	sandboxed := func(t *testing.T, e *Env) {
		if !e.Runner.Sandboxed() {
			t.Skip("bubblewrap not available")
		}
	}
	t.Run("whole protected directory hides names and refuses writes", func(t *testing.T) {
		e := repo(t, map[string]string{"keys/a.h": "4242\n", "keys/sub/b.h": "4242\n", "ok.c": "int ok;\n"})
		sandboxed(t, e)
		deny, _ := permissions.Parse(nil, nil, []string{"read_file(keys/**)"})
		e.Runner.HideReadProtected(deny, nil, false)
		if r := run(e, "ls -A keys"); strings.TrimSpace(r.Output) != "" || r.HiddenPaths != 2 {
			t.Fatalf("collapsed directory listing: hidden=%d %q", r.HiddenPaths, r.Output)
		}
		if r := run(e, "echo x > keys/new.h"); r.ExitCode == 0 {
			t.Fatal("a command wrote into a protected directory")
		}
	})
	t.Run("pattern that does not cover the directory keeps it writable", func(t *testing.T) {
		e := repo(t, map[string]string{"certs/a.pem": "4242\n", "ok.c": "int ok;\n"})
		sandboxed(t, e)
		deny, _ := permissions.Parse(nil, nil, []string{"read_file(**/*.pem)"})
		e.Runner.HideReadProtected(deny, nil, false)
		if r := run(e, "cat certs/a.pem"); strings.Contains(r.Output, "4242") {
			t.Fatalf("protected .pem readable:\n%s", r.Output)
		}
		if r := run(e, "echo x > certs/new.crt && ls certs"); r.ExitCode != 0 || !strings.Contains(r.Output, "a.pem") {
			t.Fatalf("certs/ was masked whole: %+v", r)
		}
	})
	t.Run("partly protected directory keeps the rest", func(t *testing.T) {
		e := repo(t, map[string]string{"keys/a.h": "4242\n", "keys/README": "public\n"})
		sandboxed(t, e)
		deny, _ := permissions.Parse(nil, nil, []string{"read_file(keys/*.h)"})
		e.Runner.HideReadProtected(deny, nil, false)
		r := run(e, "cat keys/a.h; cat keys/README; echo y > keys/new.txt && echo wrote")
		if strings.Contains(r.Output, "4242") || !strings.Contains(r.Output, "public") || !strings.Contains(r.Output, "wrote") {
			t.Fatalf("partly protected directory: %+v", r)
		}
	})
	t.Run("too many scattered masks are refused by govcode", func(t *testing.T) {
		files := map[string]string{}
		for i := 0; i < 3000; i++ {
			files[fmt.Sprintf("d%04d/k.pem", i)] = "4242\n"
			files[fmt.Sprintf("d%04d/ok.c", i)] = "int ok;\n"
		}
		e := repo(t, files)
		sandboxed(t, e)
		deny, _ := permissions.Parse(nil, nil, []string{"read_file(**/*.pem)"})
		e.Runner.HideReadProtected(deny, nil, false)
		if r := run(e, "true"); r.ExitCode == 0 || !strings.Contains(r.Output, "separately protected files") {
			t.Fatalf("scattered masks: %+v", r)
		}
	})
	t.Run("the options file is not readable inside the sandbox", func(t *testing.T) {
		e := repo(t, map[string]string{"keys/creds.h": "4242\n", "ok.c": "int ok;\n"})
		sandboxed(t, e)
		deny, _ := permissions.Parse(nil, nil, []string{"read_file(keys/*.h)"})
		e.Runner.HideReadProtected(deny, nil, false)
		r := run(e, "for f in /proc/self/fd/*; do case $f in */0|*/1|*/2) ;; *) cat $f 2>/dev/null;; esac; done | tr '\\0' '\\n'")
		if strings.Contains(r.Output, "creds.h") || strings.Contains(r.Output, "--ro-bind") {
			t.Fatalf("sandbox options (and protected paths) readable from a descriptor:\n%s", r.Output)
		}
	})
}

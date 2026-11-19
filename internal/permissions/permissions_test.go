package permissions

import "testing"

func TestPrecedenceAndDefaults(t *testing.T) {
	r, err := Parse(
		[]string{"run_command(make *)", "run_command(make)", "edit_file(src/**)", "read_file"},
		[]string{"edit_file(src/crypto/**)", "run_command(make install*)"},
		[]string{"read_file(keys/**)", "run_command(rm *)", "edit_file(**/*.pem)"},
	)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		tool, subj string
		want       Decision
	}{
		{"run_command", "make test", Allow},
		{"run_command", "make", Allow},
		{"run_command", "make install DESTDIR=/", Ask}, // ask beats allow
		{"run_command", "make test; rm -rf /", Ask},    // metachar downgrade
		{"run_command", "rm -rf build", Deny},
		{"run_command", "gcc -c a.c", Ask}, // default for commands
		{"edit_file", "src/radar/track.c", Allow},
		{"edit_file", "src/crypto/aes.c", Ask},
		{"edit_file", "src/certs/server.pem", Deny}, // deny beats allow
		{"read_file", "keys/prod/id_rsa", Deny},
		{"read_file", "keys", Deny},          // keys/** also covers the directory itself
		{"outline", "anything.adb", Allow},   // default for non-command tools
		{"read_file", "src/../keys/x", Deny}, // cleaned before matching
	}
	for _, c := range cases {
		if got, rule := r.Decide(c.tool, c.subj); got != c.want {
			t.Errorf("Decide(%s, %q) = %v (%s), want %v", c.tool, c.subj, got, rule, c.want)
		}
	}
}

func TestFromAllowlistCompat(t *testing.T) {
	r, _ := Parse(FromAllowlist([]string{"make", "cobc"}), nil, nil)
	for subj, want := range map[string]Decision{"make": Allow, "make -C src": Allow, "makefoo": Ask, "cobc -x a.cbl": Allow, "make && id": Ask} {
		if got, _ := r.Decide("run_command", subj); got != want {
			t.Errorf("%q: %v want %v", subj, got, want)
		}
	}
}

func TestBadRules(t *testing.T) {
	for _, s := range []string{"", "(x)", "run_command(make", "read file"} {
		if _, err := Parse([]string{s}, nil, nil); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func FuzzDecideNeverAllowsMeta(f *testing.F) {
	r, _ := Parse([]string{"run_command(*)", "run_command"}, nil, nil)
	f.Add("make; id")
	f.Add("ls")
	f.Fuzz(func(t *testing.T, cmd string) {
		if d, _ := r.Decide("run_command", cmd); d == Allow && HasShellMeta(cmd) {
			t.Fatalf("allowed %q with shell metacharacters", cmd)
		}
	})
}

func TestRestricts(t *testing.T) {
	r, _ := Parse([]string{"read_file(src/**)"}, []string{"edit_file(Makefile)"}, []string{"run_command(rm *)"})
	if r.Restricts("read_file") {
		t.Error("an allow rule alone does not restrict read_file")
	}
	if !r.Restricts("edit_file") || !r.Restricts("run_command") {
		t.Error("ask and deny rules restrict their tools")
	}
	star, _ := Parse(nil, nil, []string{"*(secrets/**)"})
	if !star.Restricts("read_file") {
		t.Error("a * deny rule restricts every tool")
	}
	var none *Rules
	if none.Restricts("read_file") {
		t.Error("nil rules restrict nothing")
	}
}

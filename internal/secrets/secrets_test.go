package secrets

import (
	"regexp"
	"strings"
	"testing"
)

func TestDetects(t *testing.T) {
	for kind, line := range map[string]string{
		"private key":         "-----BEGIN RSA PRIVATE KEY-----",
		"AWS access key id":   `key = "AKIAIOSFODNN7EXAMPLE"`,
		"GitHub token":        "token: ghp_" + strings.Repeat("a1B2", 9),
		"GitLab token":        "glpat-" + strings.Repeat("x", 20),
		"credentials in URL":  "git clone https://deploy:hunter2pass@git.local/repo",
		"password assignment": `db_password = "Tr0ub4dor&3x"`,
		"high-entropy string": `k = "Zm9vYmFyYmF6cXV4X3NlY3JldF9rZXlfdmFsdWVfOTg3NjU0MzIxMA+/Q"`,
	} {
		if got := ScanLine(line, nil); got != kind {
			t.Errorf("ScanLine(%q) = %q, want %q", line, got, kind)
		}
	}
}

func TestPrefixedNames(t *testing.T) {
	for _, line := range []string{`db_password = "Tr0ub4dor&3x"`, `API_KEY_PROD: "q8Fh3kLm9Pz2Wx7Rt"`, `rootPasswd := "S3cur3!pass"`} {
		if ScanLine(line, nil) != "password assignment" {
			t.Errorf("missed %q", line)
		}
	}
}

func TestNoFalsePositives(t *testing.T) {
	for _, line := range []string{
		`password = "changeme"`,
		`password = "${DB_PASSWORD}"`,
		`if (strcmp(password, input) == 0)`,
		`sha256 = "fadc3e5f8d42bf7e894a785b05082e47daee4df26680389817e2093056f088ad"`,
		`const char *msg = "Enter the password for the radar console:";`,
		`       01  WS-PASSWORD-LEN   PIC 99.`,
		`url = "https://git.local/repo.git"`,
	} {
		if got := ScanLine(line, nil); got != "" {
			t.Errorf("false positive %q on %q", got, line)
		}
	}
}

func TestScanDiffLocationsAndAllow(t *testing.T) {
	diff := `diff --git a/cfg.c b/cfg.c
index 1..2 100644
--- a/cfg.c
+++ b/cfg.c
@@ -10,3 +10,4 @@ int f(void)
 int a;
-int b;
+int b;
+static const char *api_key = "q8Fh3kLm9Pz2Wx7Rt";
 int c;
`
	fs := ScanDiff(diff, nil)
	if len(fs) != 1 || fs[0].File != "cfg.c" || fs[0].Line != 12 || fs[0].Kind != "password assignment" {
		t.Fatalf("findings %+v", fs)
	}
	allow := []*regexp.Regexp{regexp.MustCompile(`api_key = "q8Fh`)}
	if fs := ScanDiff(diff, allow); len(fs) != 0 {
		t.Fatal("allow pattern ignored")
	}
	// removed lines are not findings
	if fs := ScanDiff("+++ b/x\n@@ -1 +1 @@\n-password = \"Tr0ub4dor&3x\"\n", nil); len(fs) != 0 {
		t.Fatal("removed line flagged")
	}
}

func FuzzScanDiff(f *testing.F) {
	f.Add("+++ b/a\n@@ -1 +1,2 @@\n+x\n")
	f.Add("@@ +")
	f.Fuzz(func(t *testing.T, d string) {
		for _, fd := range ScanDiff(d, nil) {
			if fd.Kind == "" {
				t.Fatal("empty kind")
			}
		}
	})
}

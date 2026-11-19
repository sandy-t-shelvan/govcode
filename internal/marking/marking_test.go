package marking

import (
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{
		"SECRET//NOFORN": S, "TOP SECRET//SCI": TS, "UNCLASSIFIED//DEVELOPMENT": U,
		"confidential": C, "UNCLASSIFIED//E2E-TEST": U, "bogus": Unknown,
	} {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDetects(t *testing.T) {
	cases := map[string]Level{
		"TOP SECRET//SI//NOFORN":              TS,
		"// TOP SECRET//SCI":                  TS,
		"      * SECRET//REL TO USA, FVEY":    S,
		"TOP SECRET":                          TS,
		"/* SECRET */":                        S,
		"-- CONFIDENTIAL":                     C,
		"      *> (TS//SI) Track correlation": TS,
		"(S//NF) The radar mode":              S,
		"(C) Paragraph":                       C,
		"   ! (TS) fortran comment":           TS,
		"CLASSIFICATION: TOP SECRET":          TS,
		"Classification: SECRET":              S,
		"(U) unclassified portion":            U,
		"UNCLASSIFIED//FOUO":                  U,
	}
	for in, want := range cases {
		if got := lineLevel(in); got != want {
			t.Errorf("lineLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// Source code is full of the letters S, C, U and words like "secret".
// None of these may trigger.
func TestNoFalsePositives(t *testing.T) {
	for _, in := range []string{
		"static const char *SECRET_KEY_NAME = \"x\";",
		"if (S) return C;",
		"x = f(S) + g(TS);",
		"printf(\"(S) %d\\n\", n);",
		"the secretary filed it",
		"top secret recipe",
		"ENCRYPT-SECRET SECTION.",
		"bucket = s3://SECRET-bucket",
		"#define TS 3",
		"case 'S': return SECRET;",
		"   (S)", // portion mark without following text
		"Secret//sauce",
		"SECRETS_PATH=/etc",
		"       01  WS-SECRET-FLAG   PIC X.",
	} {
		if l := lineLevel(in); l != Unknown {
			t.Errorf("false positive %v on %q", l, in)
		}
	}
}

// A unified diff puts one marker byte in front of every file line.
// "-(TS) …" and "-TOP SECRET" are the file's own text; a '-' that is
// not inside a hunk is not a diff and must not become a marking.
func TestScanSeesMarkingsBehindDiffMarkers(t *testing.T) {
	diff := strings.Join([]string{
		"diff --git a/doc.c b/doc.c",
		"--- a/doc.c",
		"+++ b/doc.c",
		"@@ -1,3 +1,3 @@",
		"-(TS) payload coordinates",
		"-TOP SECRET",
		"+// (S) allowed in this repo",
		" int mode = 4;",
	}, "\n")
	fs := Above(diff, S)
	if len(fs) != 2 || fs[0].Line != 5 || fs[0].Level != TS || fs[1].Line != 6 || fs[1].Level != TS {
		t.Fatalf("Above(diff) = %+v", fs)
	}
	plain := "-(TS) payload coordinates\n-TOP SECRET\n"
	if got := Scan(plain); len(got) != 0 {
		t.Fatalf("a dash outside a hunk was treated as a diff marker: %+v", got)
	}
}

func TestAbove(t *testing.T) {
	text := "line one\n// (S//NF) radar\n/* TOP SECRET//SI */\n(U) ok"
	fs := Above(text, S)
	if len(fs) != 1 || fs[0].Line != 3 || fs[0].Level != TS {
		t.Fatalf("Above = %+v", fs)
	}
	if len(Above(text, TS)) != 0 {
		t.Fatal("nothing should be above TS")
	}
	if Highest(Scan(text)) != TS {
		t.Fatal("highest")
	}
}

func FuzzScan(f *testing.F) {
	f.Add("TOP SECRET//SI")
	f.Add("(S) x")
	f.Add("@@ -1,2 +1,2 @@\n-(TS) payload\n-TOP SECRET\n")
	f.Fuzz(func(t *testing.T, s string) {
		for _, fd := range Scan(s) {
			if fd.Level < U || fd.Level > TS || fd.Line < 1 {
				t.Fatalf("bad finding %+v", fd)
			}
		}
	})
}

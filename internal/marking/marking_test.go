package marking

import "testing"

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
	f.Fuzz(func(t *testing.T, s string) {
		for _, fd := range Scan(s) {
			if fd.Level < U || fd.Level > TS || fd.Line < 1 {
				t.Fatalf("bad finding %+v", fd)
			}
		}
	})
}

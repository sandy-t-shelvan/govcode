package ato

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const root = "../.."

// TestEvidenceExists keeps the control statements honest: every cited file
// must exist, every cited test or fuzz target must be defined, and every
// cited policy field must be a JSON field of the policy.
func TestEvidenceExists(t *testing.T) {
	tests := map[string]bool{}
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() && (info.Name() == "dist" || info.Name() == ".git" || info.Name() == "node_modules") {
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, "_test.go") {
			b, _ := os.ReadFile(p)
			for _, m := range regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)\w+)\(`).FindAllStringSubmatch(string(b), -1) {
				tests[m[1]] = true
			}
		}
		return nil
	})
	pol, err := os.ReadFile(filepath.Join(root, "internal/policy/policy.go"))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, c := range Controls {
		if ids[c.ID] {
			t.Errorf("duplicate control %s", c.ID)
		}
		ids[c.ID] = true
		if c.Statement == "" || c.Title == "" {
			t.Errorf("%s: empty statement or title", c.ID)
		}
		switch c.Status {
		case "implemented", "partial", "supported", "inherited":
		default:
			t.Errorf("%s: status %q", c.ID, c.Status)
		}
		if c.Status != "implemented" && c.Customer == "" {
			t.Errorf("%s: %s control needs a customer responsibility", c.ID, c.Status)
		}
		for _, f := range c.Code {
			if _, err := os.Stat(filepath.Join(root, f)); err != nil {
				t.Errorf("%s: evidence file %s missing", c.ID, f)
			}
		}
		for _, tn := range c.Tests {
			if !tests[tn] {
				t.Errorf("%s: evidence test %s is not defined", c.ID, tn)
			}
		}
		for _, pf := range c.Policy {
			last := pf[strings.LastIndex(pf, ".")+1:]
			if !strings.Contains(string(pol), `json:"`+last+`"`) && !strings.Contains(string(pol), `json:"`+last+`,`) {
				t.Errorf("%s: policy field %s not in policy.go", c.ID, pf)
			}
		}
	}
	for _, d := range DoWI {
		for _, c := range d.Controls {
			if !ids[c] {
				t.Errorf("DoWI %s maps to unknown control %s", d.Clause, c)
			}
		}
	}
}

func TestFuzzTargetsListed(t *testing.T) {
	have := map[string]bool{}
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() && (info.Name() == "dist" || info.Name() == ".git") {
			return filepath.SkipDir
		}
		if err == nil && strings.HasSuffix(p, "_test.go") {
			b, _ := os.ReadFile(p)
			for _, m := range regexp.MustCompile(`(?m)^func (Fuzz\w+)\(`).FindAllStringSubmatch(string(b), -1) {
				have[m[1]] = true
			}
		}
		return nil
	})
	listed := map[string]bool{}
	for _, f := range FuzzTargets {
		listed[f] = true
		if !have[f] {
			t.Errorf("FuzzTargets lists %s, which does not exist", f)
		}
	}
	for f := range have {
		if !listed[f] {
			t.Errorf("fuzz target %s missing from FuzzTargets", f)
		}
	}
}

// Synthetic benchmark: the IDs and text are made up for the test and are
// not DISA content.
const xccdf = `<?xml version="1.0"?>
<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2"><component>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="TEST_STIG">
 <title>Test Application STIG</title><version>9</version>
 <plain-text id="release-info">Release: 1 Benchmark Date: 01 Jan 2026</plain-text>
 <Group id="V-000001"><title>SRG-TEST-1</title>
  <Rule id="SV-000001r1_rule" severity="medium" weight="10.0"><version>TEST-000010</version>
   <title>The application must produce audit records for every privileged action.</title>
   <description>&lt;VulnDiscussion&gt;Audit matters.&lt;/VulnDiscussion&gt;</description>
   <ident system="http://cyber.mil/cci">CCI-999999</ident>
   <fixtext>Enable auditing.</fixtext><check><check-content>Check the log.</check-content></check>
  </Rule></Group>
 <Group id="V-000002"><title>SRG-TEST-2</title>
  <Rule id="SV-000002r1_rule" severity="low"><version>TEST-000020</version>
   <title>The application must display the approved banner.</title>
   <check><check-content>Look.</check-content></check></Rule></Group>
</Benchmark></component></data-stream-collection>`

func TestSTIGChecklist(t *testing.T) {
	b, err := ParseXCCDF(strings.NewReader(xccdf))
	if err != nil {
		t.Fatal(err)
	}
	if b.ID != "TEST_STIG" || b.Version != "9" || len(b.Rules) != 2 || b.Rules[0].Discussion != "Audit matters." || b.Rules[0].CCIs[0] != "CCI-999999" {
		t.Fatalf("%+v", b)
	}
	site := &SiteRuleMap{Rules: map[string]SiteRule{"V-000002": {Status: "not_applicable", Comment: "no UI"}}}
	ck, ev, st, err := CKLB(b, site, "host1")
	if err != nil || ev != 1 || st != 1 {
		t.Fatalf("%v ev=%d st=%d", err, ev, st)
	}
	rules := ck["stigs"].([]map[string]any)[0]["rules"].([]map[string]any)
	if rules[0]["status"] != "not_reviewed" || !strings.Contains(rules[0]["finding_details"].(string), "AU-2") {
		t.Errorf("audit rule: %v %v", rules[0]["status"], rules[0]["finding_details"])
	}
	if rules[1]["status"] != "not_applicable" || rules[1]["comments"] != "no UI" || rules[1]["finding_details"] != "" {
		t.Errorf("banner rule: %+v", rules[1])
	}
	if _, err := ParseXCCDF(strings.NewReader("<x/>")); err == nil {
		t.Error("non-benchmark accepted")
	}
	p := filepath.Join(t.TempDir(), "m.json")
	os.WriteFile(p, []byte(`{"rules":{"V-1":{"status":"passed"}}}`), 0o644)
	if _, err := LoadSiteRuleMap(p); err == nil {
		t.Error("bad status accepted")
	}
}

const vulnStream = `{"config":{"scanner_version":"v1.9.0","db":"https://vuln.go.dev","db_last_modified":"2026-11-10T00:00:00Z","go_version":"go1.27.4"}}
{"progress":{"message":"Scanning"}}
{"osv":{"id":"GO-2026-0001","aliases":["CVE-2026-1"],"summary":"called one"}}
{"osv":{"id":"GO-2026-0002","aliases":["CVE-2026-2"],"summary":"imported only"}}
{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.27.5","trace":[{"module":"stdlib","package":"net/http"}]}}
{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.27.5","trace":[{"module":"stdlib","package":"net/http","function":"Get"},{"module":"m","function":"main"}]}}
{"finding":{"osv":"GO-2026-0002","fixed_version":"v1.27.5","trace":[{"module":"stdlib","package":"archive/zip"}]}}
`

func TestVEX(t *testing.T) {
	doc, sum, err := VEX(strings.NewReader(vulnStream), "example.com/x", "1.0", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Affected != 1 || sum.NotAffected != 1 || sum.Scanner != "govulncheck v1.9.0" {
		t.Fatalf("%+v", sum)
	}
	sts := doc["statements"].([]map[string]any)
	if sts[0]["status"] != "affected" || sts[1]["status"] != "not_affected" || sts[1]["justification"] != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("%+v", sts)
	}
	if _, _, err := VEX(strings.NewReader(`{"x":1}`), "p", "v", time.Now()); err == nil {
		t.Error("non-govulncheck input accepted")
	}
	doc, sum, _ = VEX(strings.NewReader(strings.SplitN(vulnStream, "\n", 2)[0]), "p", "v", time.Now())
	if sum.Affected+sum.NotAffected != 0 || len(doc["statements"].([]map[string]any)) != 0 {
		t.Error("clean scan should have no statements")
	}
}

func TestSummarizeGoTest(t *testing.T) {
	in := `{"Action":"run","Package":"a","Test":"TestX"}
{"Action":"pass","Package":"a","Test":"TestX"}
{"Action":"pass","Package":"a","Test":"TestX/sub"}
{"Action":"fail","Package":"a","Test":"TestY"}
{"Action":"skip","Package":"b","Test":"TestZ"}
{"Action":"fail","Package":"a"}
{"Action":"pass","Package":"b"}`
	s, err := SummarizeGoTest(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if s.Passed != 1 || s.Failed != 1 || s.Skipped != 1 || s.Packages["a"].Status != "fail" || s.Packages["a"].Failing[0] != "TestY" {
		t.Fatalf("%+v %+v", s, s.Packages["a"])
	}
}

func TestWritePackage(t *testing.T) {
	b, _ := ParseXCCDF(strings.NewReader(xccdf))
	doc, sum, _ := VEX(strings.NewReader(vulnStream), "p", "1", time.Now())
	ts, _ := SummarizeGoTest(strings.NewReader(`{"Action":"pass","Package":"a","Test":"TestX"}`))
	dir := filepath.Join(t.TempDir(), "pkg")
	files, err := Write(dir, Inputs{Version: "1", Classification: "SECRET//NOFORN", Host: "h", Now: time.Now(),
		Policy: map[string]any{"enforce": "strict"}, Benchmark: b, VEX: doc, VEXSummary: &sum, Tests: ts,
		AuditSample: []map[string]any{{"seq": 1}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "README.md,SHA256SUMS,audit-sample.json,cnssi-1253.json,configuration.json,controls.json,dowi-8430.01.json,stig/TEST_STIG.cklb,tests.json,vex.openvex.json"
	got := append([]string{}, files...)
	sortStrings(got)
	if strings.Join(got, ",") != want {
		t.Fatalf("files %v", got)
	}
	for _, f := range files {
		data, _ := os.ReadFile(filepath.Join(dir, f))
		if f == "SHA256SUMS" || f == "vex.openvex.json" {
			continue
		}
		if !strings.Contains(string(data), "NOT AN AUTHORIZATION") || (f != "stig/TEST_STIG.cklb" && !strings.Contains(string(data), "SECRET//NOFORN")) {
			t.Errorf("%s lacks the disclaimer or marking", f)
		}
	}
	sums, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if strings.Count(string(sums), "\n") != len(files)-1 {
		t.Errorf("SHA256SUMS:\n%s", sums)
	}
	if _, err := Write(dir, Inputs{}); err == nil {
		t.Error("wrote into a non-empty directory")
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

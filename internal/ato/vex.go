package ato

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// VEX builds an OpenVEX v0.2.0 document from `govulncheck -json` output.
// govulncheck reports each vulnerability at module, package and function
// level; a vulnerability affects govcode only if some finding's trace
// reaches a vulnerable function. Imported-but-not-called ones are
// not_affected with justification vulnerable_code_not_in_execute_path.
func VEX(r io.Reader, product, version string, now time.Time) (map[string]any, VEXSummary, error) {
	type osv struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
		Summary string   `json:"summary"`
	}
	type frame struct {
		Module   string `json:"module"`
		Package  string `json:"package"`
		Function string `json:"function"`
	}
	type finding struct {
		OSV          string  `json:"osv"`
		FixedVersion string  `json:"fixed_version"`
		Trace        []frame `json:"trace"`
	}
	type msg struct {
		Config *struct {
			ScannerVersion string `json:"scanner_version"`
			DB             string `json:"db"`
			DBLastModified string `json:"db_last_modified"`
			GoVersion      string `json:"go_version"`
		} `json:"config"`
		OSV     *osv     `json:"osv"`
		Finding *finding `json:"finding"`
	}
	osvs := map[string]*osv{}
	called := map[string]bool{}
	fixed := map[string]string{}
	var sum VEXSummary
	dec := json.NewDecoder(bufio.NewReader(r))
	for dec.More() {
		var m msg
		if err := dec.Decode(&m); err != nil {
			return nil, sum, fmt.Errorf("govulncheck json: %w", err)
		}
		switch {
		case m.Config != nil:
			sum.Scanner = "govulncheck " + m.Config.ScannerVersion
			sum.DB = m.Config.DB + " (" + m.Config.DBLastModified + ")"
			sum.GoVersion = m.Config.GoVersion
		case m.OSV != nil:
			osvs[m.OSV.ID] = m.OSV
		case m.Finding != nil:
			f := m.Finding
			if _, ok := called[f.OSV]; !ok {
				called[f.OSV] = false
			}
			if len(f.Trace) > 0 && f.Trace[0].Function != "" {
				called[f.OSV] = true
			}
			fixed[f.OSV] = f.FixedVersion
		}
	}
	if sum.Scanner == "" {
		return nil, sum, fmt.Errorf("not govulncheck -json output (no config message)")
	}
	ids := make([]string, 0, len(called))
	for id := range called {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	purl := "pkg:golang/" + product + "@" + version
	statements := []map[string]any{}
	for _, id := range ids {
		st := map[string]any{"vulnerability": map[string]any{"name": id}, "products": []map[string]any{{"@id": purl}}}
		if o := osvs[id]; o != nil {
			st["vulnerability"] = map[string]any{"name": id, "aliases": o.Aliases, "description": o.Summary}
		}
		if called[id] {
			sum.Affected++
			st["status"] = "affected"
			st["action_statement"] = "Upgrade to " + strings.TrimPrefix(fixed[id], "v") + " or later."
		} else {
			sum.NotAffected++
			st["status"] = "not_affected"
			st["justification"] = "vulnerable_code_not_in_execute_path"
			st["impact_statement"] = "govulncheck call-graph analysis found no path from govcode to the vulnerable symbol."
		}
		statements = append(statements, st)
	}
	doc := map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        "urn:govcode:vex:" + version + ":" + now.UTC().Format("20060102T150405Z"),
		"author":     "govcode ato (contractor self-assessment)",
		"role":       "Document Creator",
		"timestamp":  now.UTC().Format(time.RFC3339),
		"version":    1,
		"tooling":    sum.Scanner + "; vulndb " + sum.DB + "; " + sum.GoVersion,
		"statements": statements,
	}
	return doc, sum, nil
}

type VEXSummary struct {
	Scanner, DB, GoVersion string
	Affected, NotAffected  int
}

// TestSummary counts `go test -json` results per package.
type TestSummary struct {
	Packages map[string]*PkgResult `json:"packages"`
	Passed   int                   `json:"tests_passed"`
	Failed   int                   `json:"tests_failed"`
	Skipped  int                   `json:"tests_skipped"`
}

type PkgResult struct {
	Passed  int      `json:"passed"`
	Failed  int      `json:"failed"`
	Skipped int      `json:"skipped"`
	Status  string   `json:"status"`
	Failing []string `json:"failing,omitempty"`
}

func SummarizeGoTest(r io.Reader) (*TestSummary, error) {
	s := &TestSummary{Packages: map[string]*PkgResult{}}
	dec := json.NewDecoder(bufio.NewReader(r))
	n := 0
	for dec.More() {
		var e struct {
			Action, Package, Test string
		}
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("go test -json: %w", err)
		}
		n++
		if e.Package == "" {
			continue
		}
		p := s.Packages[e.Package]
		if p == nil {
			p = &PkgResult{}
			s.Packages[e.Package] = p
		}
		switch {
		case e.Test == "" && (e.Action == "pass" || e.Action == "fail" || e.Action == "skip"):
			p.Status = e.Action
		case e.Test != "" && !strings.Contains(e.Test, "/") && e.Action == "pass":
			p.Passed++
			s.Passed++
		case e.Test != "" && !strings.Contains(e.Test, "/") && e.Action == "fail":
			p.Failed++
			s.Failed++
			p.Failing = append(p.Failing, e.Test)
		case e.Test != "" && !strings.Contains(e.Test, "/") && e.Action == "skip":
			p.Skipped++
			s.Skipped++
		}
	}
	if n == 0 {
		return nil, fmt.Errorf("empty go test -json input")
	}
	return s, nil
}

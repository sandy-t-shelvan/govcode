package ato

import (
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// The STIG checklist is built from the official benchmark the site
// downloads from DISA (the ASD STIG XCCDF). govcode ships no rule IDs or
// rule text of its own. Every rule starts as not_reviewed; govcode adds
// evidence pointers to rules whose title matches one of its keyword
// mappings, and sets a status only where the site's own rule map says so.
// The assessment itself is the reviewer's.

type Benchmark struct {
	ID      string
	Title   string
	Version string
	Release string
	Rules   []STIGRule
}

type STIGRule struct {
	GroupID    string // V-xxxxxx
	GroupTitle string
	RuleID     string // SV-xxxxxx...
	Severity   string
	Version    string // STIG ID, e.g. APSC-DV-xxxxxx
	Title      string
	Discussion string
	Check      string
	Fix        string
	CCIs       []string
	Weight     string
}

// xml shapes (namespace-agnostic: DISA uses XCCDF 1.1, some tools 1.2)
type xBenchmark struct {
	ID      string   `xml:"id,attr"`
	Title   string   `xml:"title"`
	Version string   `xml:"version"`
	Plain   []xPlain `xml:"plain-text"`
	Groups  []xGroup `xml:"Group"`
}
type xPlain struct {
	ID   string `xml:"id,attr"`
	Text string `xml:",chardata"`
}
type xGroup struct {
	ID    string   `xml:"id,attr"`
	Title string   `xml:"title"`
	Rules []xRule  `xml:"Rule"`
	Sub   []xGroup `xml:"Group"`
}
type xRule struct {
	ID       string   `xml:"id,attr"`
	Severity string   `xml:"severity,attr"`
	Weight   string   `xml:"weight,attr"`
	Version  string   `xml:"version"`
	Title    string   `xml:"title"`
	Desc     string   `xml:"description"`
	Fix      string   `xml:"fixtext"`
	Idents   []xIdent `xml:"ident"`
	Check    struct {
		Content string `xml:"check-content"`
	} `xml:"check"`
}
type xIdent struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

var reDiscussion = regexp.MustCompile(`(?s)<VulnDiscussion>(.*?)</VulnDiscussion>`)

// ParseXCCDF reads a DISA STIG benchmark: a bare XCCDF Benchmark or one
// inside a SCAP data stream.
func ParseXCCDF(r io.Reader) (*Benchmark, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, fmt.Errorf("no XCCDF Benchmark element found")
		}
		if err != nil {
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Benchmark" {
			continue
		}
		var xb xBenchmark
		if err := dec.DecodeElement(&xb, &se); err != nil {
			return nil, err
		}
		b := &Benchmark{ID: xb.ID, Title: strings.TrimSpace(xb.Title), Version: strings.TrimSpace(xb.Version)}
		for _, p := range xb.Plain {
			if p.ID == "release-info" {
				b.Release = strings.TrimSpace(p.Text)
			}
		}
		var walk func([]xGroup)
		walk = func(gs []xGroup) {
			for _, g := range gs {
				for _, r := range g.Rules {
					sr := STIGRule{GroupID: g.ID, GroupTitle: strings.TrimSpace(g.Title), RuleID: r.ID, Severity: r.Severity,
						Weight: r.Weight, Version: strings.TrimSpace(r.Version), Title: strings.TrimSpace(r.Title),
						Fix: strings.TrimSpace(r.Fix), Check: strings.TrimSpace(r.Check.Content)}
					if m := reDiscussion.FindStringSubmatch(r.Desc); m != nil {
						sr.Discussion = strings.TrimSpace(m[1])
					} else {
						sr.Discussion = strings.TrimSpace(r.Desc)
					}
					for _, id := range r.Idents {
						if strings.Contains(id.System, "cci") {
							sr.CCIs = append(sr.CCIs, strings.TrimSpace(id.Value))
						}
					}
					b.Rules = append(b.Rules, sr)
				}
				walk(g.Sub)
			}
		}
		walk(xb.Groups)
		if len(b.Rules) == 0 {
			return nil, fmt.Errorf("benchmark %s has no rules", b.ID)
		}
		return b, nil
	}
}

// Keyword maps a rule-title pattern to the govcode controls whose evidence
// is relevant. Matching only attaches evidence; it never sets a status.
type Keyword struct {
	Pattern  string   `json:"pattern"`
	Controls []string `json:"controls"`
}

// DefaultKeywords are deliberately broad; the reviewer discards what does
// not apply.
var DefaultKeywords = []Keyword{
	{`(?i)\baudit|\blog(s|ging)?\b|event record`, []string{"AU-2", "AU-3", "AU-9", "AU-12"}},
	{`(?i)non-?repudiat|digital(ly)? sign`, []string{"AU-10", "SR-4"}},
	{`(?i)access control|authoriz|privilege`, []string{"AC-3", "AC-6"}},
	{`(?i)separation of duties|two-person|dual authori|change (control|approval)|approv\w* (the )?changes?`, []string{"AC-5", "CM-5"}},
	{`(?i)input|validat|injection|untrusted`, []string{"SI-10"}},
	{`(?i)integrity|tamper|checksum|hash`, []string{"SI-7", "CM-14"}},
	{`(?i)crypt|FIPS`, []string{"SC-13"}},
	{`(?i)\bnetwork|\bport|boundary|connection`, []string{"SC-7"}},
	{`(?i)classif|marking|spillage`, []string{"SI-10"}},
	{`(?i)test|code review|static analysis|vulnerability scan`, []string{"SA-11", "SA-15"}},
	{`(?i)supply chain|third.party|component|bill of materials`, []string{"SR-3", "SR-11"}},
	{`(?i)authenticat|password|credential|PKI|CAC`, []string{"IA-2", "IA-5"}},
}

// SiteRuleMap is the site's own assessment of specific rules, by V-ID.
type SiteRuleMap struct {
	Rules    map[string]SiteRule `json:"rules"`
	Keywords []Keyword           `json:"keywords,omitempty"` // replaces DefaultKeywords when set
}

type SiteRule struct {
	Status  string `json:"status"` // not_a_finding | open | not_applicable | not_reviewed
	Comment string `json:"comment"`
}

func LoadSiteRuleMap(path string) (*SiteRuleMap, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m SiteRuleMap
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for id, r := range m.Rules {
		switch r.Status {
		case "not_a_finding", "open", "not_applicable", "not_reviewed":
		default:
			return nil, fmt.Errorf("%s: status %q (want not_a_finding, open, not_applicable or not_reviewed)", id, r.Status)
		}
	}
	return &m, nil
}

func uuid4() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// CKLB builds a STIG Viewer 3 checklist (.cklb JSON). It returns the
// checklist and how many rules received evidence pointers and site statuses.
func CKLB(b *Benchmark, site *SiteRuleMap, host string) (map[string]any, int, int, error) {
	kws := DefaultKeywords
	if site != nil && len(site.Keywords) > 0 {
		kws = site.Keywords
	}
	type kre struct {
		re *regexp.Regexp
		cs []string
	}
	var res []kre
	for _, k := range kws {
		re, err := regexp.Compile(k.Pattern)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("keyword %q: %v", k.Pattern, err)
		}
		res = append(res, kre{re, k.Controls})
	}
	byID := map[string]Control{}
	for _, c := range Controls {
		byID[c.ID] = c
	}
	stigUUID := uuid4()
	var rules []map[string]any
	withEvidence, withStatus := 0, 0
	for _, r := range b.Rules {
		seen := map[string]bool{}
		var cs []string
		for _, k := range res {
			if k.re.MatchString(r.Title) {
				for _, c := range k.cs {
					if !seen[c] {
						seen[c] = true
						cs = append(cs, c)
					}
				}
			}
		}
		sort.Strings(cs)
		var details strings.Builder
		if len(cs) > 0 {
			withEvidence++
			details.WriteString("govcode evidence that may bear on this rule (reviewer to assess):\n")
			for _, c := range cs {
				ctl := byID[c]
				fmt.Fprintf(&details, "- %s %s [%s]: code %s; tests %s\n", ctl.ID, ctl.Title, ctl.Status,
					strings.Join(ctl.Code, ", "), strings.Join(ctl.Tests, ", "))
			}
		}
		status, comment := "not_reviewed", ""
		if site != nil {
			if sr, ok := site.Rules[r.GroupID]; ok {
				status, comment = sr.Status, sr.Comment
				withStatus++
			}
		}
		rules = append(rules, map[string]any{
			"uuid": uuid4(), "stig_uuid": stigUUID, "target_key": nil, "stig_ref": nil,
			"group_id": r.GroupID, "rule_id": strings.TrimSuffix(r.RuleID, "_rule"), "rule_id_src": r.RuleID,
			"weight": r.Weight, "classification": "UNCLASSIFIED", "severity": r.Severity,
			"rule_version": r.Version, "group_title": r.GroupTitle, "rule_title": r.Title,
			"fix_text": r.Fix, "false_positives": "", "false_negatives": "", "discussion": r.Discussion,
			"check_content": r.Check, "documentable": "false", "mitigations": "", "potential_impacts": "",
			"third_party_tools": "", "mitigation_control": "", "responsibility": "", "security_override_guidance": "",
			"ia_controls": "", "check_content_ref": map[string]any{"href": "", "name": "M"}, "legacy_ids": []string{},
			"ccis": r.CCIs, "group_tree": []map[string]any{{"id": r.GroupID, "title": r.GroupTitle, "description": ""}},
			"status": status, "overrides": map[string]any{}, "comments": comment, "finding_details": details.String(),
		})
	}
	ck := map[string]any{
		"title": "govcode - " + b.Title, "id": uuid4(), "active": false, "mode": 1, "has_path": true,
		"cklb_version": "1.0",
		"target_data": map[string]any{"target_type": "Computing", "host_name": host, "ip_address": "", "mac_address": "",
			"fqdn": "", "comments": "CONTRACTOR SELF-ASSESSMENT - NOT AN AUTHORIZATION. Generated by govcode ato.", "role": "None",
			"is_web_database": false, "technology_area": "Application Review", "web_db_site": "", "web_db_instance": ""},
		"stigs": []map[string]any{{"stig_name": b.Title, "display_name": b.Title, "stig_id": b.ID,
			"release_info": b.Release, "version": b.Version, "uuid": stigUUID, "reference_identifier": "",
			"size": len(rules), "rules": rules}},
	}
	return ck, withEvidence, withStatus, nil
}

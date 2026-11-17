package ato

// DoWIClause maps one DoWI 8430.01 ("Accelerated Mission Software",
// effective 8 Sep 2026) requirement to govcode controls.
//
// The clause wording below is taken from secondary summaries, not the
// official text. The generated package says so, and the compliance
// reviewer must check each row against the published instruction.
type DoWIClause struct {
	Clause      string   `json:"clause"`
	Requirement string   `json:"requirement_summary"`
	Controls    []string `json:"nist_controls"`
	How         string   `json:"how_govcode_meets_it"`
	Evidence    []string `json:"evidence"`
}

var DoWI = []DoWIClause{
	{"3.5", "Produce a software bill of materials for every build.", []string{"SR-3", "CM-14"},
		"Every release ships a CycloneDX 1.6 SBOM of the binary, toolchain, system tools and editor extension, and an AI-BOM of the models.",
		[]string{"sbom.cdx.json", "aibom.cdx.json", "internal/supply/sbom.go"}},
	{"3.5", "Provide machine-readable build provenance and attestations.", []string{"SR-4", "CM-14"},
		"Signed SLSA v1 provenance and an SBOM attestation (in-toto, DSSE, Ed25519) per release, verified at every start when configured.",
		[]string{"provenance.intoto.jsonl", "sbom.intoto.jsonl", "govcode attest verify"}},
	{"3.6", "Treat AI-generated code as unverified input that gets the same review and security testing as human-written code.", []string{"SA-11", "SA-15", "SI-10"},
		"Mandatory static analysis, the test gate, secret and spillage scans, and site checks run on every proposal before a human can approve it.",
		[]string{"analysis (policy)", "internal/analysis", "internal/app/run.go"}},
	{"3.6", "A human approves changes; separation of duties for security- or safety-critical code.", []string{"AC-5", "CM-5"},
		"Nothing lands without `govcode approve` at a terminal; the two-person rule is forced on for sensitive repositories.",
		[]string{"two_person_rule (policy)", "internal/proposal"}},
	{"3.6", "Keep records of the models and versions used to generate code.", []string{"SR-4", "AU-3", "AU-10"},
		"An approver-signed evidence record per landed change names the model, revision, quantization, origin, artifact hashes and generation settings, bound to the commit by the Govcode-Evidence trailer.",
		[]string{"govcode evidence", "internal/evidence"}},
	{"3.6", "Maintain traceability and auditability of AI-assisted development.", []string{"AU-2", "AU-9", "AU-12"},
		"A hash-chained, per-user-signed audit log of every model exchange, tool call, command and decision, anchored into landed commits.",
		[]string{"govcode audit verify", "internal/audit"}},
}

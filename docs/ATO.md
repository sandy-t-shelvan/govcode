# ATO evidence package (`govcode ato`)

`govcode ato` writes the material an ISSM needs to bring govcode into a System Security Plan (RMF in eMASS: DAAPM v2.2 for cleared contractors, or ICD 503 / JSIG). **Everything it produces is a contractor self-assessment, not an authorization.** Every file says so and carries the policy's classification marking.

## Generate

Run these on the high-side host with the production policy, so the configuration and preflight results are the real ones.

```bash
govulncheck -json ./... > vuln.json
```

```bash
go test -json ./... > tests.json
```

```bash
govcode ato -o /secure/ato-$(date +%F) -stig U_ASD_STIG_Manual-xccdf.xml -stig-map site-stig-map.json -govulncheck vuln.json -test-json tests.json
```

Run the first two on the build host from the release's source commit, then carry the files across.

## Contents

| File | What it is |
|---|---|
| `README.md` | Summary table and control status list |
| `controls.json` | NIST SP 800-53 Rev 5 implementation statements for 24 controls (AC, AU, CM, IA, SA, SC, SI, SR). Each statement cites code paths, test names and policy fields, plus the customer responsibility for partial, supported and inherited controls. A build-time test (`TestEvidenceExists`) fails if any cited file, test or policy field stops existing. |
| `dowi-8430.01.json` | DoWI 8430.01 §3.5 and §3.6 mapped to those controls. **The requirement wording comes from secondary summaries; check each row against the official instruction.** |
| `cnssi-1253.json` | How the component controls fit under the AO's CNSSI 1253 baseline |
| `stig/<benchmark>.cklb` | STIG Viewer 3 checklist built from the **official** ASD STIG XCCDF that you supply with `-stig`. govcode ships no STIG rule IDs or text. |
| `vex.openvex.json` | OpenVEX from govulncheck. A vulnerability whose code is never called is `not_affected` (vulnerable_code_not_in_execute_path); a called one is `affected`, with its fixed version. |
| `tests.json` | Pass, fail and skip counts per package, and the fuzz targets CI runs |
| `configuration.json` | The policy settings that matter for assessment, and every preflight result |
| `audit-sample.json` | The most recent audit summaries (no objects). Classified at the repository's level. |
| `SHA256SUMS` | Hash of every file |

## The STIG checklist

Download the ASD STIG from DISA (public.cyber.mil) on the low side and transfer it with your normal media procedure.

- Every rule starts as **Not Reviewed**. govcode adds `finding_details` listing the controls and evidence that may apply, matched by rule title (`DefaultKeywords` in `internal/ato/stig.go`). The matching is deliberately broad; discard what doesn't apply.
- Statuses come only from your site rule map (`-stig-map`). The reviewer writes it, keyed by V-ID:

  ```json
  {"rules": {"V-xxxxxx": {"status": "not_a_finding", "comment": "Verified by ... on ..."}},
   "keywords": [{"pattern": "(?i)audit", "controls": ["AU-2"]}]}
  ```

  `status` is `not_a_finding`, `open`, `not_applicable` or `not_reviewed`. A `keywords` list replaces the defaults.
- Open the `.cklb` in STIG Viewer 3 and finish the review there.

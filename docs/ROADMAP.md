# Roadmap and ticket plan

Mirrors Jira project **GOV**: one epic per phase, one story per feature. Each story is built on a feature branch and merged through a PR once every CI gate passes (see CONTRIBUTING.md).

| Epic | Story | Status |
|---|---|---|
| GOV-1 Local model pipeline | GOV-6 network guard, GOV-7 backends + num_ctx, GOV-8 tool-call recovery | Done |
| | GOV-9 model staging | Code done; **staging run pending** (low-side host, about 80 GB) |
| | GOV-10 10-task eval | Harness done, scoring validated; **target-model run pending on GPU** |
| | GOV-40 real local model, air-gapped (CPU) | Done: Granite-3.3-8B on CPU in a loopback-only namespace scored 3/10 tasks with 97% valid tool calls; 5 real-model bugs fixed (see EVAL.md). Not a Devstral result |
| GOV-2 Agent loop on legacy code | (phase 1–5 PR) | Done; large-repo scale test outstanding |
| GOV-3 Signed audit log | (phase 1–5 PR) | Done; WORM export covered by GOV-30 |
| GOV-4 SBOM / supply chain | (phase 1–5 PR) | Done |
| GOV-5 Approval and access control | (phase 1–5 PR) | Done; hardware signer GOV-31 |
| | GOV-41 multi-user two-person e2e | Done: `scripts/e2e/two-person.sh` passes 33/33 with real OS users and now runs in CI on every PR. Its first run found a silent no-tool-call on non-streaming servers and a repository-swap fallback, both fixed |
| GOV-11 SDLC and CI gates | GOV-15 CI gates, GOV-16 fuzzing, GOV-17 PR process | Done (PR #2). Fuzzing found 2 bugs; govulncheck found 36 vulnerabilities in Go 1.24.7, fixed by moving to 1.27.4 |
| GOV-12 Agent features | GOV-18 permission rules | Done (PR #3) |
| | GOV-19 plan mode, GOV-20 hooks, GOV-21 project memory | Done (PR #4) |
| | GOV-23 streaming | Done (PR #6) |
| | GOV-22 resume, checkpoints and rewind (also GOV-23 follow-ups) | Done (PR #14) |
| GOV-13 VS Code | GOV-24 serve --stdio, GOV-25 panel, GOV-26 review, GOV-27 VSIX | Done (PR #5) |
| | GOV-43 real VS Code | Done: in VS Code 1.95.3 (headless, pinned SHA-256) the extension activates, drives the real `govcode serve` through a run to a ready proposal, and shows the tree, diff and panel. 10/10 checks, in CI on every PR. Not yet tried on the site's VS Code build or a remote/SSH workspace |
| GOV-14 Classified hardening | GOV-28 spillage guard, GOV-29 secret scan | Done (PR #3) |
| | GOV-30 SIEM export | Done (PR #6) |
| | GOV-31 PIV/CAC signing (PKCS#11, site CA, hardware approvers) | Done (PR #17); tested with SoftHSM2 in CI; **physical CAC not yet tried** |
| GOV-32 Classified deployment readiness | GOV-33 Devstral default + model-origin policy | Done (PR #7) |
| | GOV-34 SLSA v1 / in-toto build provenance | Done (PR #8) |
| | GOV-35 per-change AI evidence record | Done (PR #9) |
| | GOV-36 mandatory static analysis | Done (PR #10) |
| | GOV-38 refuse pickle-format weights, staging malware scan | Done (PR #11) |
| | GOV-37 `govcode ato` evidence package | Done (PR #12); **STIG Viewer 3 import of the .cklb not yet tried** |
| | GOV-39 RHEL 8/9 RPM, SELinux module, FIPS and SELinux preflight | Packaging merged (PR #16); **install on a STIG-hardened RHEL host with FIPS and SELinux enforcing not yet done** |

## The 1-week proof
1. **Day 1–2:** stage Devstral-Small-2507 Q4_K_M (and Qwen3-Coder only if the AO grants an origin exception) on the low side, transfer it, run `govcode model verify`.
2. **Day 2:** install per DEPLOYMENT.md; `govcode verify` must be all PASS. Run `scripts/e2e/two-person.sh` on a scratch VM, and install the VSIX in VS Code.
3. **Day 3:** run `govcode eval` on Devstral (and Qwen3-Coder if excepted). Go/no-go: ≥ 95% valid tool calls and ≥ 7/10 tasks passed.
4. **Day 4:** `govcode ato` with the site's official ASD STIG XCCDF; hand the package to the ISSM.
5. **Day 4–5:** real tickets on the customer repository through plan → run → review → approve, from the CLI and from VS Code. Run `govcode audit verify` daily and confirm the events arrive in the SIEM.

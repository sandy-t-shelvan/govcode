# Roadmap and ticket plan

Mirrors Jira project **GOV**: one epic per phase, one story per feature. Each story is built on a feature branch and merged through a PR once every CI gate passes (see CONTRIBUTING.md).

| Epic | Story | Status |
|---|---|---|
| GOV-1 Local model pipeline | GOV-6 network guard, GOV-7 backends + num_ctx, GOV-8 tool-call recovery | Done |
| | GOV-9 model staging | Code done; **staging run pending** (low-side host, about 80 GB) |
| | GOV-10 10-task eval | Harness done, scoring validated; **target-model run pending on GPU** |
| GOV-2 Agent loop on legacy code | (phase 1–5 PR) | Done; large-repo scale test outstanding |
| GOV-3 Signed audit log | (phase 1–5 PR) | Done; WORM export covered by GOV-30 |
| GOV-4 SBOM / supply chain | (phase 1–5 PR) | Done |
| GOV-5 Approval and access control | (phase 1–5 PR) | Done; multi-user e2e script to run on a VM; hardware signer GOV-31 |
| GOV-11 SDLC and CI gates | GOV-15 CI gates, GOV-16 fuzzing, GOV-17 PR process | Done (PR #2). Fuzzing found 2 bugs; govulncheck found 36 vulnerabilities in Go 1.24.7, fixed by moving to 1.27.4 |
| GOV-12 Agent features | GOV-18 permission rules | Done (PR #3) |
| | GOV-19 plan mode, GOV-20 hooks, GOV-21 project memory | Done (PR #4) |
| | GOV-23 streaming | Done (PR #6) |
| | GOV-22 resume and checkpoints | **To do** |
| GOV-13 VS Code | GOV-24 serve --stdio, GOV-25 panel, GOV-26 review, GOV-27 VSIX | Done (PR #5); **not yet tried in a real VS Code** |
| GOV-14 Classified hardening | GOV-28 spillage guard, GOV-29 secret scan | Done (PR #3) |
| | GOV-30 SIEM export | Done (PR #6) |
| | GOV-31 PIV/CAC signing | **To do** (needs smart-card hardware to test) |
| GOV-32 Classified deployment readiness | GOV-33 Devstral default + model-origin policy | Done (PR #7) |
| | GOV-34 SLSA v1 / in-toto build provenance | PR #8 |
| | GOV-35 per-change AI evidence record | Built; PR after #8 |
| | GOV-36 mandatory static analysis | Built; PR after GOV-35 |
| | GOV-37 ATO package generator, GOV-38 refuse pickle-format weights, GOV-39 RHEL packaging on a STIG host | **To do** (P1) |

## The 1-week proof
1. **Day 1–2:** stage Devstral-Small-2507 Q4_K_M (and Qwen3-Coder only if the AO grants an origin exception) on the low side, transfer it, run `govcode model verify`.
2. **Day 2:** install per DEPLOYMENT.md; `govcode verify` must be all PASS. Run `scripts/e2e/two-person.sh` on a scratch VM, and install the VSIX in VS Code.
3. **Day 3:** run `govcode eval` on Devstral (and Qwen3-Coder if excepted). Go/no-go: ≥ 95% valid tool calls and ≥ 7/10 tasks passed.
4. **Day 4–5:** real tickets on the customer repository through plan → run → review → approve, from the CLI and from VS Code. Run `govcode audit verify` daily and confirm the events arrive in the SIEM.

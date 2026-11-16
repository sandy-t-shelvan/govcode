# Roadmap and ticket plan

This mirrors the Jira plan: one epic per phase, with stories under each. Status reflects this branch.

## Phase 1: Local model pipeline (epic)
| Story | Status |
|---|---|
| P1.1 Remove all cloud providers; loopback-only network guard | Done: `internal/netguard`; the OpenCode provider SDKs were removed |
| P1.2 Ollama native + OpenAI-compatible (vLLM/llama.cpp) backends with explicit num_ctx | Done: `internal/llm`; num_ctx is required and sent on every Ollama request |
| P1.3 Reliable tool calling (fallback parsing, JSON repair, schema validation) | Done: Qwen3-Coder XML, Hermes, Mistral and JSON-block recovery; coercion; model-readable errors |
| P1.4 Model staging: quantize, SHA-pinned signed artifacts, AI-BOM, Modelfile + vLLM config | Done in code: real revision and SHA-256 pins. **Staging not yet run** (needs a low-side host with about 80 GB of disk) |
| P1.5 Tool-call success eval on 10 real legacy-code tasks | Harness, tasks and validated scoring done. **Target-model run pending on GPU hardware** |

## Phase 2: Agent loop on legacy code (epic)
| Story | Status |
|---|---|
| P2.1 Repo-jailed tools sized for local models (list/search/read/outline/edit/create) | Done |
| P2.2 Byte-exact edits: COBOL columns, tabs, CRLF; recovery from copied line numbers | Done |
| P2.3 Plan → edit → test → fix loop with test gate on finish | Done |
| P2.4 Context budgeting for fixed num_ctx | Done |
| P2.5 Per-run git worktree; works with any on-prem remote | Done |
| P2.6 bubblewrap sandbox: no network, worktree-only writes | Done |
| P2.7 Large-repo scale test (≥ 1M LOC) | Todo: measure `search`/`list_files` latency and outline accuracy on a real program |

## Phase 3: Signed audit log (epic)
| Story | Status |
|---|---|
| P3.1 Hash-chained, Ed25519-signed entries; content-addressed objects | Done |
| P3.2 verify: modification, deletion, reorder, impersonation, object tamper | Done |
| P3.3 Truncation detection through commit anchors | Done |
| P3.4 chattr +a enforcement; classification on every entry | Done |
| P3.5 Periodic head export to WORM/SIEM | Todo |

## Phase 4: SBOM and signed supply chain (epic)
| Story | Status |
|---|---|
| P4.1 Stdlib-only, offline, reproducible build | Done (verified twice-build identical) |
| P4.2 CycloneDX 1.6 SBOM + AI-BOM | Done |
| P4.3 Signed release manifest; runtime self-verification (fail closed) | Done |
| P4.4 Build-time no-hidden-network test | Done |
| P4.5 FIPS 140-3 build | Done (`GOFIPS140=v1.0.0`); CMVP status to be confirmed by the reviewer |

## Phase 5: Human approval and access control (epic)
| Story | Status |
|---|---|
| P5.1 Root-owned policy binding one repo, approvers, sandbox, trust roots | Done |
| P5.2 Signed proposals; target branch never touched by the agent | Done |
| P5.3 Two-person approval with integrity checks and tty confirmation | Done |
| P5.4 uid-bound keyring | Done |
| P5.5 Multi-user acceptance test (`scripts/e2e/two-person.sh`) | Written, **not yet run** (creates OS users; run it on a disposable VM) |
| P5.6 PIV/CAC or HSM signer via PKCS#11 | Todo |

## The 1-week proof
1. Day 1–2: low-side staging of Qwen3-Coder-30B-A3B Q4_K_M; transfer; `govcode model verify`.
2. Day 2: install per DEPLOYMENT.md; `govcode verify` all PASS; run `scripts/e2e/two-person.sh` on a scratch VM.
3. Day 3: `govcode eval` on Qwen3-Coder and Devstral. Go/no-go: ≥ 95% valid tool calls and ≥ 7/10 tasks passed.
4. Day 4–5: real tickets on the customer's own repository through run → review → approve, with `audit verify` at the end of each day.

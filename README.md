# govcode

An air-gapped coding agent for legacy code, built for closed enclaves where nothing may leave the host and every change needs a named human approver.

- **Local model only.** Devstral-Small-24B (Mistral AI, France) by default, or Qwen3-Coder-30B-A3B where policy allows its origin, served by Ollama, vLLM or llama.cpp on `127.0.0.1`. There is no cloud provider code. The only network client refuses any address that is not loopback.
- **Works on the code you have.** Plan → edit → test → fix on C, C++, Ada, COBOL and Fortran, in large repositories hosted on on-prem git. Edits are byte-exact, so COBOL columns, tabs and CRLF line endings survive.
- **Signed audit log.** Append-only and hash-chained. Each entry is Ed25519-signed by the OS user who caused it. It records who asked, what the model said and did, every command, every diff, and who approved.
- **Signed supply chain.** Go standard library only, with zero third-party modules. The build is reproducible and uses FIPS 140-3 mode. It ships with a CycloneDX SBOM and AI-BOM, and model weights are pinned by SHA-256 in a signed lock file. The binary refuses to run if its own hash is not in the signed release manifest.
- **Human approval.** The agent only produces a signed *proposal*. A different person (two-person rule) approves it at a terminal before anything lands on the target branch. The tool runs as the invoking user, is limited to one repository, and its commands are sandboxed with no network access.

govcode began as a fork of [OpenCode](https://github.com/opencode-ai/opencode) (MIT). The cloud-provider TUI was replaced with this smaller, auditable core; the original code is in git history.

## Status

| Requirement | State | Evidence |
|---|---|---|
| 1. Local model pipeline | Implemented | `internal/llm`, `internal/netguard`, `models/models.lock.json` (real hub revisions and SHA-256s), `deploy/`, `scripts/stage-models.sh` |
| 1. Tool-call success on 10 real tasks | **Harness ready; target-model numbers not yet measured** | `govcode eval`; scoring is validated: the reference solutions score 10/10 and a do-nothing model 0/10 (`internal/eval`). The 30B model must be run on GPU hardware; see [docs/EVAL.md](docs/EVAL.md) |
| 2. Agent loop on legacy code | Implemented | `internal/agent`, `internal/tools`, tests for the full plan→edit→fail→fix→pass loop |
| 3. Signed audit log | Implemented | `internal/audit`; tests for modified, deleted and truncated entries, impersonation, and object tampering |
| 4. SBOM and signed supply chain | Implemented | `scripts/build-release.sh`, `govcode sbom`, `govcode verify`, `internal/supply/nonetwork_test.go` |
| 5. Approval and access control | Implemented | `internal/proposal`, `internal/policy`; multi-user acceptance script `scripts/e2e/two-person.sh` (**not yet run**: it creates OS users, so run it in a disposable VM) |

## How a change happens

```
developer (alice)                    approver (bob)                     ISSO
-----------------                    --------------                     ----
govcode run "fix X"                                                     policy.json (root-owned)
  ├─ preflight: release sig, model lock sig, served-model digest,      keyring (root-owned)
  │  policy perms, sandbox, keys, audit log chattr +a                  chattr +a audit log
  ├─ worktree on branch govcode/proposal/<id>
  ├─ agent loop (local model, sandboxed commands)
  │    every request/response/tool call -> signed audit entry
  └─ proposal.json signed by alice  (base, head, diff SHA-256)
                                     govcode review <id>
                                       verifies alice's signature, branch, diff hash
                                     govcode approve <id>
                                       bob != alice, bob in approvers
                                       types "approve" on /dev/tty
                                       audit entry -> anchor <seq>:<hash>
                                       merge commit on main:
                                         author alice, committer bob,
                                         Govcode-* trailers incl. audit anchor
govcode audit verify  -- chain, signatures, objects, and every anchor in main's history
```

## Quick start (development, warn mode)

```bash
go build -o bin/govcode ./cmd/govcode        # Go 1.27.4 (pinned in go.mod), no network needed
```

```bash
cd /path/to/your/repo && govcode init        # writes a dev policy (trust.enforce=warn)
```

```bash
export GOVCODE_POLICY=<path printed by init>
```

```bash
govcode keygen --register && govcode verify
```

```bash
ollama create govcode-devstral:24b-q4km -f deploy/ollama/Modelfile.devstral-small-24b
```

```bash
govcode model smoke                          # one tool-call round trip
```

```bash
govcode run "UPDATE-BALANCE in LEDGER.cbl truncates amounts over 99999.99; widen the field"
```

```bash
govcode review <id> && govcode approve <id>
```

For a classified deployment (strict mode, two-person rule, root-owned policy and keyring, append-only log), see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Commands

| Command | Who | What |
|---|---|---|
| `govcode run "<task>"` | developer | Runs the agent and produces a signed proposal. Never touches the target branch. |
| `govcode proposals` / `review <id>` | anyone | Lists proposals; shows a summary, test result, integrity check, audit trail and diff. |
| `govcode approve <id> [-m]` / `reject <id> -m` | approver | Lands or rejects a proposal. |
| `govcode audit verify \| show \| object` | anyone | Verifies or inspects the log. |
| `govcode evidence <commit\|proposal>` / `evidence export` | assessor | Verifies a landed change's signed AI evidence record (model, settings, checks, people, audit range); exports a date range for the ATO package. |
| `govcode verify` | anyone | Runs every preflight check and prints PASS/WARN/FAIL. |
| `govcode keygen [--register]` | each user | Creates your Ed25519 key in `~/.config/govcode/signing.key` (mode 0600). |
| `govcode sbom`, `aibom`, `manifest`, `sign` | release engineer | Supply-chain artifacts. |
| `govcode model verify \| smoke` | admin | Checks staged weights against the lock; tests one tool call against the server. |
| `govcode eval` | evaluator | Measures tool calls and task success on the 10 legacy tasks. |
| `govcode ato -o <dir> [-stig xccdf] [-govulncheck f] [-test-json f]` | ISSM | ATO evidence package: 800-53 statements, DoWI 8430.01 mapping, STIG checklist, VEX, test and audit summaries. A self-assessment, not an authorization. |
| `govcode serve --stdio` | VS Code extension | JSON-RPC over stdin/stdout for the editor UI; no sockets. |

## Documentation

- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): high-side installation for an ISSO or admin
- [docs/SECURITY.md](docs/SECURITY.md): how each requirement is enforced, the threat model, and known limitations
- [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md): what the security reviewer checks, model staging, SBOM and AI-BOM, FIPS
- [docs/EVAL.md](docs/EVAL.md): measuring tool-call reliability on your hardware
- [docs/VSCODE.md](docs/VSCODE.md): the VS Code extension (offline VSIX)
- [docs/ATO.md](docs/ATO.md): generating the ATO evidence package for the ISSM
- [docs/ROADMAP.md](docs/ROADMAP.md): phase and ticket plan (mirrors Jira)
- [CONTRIBUTING.md](CONTRIBUTING.md): branch, PR, CI gates and merge rules

## Layout

```
cmd/govcode/          CLI
internal/netguard     the only network client (loopback-only dialer)
internal/llm          Ollama /api/chat + OpenAI-compatible backends, tool-call recovery, schema validation
internal/agent        plan/edit/test/fix loop, context budgeting, metrics
internal/tools        jailed tools, legacy-language outline, bubblewrap runner
internal/audit        hash-chained signed log, object store, verifier
internal/proposal     proposals, two-person approval, landing, anchors
internal/policy       site policy (one repo, approvers, sandbox, trust roots)
internal/sign, keyring, identity   Ed25519 keys, uid-bound keyring, kernel identity
internal/modelpin     model lock verification, served-model digest check
internal/supply       SBOM / AI-BOM (CycloneDX 1.6), release manifest, no-network test
internal/eval         10-task legacy eval harness
models/               signed model lock (pinned revisions + SHA-256)
deploy/               Ollama Modelfiles (explicit num_ctx), systemd unit, vLLM/llama.cpp launchers, example policy
eval/tasks/           C, C++, Ada, COBOL tasks with hidden checkers
scripts/              stage-models.sh (low side), build-release.sh, e2e/
```

License: MIT (see LICENSE). Model weights are Apache-2.0 (see the AI-BOM).

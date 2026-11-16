# Contributing

## Workflow

1. **Ticket.** Every change starts from a Jira story in the GOV project with acceptance criteria.
2. **Branch.** Create `feature/GOV-<n>-<short-name>` from the latest `main`. Never commit to `main` directly.
3. **Build and test locally** before pushing:
   ```bash
   gofmt -l . && go vet ./... && scripts/ci/coverage.sh 52 && scripts/ci/fuzz.sh 10
   ```
4. **Pull request** into `main` using the template: Jira key, security impact, test evidence, Definition of Done.
5. **CI must be green.** Every job is required:

   | Job | Checks |
   |---|---|
   | `lint` | gofmt, `go vet`, staticcheck, no third-party Go modules |
   | `security` | govulncheck against the pinned toolchain |
   | `test` | full suite with the race detector; coverage floor |
   | `fuzz` | every fuzz target, 30 s each |
   | `release` | reproducible signed release build (built twice, compared) |
   | `vscode` | extension unit tests (once the extension exists) |

6. **Review.** CODEOWNERS review. Security-impact boxes that are ticked need an explicit reviewer comment.
7. **Merge** with a merge commit (history is kept for provenance), then move the Jira story to Done.

## Rules

- **Standard library only.** A new Go module, npm package or system tool needs a Jira story, a security review and an SBOM update.
- **Toolchain.** `go.mod` pins Go `1.27.4`, and older toolchains refuse to build. Bump it when govulncheck reports a fixed vulnerability.
- **Never lower the coverage floor** or skip, disable or quarantine a test to get green. Fix the cause.
- **Fuzz crashers are regressions.** Commit the input that `go test -fuzz` writes under `testdata/fuzz/`, together with the fix.
- **No real code, data or markings from a classified system** may enter this repository, which lives on the low side.

## Branch protection for `main` (repository admin)

In GitHub, go to **Settings → Branches → Add branch ruleset** (or Branch protection rule) for `main`, then:

- Require a pull request before merging, with 1 approval and Code Owner review
- Require status checks to pass: `lint`, `security`, `test`, `fuzz`, `release` (add `vscode` once it exists), and require branches to be up to date
- Block force pushes and deletions
- Do not allow bypassing the above settings

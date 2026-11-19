# Changelog

## Unreleased

### Security fixes
- Commands (`run_command`, `run_tests`, site hooks, analyzers) can no longer read files that `read_file` rules deny or ask for: such files are masked inside the sandbox, and git data is hidden while read rules exist, so history cannot reveal them (GOV-47). New policy fields `sandbox.expose` and `sandbox.expose_git` opt specific paths, or git, back in. Policies that use them do not load in v0.3.0.

### Behaviour changes
- With read rules in the policy, git commands inside the sandbox fail unless `sandbox.expose_git: true`. The example policy no longer lists `run_command(git *)`.
- In `best-effort` sandbox mode without bubblewrap, commands are refused while read rules protect files.
- A directory the read rules protect as a whole (for example `keys/**`) appears empty and read-only to commands. Builds that write into such a directory need it in `sandbox.expose`.
- Hiding needs a bubblewrap with `--args` and `--remount-ro`; with an older one, commands are refused while read rules exist.

## 0.3.0 (2026-11-19)

The first tagged release. Earlier builds (0.1.0, 0.2.0-rc1/rc2) were untagged development builds.

**Signing.** This tag ships no signed artifacts. Build and sign it on the site's controlled build host with the site release key (docs/SUPPLY_CHAIN.md):

    scripts/build-release.sh 0.3.0 /secure/release.key

The build is reproducible, so `bin/govcode` must match the SHA-256 recorded for this tag in the GitHub release notes / tag message.

### Security fixes
- `search` honors `read_file` ask rules: with no human attached, ask is deny; a human is asked once per file (#26).
- `search` spillage guard scans the file's own line instead of `path:lineno:text`, so `TOP SECRET` banners and `(TS)` portion marks are withheld; paths containing `:` are parsed correctly (GOV-45, #29).
- `outline`, `edit_file` and `list_files` honor `read_file` deny/ask rules; previously an edit could return a read-denied file's content in its diff (GOV-46, #31).
- Edit diffs and `git diff` output no longer return lines marked above the repository's level, including deleted `(TS)` lines (GOV-48, #30).
- A working directory inside a repository git cannot open is refused instead of silently falling back to the policy's repository (GOV-41, #21).

### Features
- PIV/CAC signing through PKCS#11, site CA trust, hardware-only approvers (GOV-31, #17).
- RHEL 8/9 RPMs, SELinux module, FIPS and SELinux preflight (GOV-39, #16).
- Resume interrupted runs; checkpoints and rewind (GOV-22, #14).
- `govcode ato` evidence package (GOV-37, #12); refusal of pickle-format weights and staging malware scan (GOV-38, #11); mandatory static analysis (GOV-36, #10); per-change AI evidence record (GOV-35, #9); signed SLSA v1 provenance (GOV-34, #8); model origin policy, Devstral default (GOV-33, #7).
- Streaming output and SIEM export (GOV-23/30, #6); VS Code extension, `serve --stdio`, offline VSIX (GOV-24–27, #5); plan mode, site hooks, project memory (GOV-19–21, #4).
- Per-model tool prompt and Granite tool-call parsing; invalid JSON escape repair; fenced JSON call lists (GOV-40, #20).
- Non-streamed model replies are accepted on streaming requests (GOV-41, #21).
- `search` streams output: a broad search on an 81,798-file repository dropped from 8.45 s to 1.6 s (GOV-42, #22).
- Eval report saved after every task, `-only` lists (GOV-40); turns with no reported token usage are counted, not recorded as 0 (GOV-44, #27).

### Testing
- Multi-user two-person e2e with real OS users, 33/33, in CI (GOV-41, #21).
- Extension tested inside a real VS Code 1.95.3, 10/10, in CI (GOV-43, #23).
- Large-repository scale test, `scripts/scale/run.sh` (GOV-42, #22).
- First real-model run, air-gapped on CPU: Granite-3.3-8B, 3/10 tasks, 97% valid tool calls; not a Devstral result (GOV-40, docs/EVAL.md).

### Known limitations
- Commands run by `run_command` can read files that `read_file` rules deny (GOV-47, decision pending). See docs/SECURITY.md, known limitation 7.
- Not yet done on target hardware: Devstral GPU eval (GOV-10), STIG-hardened RHEL host (GOV-39), physical CAC (GOV-31), STIG Viewer import (GOV-37).

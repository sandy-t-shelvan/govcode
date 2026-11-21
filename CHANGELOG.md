# Changelog

## Unreleased

### Security fixes
- The Mistral tool-call fallback no longer splits a call on `[TOOL_CALLS]` inside its JSON arguments. An edit whose text contained that marker was dropped, and a truncated edit could run the command written inside the argument (`make` and `gcc` are allowlisted).
- Commands (`run_command`, `run_tests`, site hooks, analyzers) can no longer read files that `read_file` rules deny or ask for: such files are masked inside the sandbox, and git data is hidden while read rules exist, so history cannot reveal them (GOV-47). New policy fields `sandbox.expose` and `sandbox.expose_git` opt specific paths, or git, back in. Policies that use them do not load in v0.3.0.

### Behaviour changes
- With read rules in the policy, git commands inside the sandbox fail unless `sandbox.expose_git: true`. The example policy no longer lists `run_command(git *)`.
- In `best-effort` sandbox mode without bubblewrap, commands are refused while read rules protect files.
- A directory the read rules protect as a whole (for example `keys/**`) appears empty and read-only to commands. Builds that write into such a directory need it in `sandbox.expose`.
- Hiding needs a bubblewrap with `--args` and `--remount-ro`; with an older one, commands are refused while read rules exist. `govcode verify` reports it as `sandbox hiding`.
- A proposal that changes a file read rules hide is `blocked` when the policy has analyzers or pre-proposal checks, since they run in the sandbox and cannot see it.

### Fixes
- llama.cpp now serves Devstral with tool calls. Its first-party GGUF embeds a chat template with no tool support, so `llama-server --jinja` dropped the tools and the model never called one. The lock pins a tool-capable template (`serve.llamacpp_chat_template`: path, size, sha256, source), `govcode model verify` checks it, and `deploy/llamacpp/serve.sh` passes it with `--chat-template-file`. A staged directory without that file now fails verification (GOV-10).
- `deploy/llamacpp/serve.sh` runs with `-np 1`, so the single session gets the whole `num_ctx` instead of a slot's share.
- Ollama now gets tool calls from Devstral. `deploy/ollama/Modelfile.devstral-small-24b` rendered calls in the old `[TOOL_CALLS][{"name":…}]` form, and Ollama builds its tool parser from that rendering. Devstral-Small-2507 writes `[TOOL_CALLS]name[ARGS]{…}`, so Ollama parsed none of its calls. The tool list also dropped out of the prompt after the first tool result. The Modelfile now uses the v11 format and lists the tools before the last user message. This changes the model's Ollama digest, so re-stage before deploying (GOV-10).
- The Mistral text fallback accepts `[TOOL_CALLS]name{…}` without `[ARGS]` when `name` is a known tool.
- `deploy/vllm/serve.sh` can load the pinned Devstral weights. It forced `--load-format mistral`, which reads `consolidated*.safetensors`, but the lock pins the Hugging Face-format shards (GOV-9).
- `scripts/stage-models.sh` verifies first-party upstream files for every model. For Devstral it used to fetch only the GGUF, so the shards were never checked against the lock. It also malware-scans everything it stages, and a rerun reuses files already staged instead of downloading them again.
- `govcode model verify` checks the upstream files staged for vLLM in `weights/<model-id>/`, and refuses any file there the lock does not list. With `-upstream`, which `deploy/vllm/serve.sh` passes, a staging with no upstream files fails verification instead of passing.
- `scripts/stage-models.sh`: a rerun without `GOVCODE_STAGE_UPSTREAM=1` keeps the vLLM files a previous run staged, an interrupted download resumes, and `SHA256SUMS` lists every staged file rather than only the GGUF.

### Additions
- `GOVCODE_STAGE_UPSTREAM=1` stages the verified safetensors for vLLM.
- docs/EVAL.md: Devstral-Small-2507 BF16 on vLLM, three seeds: 29/30 tasks passed, 100% valid tool calls (GOV-9).
- `govcode eval -seed` sets the sampling seed (default 42, as before).
- docs/EVAL.md: Devstral-Small-2507 Q4_K_M on an RTX PRO 6000 GPU via llama.cpp, three seeds: 27/30 tasks passed, 100% valid tool calls (GOV-10).

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

# Measuring tool-call reliability

> If the local model cannot call tools reliably, nothing else works.

`govcode eval` answers that question on **your** hardware, with **your** quantization and server, on 10 legacy-code tasks.

## The tasks (`eval/tasks/`)

| # | Lang | Defect |
|---|---|---|
| 01 | C89 | `strcpy` into a fixed buffer overruns a guard field |
| 02 | C89 | sign extension: checksum is wrong for bytes ≥ 0x80 |
| 03 | C89 | implement a stubbed CRC-16/CCITT from the header's spec |
| 04 | C++ | port `std::auto_ptr` to `std::unique_ptr` for C++17 |
| 05 | C++ | missing rule-of-three: shallow copy, double free (ASan) |
| 06 | Ada | `Constraint_Error` when a heading turn crosses north |
| 07 | Ada | implement a procedure declared in the spec but missing from the body |
| 08 | COBOL | `PIC V99` truncates a 5.25% rate (fixed-format columns) |
| 09 | COBOL | `PERFORM VARYING … UNTIL > 11` skips December |
| 10 | C | rename a function across a header, 3 sources and the test |

Each task has a repo, a visible `make test`, and a **hidden checker** with extra cases. The checker is copied over the final tree only after the agent stops, so editing the tests cannot fake a pass. Toolchains: gcc/g++, GNAT, GnuCOBOL. A task whose compiler is missing is reported as skipped, not failed.

**Scoring is validated, not assumed.** `go test ./internal/eval` runs every task twice. With the reference solution it must pass 10/10; with a do-nothing model it must pass 0/10. Both hold in the development environment.

## Run it

Start the model server as in [DEPLOYMENT.md](DEPLOYMENT.md), then run one smoke call first:

```bash
govcode model smoke
```

`parsed=native` means the server's tool template or parser is right. `parsed=fallback-*` means govcode recovered the call from text: it works, but fix the Modelfile `TEMPLATE` or the vLLM `--tool-call-parser`.

Full eval against Ollama:

```bash
govcode eval -backend ollama -endpoint http://127.0.0.1:11434 -model govcode-devstral:24b-q4km -num-ctx 32768 -temperature 0.15
```

The same eval against Devstral on vLLM (Qwen3-Coder works the same way where the AO has granted an origin exception):

```bash
govcode eval -backend openai -endpoint http://127.0.0.1:8000/v1 -model devstral-small-24b -num-ctx 32768 -temperature 0.15
```

Against llama.cpp started with `deploy/llamacpp/serve.sh`, use the same command with `-endpoint http://127.0.0.1:8080/v1`. `-seed` (default 42) changes the sampling seed. Run several seeds before trusting one score.

Results go to `eval/results/<time>-<model>.json` and `.md`. The report is rewritten after every task and has `"complete": false` until the run finishes, so an interrupted run (Ctrl-C, SIGTERM, a reboot) keeps the tasks it finished. To resume, pass the remaining tasks as a list, for example `-only 04,05,06`.

A model whose chat template drops its tool-calling instruction when a system prompt is present (Granite 3.x does this) needs that instruction restored. Set it with `-tool-prompt` here, or `serve.tool_prompt` in the model lock for `govcode run`.

## Metrics

| Metric | Meaning |
|---|---|
| **valid tool calls** | Share of emitted calls that named a real tool *and* had schema-valid arguments. This is the core "can it call tools" number. |
| executed without error | The call ran and the tool succeeded; for example, `old_text` matched the file exactly. A low value with high validity usually means whitespace or column mistakes in edits. |
| parse path | `native`, or which text fallback recovered the call (`qwen-xml`, `hermes`, `mistral`, `granite`, `json`). |
| no-call turns | Replies with prose and no tool call. govcode nudges up to 3 times, then stops. |
| tasks passed | The hidden checker passed on the final tree. |
| finished | The model called `finish` and the test gate accepted it. |
| model tokens | Prompt and output tokens the server reported. Some servers send no usage on streamed replies (llama-cpp-python ignores `stream_options.include_usage`); those turns are counted in `usage_unreported_turns` and the totals are marked as a lower bound. |

Suggested go/no-go for the one-week proof: **valid tool calls ≥ 95%** and **tasks passed ≥ 7/10** for the chosen model and quantization. If validity is high but executed-without-error is low, check the edit failures in the JSON before blaming the model.

## First real-model run: Granite 3.3 8B on CPU, air-gapped (GOV-40)

> **These are not Devstral numbers.** This run proves the pipeline works end to end against a real local model with no network. It says little about how the target model will score. The development container has 4 vCPU, 15 GB RAM and no GPU, so Devstral-24B does not fit; an 8B model is the largest that does.

| | |
|---|---|
| Model | IBM Granite-3.3-8B-Instruct, GGUF Q4_K_M (US origin, Apache-2.0; passes `denied_origins: ["CN"]`) |
| Weights | `granite-3.3-8b-instruct-Q4_K_M.gguf`, 4,942,873,344 bytes, sha256 `77bcee066a76dcdd10d0d123c87e32c8ec2c74e31b6ffd87ebee49c9ac215dca`, Hugging Face revision `e40e9dd739c7be00fa965c16ce167088190ce114` |
| Server | llama-cpp-python 0.3.16 (`llama_cpp.server`), CPU only, 4 threads, `n_ctx` 16384, the GGUF's own chat template |
| Throughput | about 2.8 tokens/s generation, 20–24 tokens/s prompt |
| govcode | `-num-ctx 16384 -max-tokens 2048 -temperature 0.1 -max-turns 20`, `-tool-prompt` set (see above) |
| Air gap | server and govcode ran inside `unshare --net`: only `lo` present, outbound HTTPS and direct-IP connections both failed in the same namespace, `govcode verify` passed |

Raw reports: [`docs/results/gov-40-granite-cpu/`](results/gov-40-granite-cpu/). The eval ran in two passes because the first was restarted on a fixed binary. Tasks 01–03 come from pass 1; task 04 was cut off there and re-run in pass 2 with 05–10.

| Task | Lang | Passed | Finished | Turns | Calls | Valid | Exec errors | No-call turns | Minutes |
|---|---|---|---|---|---|---|---|---|---|
| 01 buffer overflow | C | **yes** | yes | 11 | 13 | 100% | 3 | 2 | 5 |
| 02 sign extension | C | **yes** | yes | 7 | 9 | 100% | 1 | 1 | 5 |
| 03 implement CRC | C | no | no | 10 | 9 | 100% | 2 | 5 | 20 |
| 04 auto_ptr port | C++ | no | no | 7 | 8 | 88% | 2 | 4 | 59 |
| 05 rule of three | C++ | no | no | 9 | 4 | 75% | 1 | 5 | 18 |
| 06 Constraint_Error | Ada | **yes** | no | 12 | 17 | 100% | 2 | 5 | 6 |
| 07 missing body | Ada | no | no | 16 | 15 | 100% | 5 | 6 | 11 |
| 08 PIC truncation | COBOL | no | no | 11 | 10 | 100% | 1 | 5 | 7 |
| 09 PERFORM VARYING | COBOL | no | no | 14 | 10 | 90% | 4 | 5 | 8 |
| 10 rename across files | C | no | yes | 9 | 8 | 100% | 3 | 4 | 8 |

**Totals: 3/10 passed. 97% valid tool calls (100 of 103), 74% executed without error, 42 of 106 turns had no tool call.** 100 calls came through the new `granite` text parser, 3 through `json`, none native. Against the go/no-go above (≥ 95% valid, ≥ 7/10 passed), Granite-8B on CPU is a **no-go** for this work, which is expected for a model a third the size of the target.

What it shows:

- **Tool-call format is not the bottleneck.** Once the template's instruction was restored, 97% of calls were well-formed. The failures are edit accuracy (`old_text` with invented comments or wrong whitespace, so govcode refuses the edit), prose turns with no call, and weak reasoning on C++ and COBOL.
- **The safety gates held.** Mismatched edits were refused rather than guessed; a run that never passed its tests produced an `incomplete` proposal that `approve` refused; `audit verify` passed on every run (127 entries after four runs).
- **Real-model bugs found and fixed** (each has a regression test built from a captured reply):
  1. Granite's template drops its tool instruction when a system prompt is sent, so it never called tools. Fixed with `serve.tool_prompt` / `-tool-prompt` and a `granite` parser for `<|tool_call|>[...]`.
  2. C source in arguments (`'\0'`) is invalid JSON, so the whole multi-call reply was dropped. Invalid escapes are now repaired.
  3. A fenced JSON list of calls was ignored. It is now accepted when every name is a known tool.
  4. The no-call nag did not repeat the model's format, so it kept answering in prose. It now does.
  5. An eval killed part-way lost every finished task. The report is now saved after every task.
- **The full path with a real model** (run, then a `ready` proposal, approve, landed commit, `audit verify`, `evidence`) was shown on the eighth full `run` attempt on task 01. All of it ran air-gapped in the same loopback-only namespace.
  - Earlier attempts ended `incomplete`, at the turn limit, or with no tool call; most likely model variance. The eval ran this task once and passed, which is too small a sample to show that `run` (streamed replies) behaves differently from `eval` (non-streamed); both use the same prompt, seed and sampling settings. On the successful attempt, govcode refused three mismatched edits before Granite copied the text exactly.
  - The run passed `make test` and the hidden checker, and landed with every `Govcode-*` trailer. `audit verify` passed with 293 entries and the evidence record verified.
  - The fix is correct, but Granite put it on one line with the next statement. A human reviewer would likely send that back. Here approval used the dev-policy `--yes` path (`allow_non_interactive_approval`) because the host has no TTY, so nobody read the diff.

## Devstral-Small-2507 Q4_K_M on GPU, llama.cpp (GOV-10)

This is the target model and quantization, served the way `deploy/llamacpp/serve.sh` serves it. It ran three times with different sampling seeds, because one run is too small a sample.

| | |
|---|---|
| Model | Mistral AI Devstral-Small-2507 (FR origin, Apache-2.0), first-party GGUF Q4_K_M |
| Weights | `Devstral-Small-2507-Q4_K_M.gguf`, 14,333,915,904 bytes, sha256 `1bcc2b1b7b7ea3168ba2dbe782432c464f2240598bd193930122c41b117c1796`, `mistralai/Devstral-Small-2507_gguf` revision `ee2f0c00c5c86862f471fbf533268cf01b80d4a6` (as pinned in the lock) |
| Chat template | the lock's `serve.llamacpp_chat_template`: llama.cpp's `models/templates/unsloth-mistral-Devstral-Small-2507.jinja` at `a06044b9`, sha256 `039a4710…8c13b1`. Not the GGUF's own template; see the first finding below |
| Server | llama.cpp `b12447` (`a06044b9`), CUDA build for sm_120, `-c 32768 -np 1 -ngl 99 --jinja --chat-template-file …`, every layer on the GPU (19.4 GB VRAM incl. KV cache) |
| Hardware | 1 × NVIDIA RTX PRO 6000 Blackwell Workstation (96 GB), driver 595.99.02, CUDA 12.8 toolkit; Ryzen 9 7900X, 128 GB RAM; rented, Ubuntu 24.04 |
| Throughput | 77 tokens/s generation (median of 511 requests; p10–p90 74–81). About 4,100 tokens/s on an uncached prefill; most turns reuse the cached prefix |
| govcode | `c01efb1` + this change: `-backend openai -num-ctx 32768 -max-tokens 4096 -temperature 0.15 -max-turns 30`, `-seed` 42 / 1 / 2, no `-tool-prompt` |
| Network | not air-gapped. The host was a connected staging box, and both server and govcode were bound to 127.0.0.1. The air-gap behaviour was shown in GOV-40 |

Raw reports: [`docs/results/gov-10-devstral-gpu/llamacpp-q4km/`](results/gov-10-devstral-gpu/llamacpp-q4km/), one directory per seed.

| Task | Lang | Passed (42 / 1 / 2) | Finished | Turns | Exec errors |
|---|---|---|---|---|---|
| 01 buffer overflow | C | **yes** / **yes** / **yes** | no / no / yes | 30 / 30 / 19 | 3 / 9 / 0 |
| 02 sign extension | C | no / **yes** / **yes** | no / yes / yes | 30 / 11 / 10 | 2 / 0 / 0 |
| 03 implement CRC | C | **yes** / **yes** / **yes** | yes / yes / yes | 10 / 10 / 10 | 0 / 0 / 0 |
| 04 auto_ptr port | C++ | **yes** / **yes** / **yes** | yes / yes / yes | 10 / 10 / 8 | 0 / 0 / 0 |
| 05 rule of three | C++ | **yes** / **yes** / **yes** | yes / yes / yes | 10 / 15 / 10 | 0 / 0 / 0 |
| 06 Constraint_Error | Ada | **yes** / no / **yes** | yes / no / yes | 20 / 30 / 30 | 7 / 14 / 6 |
| 07 missing body | Ada | **yes** / **yes** / **yes** | yes / yes / yes | 8 / 8 / 8 | 0 / 0 / 0 |
| 08 PIC truncation | COBOL | **yes** / no / **yes** | yes / no / yes | 16 / 30 / 25 | 7 / 26 / 9 |
| 09 PERFORM VARYING | COBOL | **yes** / **yes** / **yes** | yes / yes / yes | 16 / 13 / 26 | 4 / 5 / 10 |
| 10 rename across files | C | **yes** / **yes** / **yes** | yes / yes / yes | 16 / 17 / 15 | 0 / 1 / 0 |

| Seed | Passed | Valid calls | Executed OK | Finished | Turns | Wall time | Tokens (prompt / output) |
|---|---|---|---|---|---|---|---|
| 42 | 9/10 | 166/166 (100%) | 143/166 (86%) | 8/10 | 166 | 4.4 min | 608,807 / 19,568 |
| 1 | 8/10 | 174/174 (100%) | 119/174 (68%) | 7/10 | 174 | 4.0 min | 597,432 / 16,786 |
| 2 | 10/10 | 161/161 (100%) | 136/161 (84%) | 10/10 | 161 | 3.9 min | 545,719 / 16,872 |

**Totals: 27/30 passed (9, 8 and 10 of 10). 100% valid tool calls (501 of 501), all parsed natively, no turn without a tool call. 79% executed without error (398 of 501).** Every seed clears the go/no-go above on its own (≥ 95% valid, ≥ 7/10 passed). **Devstral-Small-2507 Q4_K_M on llama.cpp is a go**, with the pinned chat template.

What it shows:

- **The GGUF's embedded chat template has no tool support. This was the blocker on llama.cpp.** The template inside Mistral's first-party GGUF has no `[AVAILABLE_TOOLS]` or `[TOOL_CALLS]`, and it raises on a `tool`-role message. `llama-server --jinja` drops the `tools` array without an error. On the first attempt the model answered in prose and made **0 tool calls** on task 01 ([report](results/gov-10-devstral-gpu/llamacpp-q4km/embedded-template/)). llama.cpp ships and tests a correct template for this model. The lock now pins it (path, size, sha256, source commit), `govcode model verify` checks it, and `deploy/llamacpp/serve.sh` passes it with `--chat-template-file`. With it, the same task passed with 9 of 9 native calls. Ollama had its own template problem, covered in the next section. This is the same class of problem Granite had in GOV-40: check the template before blaming the model.
- **`serve.sh` also needed `-np 1`.** Without it, llama-server splits `-c` across several slots, and each request gets a fraction of `num_ctx`.
- **Tool-call format is solved for this model; what remains is tool use.** No call was malformed, unknown or schema-invalid. 88 of the 103 failed executions are in the Ada and COBOL tasks (06, 08, 09), and the three failed task runs are where they pile up (14 and 26 errors on seed 1). The report records counts, not causes. The likely cause is `edit_file` text that does not match exactly in fixed-column and whitespace-sensitive sources, but these runs do not show that. Capture transcripts with `-verbose` to check it.
- **Passing is not the same as finishing.** Task 01 passed on seeds 42 and 1 at the 30-turn limit without calling `finish`. The checker passed the tree, but `govcode run` would leave that proposal `incomplete`, so it would not reach approval. Count those passes accordingly.
- **The failures are spread out.** Each failure is in a different task, and every task passed in at least two of three runs. On seed 42, task 02 used all 30 turns adding debug prints to `frame.c` and never found that `sum += buf[i]` sign-extends a `char`. The hidden checker, copied over the model's own `test_02.c`, still saw `0xff83`. Seeds 1 and 2 fixed it in 10–11 turns.
- **A fixed seed does not make runs repeatable.** A single-task smoke run at seed 42 finished task 01 in 9 turns. The full run, also at seed 42, took 30. llama.cpp is not bit-for-bit deterministic across runs, and this is why the results above use several seeds.

## Devstral-Small-2507 Q4_K_M on GPU, Ollama (GOV-10)

This is the same GGUF as the llama.cpp runs above, served by Ollama, which is the default backend in `deploy/policy.example.json`. It was staged with `scripts/stage-models.sh`: imported with `deploy/ollama/Modelfile.devstral-small-24b`, and its manifest digest is pinned in the lock.

| | |
|---|---|
| Model | as above: `Devstral-Small-2507-Q4_K_M.gguf`, sha256 `1bcc2b1b…1796` |
| Server | Ollama v0.40.16 (`d63b7026`, release tarball checked against its `sha256sum.txt`), 127.0.0.1:11434, otherwise default server settings. The context was 32768 (`n_ctx` in the server log), set by the Modelfile's `num_ctx` and by govcode on every request. All 41/41 layers on the GPU, f16 KV cache. Manifest digest `72998df8…a2e1e` |
| Sampler | the Modelfile's `temperature 0.15`, `num_ctx 32768`, `num_predict 4096`. Ollama defaults otherwise (top_k 40, top_p 0.9, repeat_penalty 1.0) |
| Throughput | about 84 tokens/s generation |
| govcode | as above, `-backend ollama -model govcode-devstral:24b-q4km`, `-seed` 42 / 1 / 2 |

Raw reports: [`docs/results/gov-10-devstral-gpu/ollama-q4km/`](results/gov-10-devstral-gpu/ollama-q4km/).

| Task | Lang | Passed (42 / 1 / 2) | Finished | Turns | Exec errors |
|---|---|---|---|---|---|
| 01 buffer overflow | C | **yes** / **yes** / **yes** | yes / yes / yes | 22 / 11 / 13 | 2 / 0 / 1 |
| 02 sign extension | C | **yes** / **yes** / **yes** | yes / yes / yes | 13 / 10 / 11 | 0 / 0 / 0 |
| 03 implement CRC | C | **yes** / **yes** / **yes** | yes / yes / yes | 7 / 10 / 10 | 0 / 0 / 0 |
| 04 auto_ptr port | C++ | no / no / **yes** | no / no / yes | 30 / 30 / 12 | 22 / 20 / 0 |
| 05 rule of three | C++ | **yes** / **yes** / **yes** | yes / yes / yes | 10 / 10 / 10 | 0 / 0 / 0 |
| 06 Constraint_Error | Ada | **yes** / no / **yes** | yes / no / yes | 25 / 30 / 28 | 6 / 23 / 6 |
| 07 missing body | Ada | **yes** / **yes** / **yes** | yes / yes / yes | 14 / 15 / 12 | 3 / 4 / 2 |
| 08 PIC truncation | COBOL | no / **yes** / no | no / yes / no | 30 / 25 / 30 | 8 / 6 / 14 |
| 09 PERFORM VARYING | COBOL | no / no / no | no / no / no | 30 / 30 / 30 | 15 / 26 / 27 |
| 10 rename across files | C | **yes** / **yes** / **yes** | yes / yes / yes | 19 / 17 / 15 | 0 / 0 / 0 |

| Seed | Passed | Valid calls | Executed OK | Finished | Turns | Wall time | Tokens (prompt / output) |
|---|---|---|---|---|---|---|---|
| 42 | 7/10 | 200/200 (100%) | 144/200 (72%) | 7/10 | 200 | 4.0 min | 660,383 / 18,731 |
| 1 | 7/10 | 188/188 (100%) | 109/188 (58%) | 7/10 | 188 | 4.2 min | 618,571 / 19,593 |
| 2 | 8/10 | 171/171 (100%) | 121/171 (71%) | 8/10 | 171 | 3.8 min | 561,227 / 17,910 |

**Totals: 22/30 passed (7, 7 and 8 of 10). 100% valid tool calls (559 of 559), all parsed natively. 67% executed without error (374 of 559).** Every seed meets the go/no-go, but only just. **Ollama is a marginal go.**

What it shows:

- **With the Modelfile as it was, Ollama got 0 tool calls.** The template rendered calls in the old `[TOOL_CALLS][{"name":…}]` form. Ollama builds its tool-call parser from that rendering, while Devstral-Small-2507 writes `[TOOL_CALLS]name[ARGS]{…}`. Ollama returned the text with no `tool_calls` ([report](results/gov-10-devstral-gpu/ollama-q4km/old-template/)). The template also listed the tools only while a user message was among the last two, so they dropped out after the first tool result. The Modelfile now renders the v11 form and lists the tools before the last user message.
  - **Structure matters as well as text.** On Ollama v0.40.16, calls were parsed only with the `range .ToolCalls` inside `if .ToolCalls`. A bare `range` rendered the same prompt and parsed nothing.
  - The fixed template was checked on a streamed reply too, since `govcode run` streams.
  - The fix changes the manifest digest, so staging must be re-run.
- **Same weights as llama.cpp, clearly lower scores, and the cause is not established.** llama.cpp passed 27/30 with 79% executed without error. Ollama passed 22/30 with 67%. The losses are concentrated in 09 (failed on every seed, 68 failed executions) and 04 (failed twice).
  - **Ruled out:** offload (all layers on the GPU), context (32k, f16 KV) and repeat penalty (1.0 on both). Sampler defaults differ slightly (top_p 0.9 against 0.95, min_p 0 against 0.05) but matter little at temperature 0.15.
  - **Not compared:** how each server renders the prompt. Ollama's tool-list placement, tool-result framing and `{{ $.Tools }}` serialization differ from llama.cpp's Jinja template.
- **Recommendation:** serve Devstral with llama.cpp or vLLM until the Ollama gap is understood. Ollama works, but it has the least margin.

## Still to measure

- Qwen3-Coder-30B-A3B. It is CN-origin and runs only where the AO has granted an exception, so it was not run.
- The vLLM backend for Devstral, which comes with the GOV-9 staging work.
- Why Ollama scores below llama.cpp on the same GGUF: compare the rendered prompts.
- An air-gapped GPU run on the RHEL target host (GOV-39).

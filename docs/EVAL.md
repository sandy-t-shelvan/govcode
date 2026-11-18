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

## Still to measure

The target models (Devstral-Small-2507, and Qwen3-Coder where excepted) have **not** been run. Run the commands above on the GPU host; on that hardware the 10 tasks should take minutes, not the 3 hours this CPU run took.

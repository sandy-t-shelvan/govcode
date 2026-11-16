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
govcode eval -backend ollama -endpoint http://127.0.0.1:11434 -model govcode-qwen3-coder:30b-q4km -num-ctx 32768
```

The same eval against Devstral on vLLM:

```bash
govcode eval -backend openai -endpoint http://127.0.0.1:8000/v1 -model devstral-small-24b -num-ctx 32768 -temperature 0.15
```

Results go to `eval/results/<time>-<model>.json` and `.md`.

## Metrics

| Metric | Meaning |
|---|---|
| **valid tool calls** | Share of emitted calls that named a real tool *and* had schema-valid arguments. This is the core "can it call tools" number. |
| executed without error | The call ran and the tool succeeded; for example, `old_text` matched the file exactly. A low value with high validity usually means whitespace or column mistakes in edits. |
| parse path | `native`, or which text fallback recovered the call (`qwen-xml`, `hermes`, `mistral`, `json`). |
| no-call turns | Replies with prose and no tool call. govcode nudges up to 3 times, then stops. |
| tasks passed | The hidden checker passed on the final tree. |
| finished | The model called `finish` and the test gate accepted it. |

Suggested go/no-go for the one-week proof: **valid tool calls ≥ 95%** and **tasks passed ≥ 7/10** for the chosen model and quantization. If validity is high but executed-without-error is low, check the edit failures in the JSON before blaming the model.

## Not yet measured

The development container has no GPU and 15 GB of RAM, and its permissions did not allow building llama.cpp, so the target models have **not** been run there. The harness, the tasks and the scoring are complete and tested. The first real numbers come from running the commands above on the target hardware.

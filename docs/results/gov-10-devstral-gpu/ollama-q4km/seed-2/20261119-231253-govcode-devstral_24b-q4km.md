# govcode eval: govcode-devstral:24b-q4km

- num_ctx: 32768
- started: 2026-11-19T23:12:30Z
- **tasks passed: 8/10**
- **valid tool calls: 100%** (171/171)
- executed without error: 71%
- parse path: native=171

| task | lang | pass | finished | turns | calls | valid | exec err | no-call | stop |
|---|---|---|---|---|---|---|---|---|---|
| 01-c-buffer-overflow | C | true | true | 13 | 13 | 100% | 1 | 0 | finished |
| 02-c-sign-extension | C | true | true | 11 | 11 | 100% | 0 | 0 | finished |
| 03-c-implement-crc | C | true | true | 10 | 10 | 100% | 0 | 0 | finished |
| 04-cpp-auto-ptr | C++ | true | true | 12 | 12 | 100% | 0 | 0 | finished |
| 05-cpp-rule-of-three | C++ | true | true | 10 | 10 | 100% | 0 | 0 | finished |
| 06-ada-constraint-error | Ada | true | true | 28 | 28 | 100% | 6 | 0 | finished |
| 07-ada-missing-body | Ada | true | true | 12 | 12 | 100% | 2 | 0 | finished |
| 08-cobol-pic-truncation | COBOL | false | false | 30 | 30 | 100% | 14 | 0 | max_turns |
| 09-cobol-perform-varying | COBOL | false | false | 30 | 30 | 100% | 27 | 0 | max_turns |
| 10-c-rename-across-files | C | true | true | 15 | 15 | 100% | 0 | 0 | finished |

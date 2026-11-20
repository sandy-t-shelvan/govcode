# govcode eval: govcode-devstral:24b-q4km

- num_ctx: 32768
- started: 2026-11-19T23:08:19Z
- **tasks passed: 7/10**
- **valid tool calls: 100%** (188/188)
- executed without error: 58%
- parse path: native=188

| task | lang | pass | finished | turns | calls | valid | exec err | no-call | stop |
|---|---|---|---|---|---|---|---|---|---|
| 01-c-buffer-overflow | C | true | true | 11 | 11 | 100% | 0 | 0 | finished |
| 02-c-sign-extension | C | true | true | 10 | 10 | 100% | 0 | 0 | finished |
| 03-c-implement-crc | C | true | true | 10 | 10 | 100% | 0 | 0 | finished |
| 04-cpp-auto-ptr | C++ | false | false | 30 | 30 | 100% | 20 | 0 | max_turns |
| 05-cpp-rule-of-three | C++ | true | true | 10 | 10 | 100% | 0 | 0 | finished |
| 06-ada-constraint-error | Ada | false | false | 30 | 30 | 100% | 23 | 0 | max_turns |
| 07-ada-missing-body | Ada | true | true | 15 | 15 | 100% | 4 | 0 | finished |
| 08-cobol-pic-truncation | COBOL | true | true | 25 | 25 | 100% | 6 | 0 | finished |
| 09-cobol-perform-varying | COBOL | false | false | 30 | 30 | 100% | 26 | 0 | max_turns |
| 10-c-rename-across-files | C | true | true | 17 | 17 | 100% | 0 | 0 | finished |

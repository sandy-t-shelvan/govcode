# govcode eval: govcode-devstral:24b-q4km

- num_ctx: 32768
- started: 2026-11-19T23:04:17Z
- **tasks passed: 7/10**
- **valid tool calls: 100%** (200/200)
- executed without error: 72%
- parse path: native=200

| task | lang | pass | finished | turns | calls | valid | exec err | no-call | stop |
|---|---|---|---|---|---|---|---|---|---|
| 01-c-buffer-overflow | C | true | true | 22 | 22 | 100% | 2 | 0 | finished |
| 02-c-sign-extension | C | true | true | 13 | 13 | 100% | 0 | 0 | finished |
| 03-c-implement-crc | C | true | true | 7 | 7 | 100% | 0 | 0 | finished |
| 04-cpp-auto-ptr | C++ | false | false | 30 | 30 | 100% | 22 | 0 | max_turns |
| 05-cpp-rule-of-three | C++ | true | true | 10 | 10 | 100% | 0 | 0 | finished |
| 06-ada-constraint-error | Ada | true | true | 25 | 25 | 100% | 6 | 0 | finished |
| 07-ada-missing-body | Ada | true | true | 14 | 14 | 100% | 3 | 0 | finished |
| 08-cobol-pic-truncation | COBOL | false | false | 30 | 30 | 100% | 8 | 0 | max_turns |
| 09-cobol-perform-varying | COBOL | false | false | 30 | 30 | 100% | 15 | 0 | max_turns |
| 10-c-rename-across-files | C | true | true | 19 | 19 | 100% | 0 | 0 | finished |

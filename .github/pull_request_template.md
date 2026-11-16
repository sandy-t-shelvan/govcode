## Jira

GOV-<n>: <story title>

## What and why

<!-- One paragraph: the change and the reason for it. -->

## Security impact

<!-- Tick every box that applies and explain each one below. "None" is a valid answer. -->
- [ ] Touches the network path (`internal/netguard`, `internal/llm`)
- [ ] Touches the sandbox, the path jail or command permissions
- [ ] Touches the audit log, signing, keyring or identity
- [ ] Touches approval, the two-person rule or policy loading
- [ ] Adds a dependency (Go module, npm package or system tool); the SBOM must be updated
- [ ] Changes what is sent to the model (prompt, tool output, memory files)

## Test evidence

<!-- Commands you ran and their results; new tests added. -->

## Definition of Done

- [ ] Acceptance criteria in the Jira story are met
- [ ] Unit tests cover the new behaviour, including failure and attack cases
- [ ] Fuzz target added or updated if the change parses untrusted input
- [ ] All CI jobs green: lint, security, test (race + coverage floor), fuzz, release
- [ ] Docs updated (README / docs/*) where behaviour or operations change
- [ ] No secrets, classified markings or real customer code in the diff

# govcode for VS Code

A thin editor UI for **govcode**, the air-gapped coding agent. The extension starts `govcode serve --stdio` as you, and talks to it over its stdin and stdout pipes. It opens no sockets and makes no network connections.

- **Agent panel**: describe a task, optionally plan first, and watch tool activity live. The classification banner is shown at the top and bottom.
- **Permission prompts**: when site policy says "ask", you decide in a modal dialog.
- **Proposals view**: lists proposals with their status, an integrity check, and any blocked reasons. Click a file to review base against head in VS Code's diff editor.
- **Approve** opens an integrated terminal running `govcode approve <id>`. You type `approve` there, and govcode enforces the two-person rule and the integrity checks. The extension cannot approve anything itself.
- **Verify Audit Log**: checks the hash chain, signatures and commit anchors.

Settings: `govcode.binaryPath` (the signed binary) and `govcode.policyPath`.

Install offline:

```bash
code --install-extension govcode-<version>.vsix
```

On classified workstations, set `"extensions.autoUpdate": false` and `"extensions.autoCheckUpdates": false`, and block the marketplace through your VS Code enterprise policy.

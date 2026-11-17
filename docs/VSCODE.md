# govcode in VS Code

## Install (offline)

1. Take `vscode/govcode-<version>.vsix` from the signed release directory. Verify the release first, as described in DEPLOYMENT.md §1; the VSIX's SHA-256 is in `manifest.json` and the SBOM.
2. Install it:
   ```bash
   code --install-extension govcode-<version>.vsix
   ```
3. Workstation settings, ideally pushed by your VS Code enterprise policy:
   ```json
   {
     "extensions.autoUpdate": false,
     "extensions.autoCheckUpdates": false,
     "govcode.binaryPath": "/opt/govcode/bin/govcode",
     "govcode.policyPath": "/etc/govcode/policy.json"
   }
   ```
   Block marketplace access in the same policy.

## Use

- **govcode: Open Agent Panel** (or click the classification badge in the status bar): describe the task, optionally tick **Plan first**, then click **Run**. Model text and tool activity stream live. Spillage-guard events show in bold.
- **Permission prompts** appear as modal dialogs whenever policy says "ask". **Plan review** is a modal dialog with Approve or Reject; on reject you're asked for feedback, which goes back to the model.
- **Proposals** view (shield icon in the activity bar): each proposal shows its integrity status, any blocked reasons, and its files. Click a file to review base against head in the diff editor.
- **Approve** (right-click a ready proposal) opens an integrated terminal running `govcode approve <id>`. Type `approve` there. govcode checks the two-person rule, both signatures, the branch and the diff hash, then lands the change. The extension itself cannot approve.
- **Reject** asks for a reason. **Verify Audit Log** prints the result to the govcode output channel.

## Security properties

| Property | How |
|---|---|
| No network | Talks only to the child process's stdin/stdout. CI fails if the code requires `http`, `https`, `net`, `tls`, `dgram` or `dns`, or uses `fetch`, `XMLHttpRequest` or `WebSocket`. |
| No supply-chain additions | Plain JavaScript, zero npm dependencies, no build step. The VSIX is built reproducibly with `zip` and listed in the SBOM. |
| Webview cannot load remote content | CSP `default-src 'none'`, `connect-src 'none'`, scripts only by nonce. Model output is inserted with `textContent`, never as HTML. |
| Cannot be tricked into approving | Proposal IDs are validated against govcode's exact format before going into the terminal command line, and the binary path is shell-quoted. Approval itself needs a human to type on a TTY. |
| Workspace trust | `untrustedWorkspaces.supported: false`: the extension does nothing in an untrusted folder. |
| Runs where the code is | `extensionKind: workspace`; govcode runs as the VS Code user, under the same root-owned policy as the CLI. |

## Not yet verified

The extension's unit tests run against a mocked VS Code API, and its integration test runs against the real `govcode serve --stdio`. `scripts/e2e/vscode-real.sh <unpacked-vscode-dir> [govcode]` also runs it inside a **real VS Code** (validated with 1.95.3, headless under xvfb) against the real server and a replayed model. It checks activation, commands, a run to a ready proposal, the proposals tree, the diff view, the panel, audit verify, that approval is not reachable from the extension, and reject. CI runs it on every change. As part of site acceptance, install the VSIX in the site's own VS Code build and repeat the review flow by hand, including a remote/SSH workspace if you use one.

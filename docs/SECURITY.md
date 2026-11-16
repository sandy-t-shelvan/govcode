# Security design

## Threat model

| Actor | Assumed capability | Goal we prevent |
|---|---|---|
| **The model** | Fully untrusted; may be prompt-injected by repository content | Changing code outside the repo, exfiltrating code, landing code unreviewed, hiding its actions |
| **A developer (proposer)** | Legitimate user of one repo; controls their own account | Landing their own change without a second person; forging another user's signature; editing history or the log afterwards |
| **An approver** | Legitimate user | Approving something other than what they reviewed |
| **Supply chain** | Modified binary, weights or dependencies in transit | Running unapproved code or models |
| **root / ISSO** | Trusted | Not defended against; root can change anything on the host. Mitigate with your site's privileged-user monitoring and offline log backups |

## Requirement → control

### 1. Local model, no cloud
- No provider SDKs at all. `internal/netguard` is the only HTTP client: it resolves the target, refuses anything that is not loopback, ignores `HTTP(S)_PROXY`, and refuses redirects off the host.
- `internal/supply/nonetwork_test.go` fails the build if any package other than `netguard`/`llm` imports `net`, `net/http` or `crypto/tls`, if anything calls `http.Get`, `http.DefaultClient`, `net.Dial` and similar, or if any third-party module is imported.
- The policy rejects non-loopback model endpoints. The Ollama systemd unit adds `IPAddressDeny=any`. The vLLM launcher sets `HF_HUB_OFFLINE`, `TRANSFORMERS_OFFLINE`, `VLLM_NO_USAGE_STATS` and `DO_NOT_TRACK`.
- Agent commands run in a bubblewrap sandbox with `--unshare-all`: there is no network namespace beyond loopback, and no DNS.

### 2. Agent confined to one repo
- The policy names exactly one `repo_root`; govcode refuses to run anywhere else.
- Each run gets its own git worktree. Every file path goes through `tools.Jail`: absolute paths outside the worktree, `..` escapes, symlinks pointing out, `.git` and `.govcode` are all refused.
- Commands see the system directories read-only and the worktree read-write. They do not see `$HOME` (where signing keys live), other repositories, the policy, or the audit log; `state_dir` must be outside `repo_root`. The process group is killed on timeout.
- A command outside the allowlist needs a typed `y` on `/dev/tty`, so piped input cannot approve it. An allowlisted prefix only auto-approves the simple case: any `;`, `&&`, `|`, `$( )`, backticks or redirection sends the command back to the human.
- Commits use `core.hooksPath=/dev/null` and `--no-verify`, so hooks the model wrote never run.
- Only files edited through the edit tools go into the proposal. Build outputs and other side effects are listed in the audit log but not committed.

### 3. Attribution and provenance (audit log)
- Every model request and response, tool call and result, command and its output, test run, proposal, approval, rejection and landing is an entry.
- Entry hash = SHA-256 over the canonical JSON of the entry, which includes `prev`, the previous entry's hash. The entry is signed with Ed25519 by the acting user's key. Large content goes to a content-addressed object store referenced by hash.
- `audit verify` detects modified, inserted, deleted or reordered entries; keys missing from the keyring; impersonation (the actor field does not match the key owner); and corrupted objects.
- **Truncation** of the newest entries cannot be detected from the chain alone. It is detected through anchors: every landed commit carries `Govcode-Audit-Anchor: <seq>:<hash>`, and `audit verify` checks that every anchor in the target branch's history is in the log. A log cut back to before a landed change therefore fails verification.
- `chattr +a` (checked through the `FS_IOC_GETFLAGS` ioctl) makes the log append-only even for its owner. `audit.require_append_only` makes govcode refuse to run without it.
- Every entry carries the policy's classification marking. **The log and its objects are classified at the level of the code they record.** They contain prompts, code and diffs. Store, back up, mark and destroy them accordingly. Nothing in them leaves the host.

### 4. Supply chain
See [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md). In strict mode the binary refuses to start unless its own SHA-256 is in a manifest signed by a trusted release key, the model lock signature verifies, and the model Ollama serves has the pinned manifest digest.

### 5. Human approval and separation of duties
- `run` only ever writes to `govcode/proposal/<id>`. The proposal record pins the base, head and diff SHA-256, and the proposer signs it.
- `approve` checks, in order:
  1. The proposal is `ready`: the agent finished and the tests passed after its last edit.
  2. The approver is in `approvers`.
  3. Under the two-person rule, the approver's uid is not the proposer's.
  4. The proposer's signature verifies with the proposer's uid-bound key.
  5. The branch still points at the signed head.
  6. The diff still hashes to the signed value.
  7. The proposal has not been decided before; decisions are created exclusively.
  8. The human types `approve` on `/dev/tty`.

  The audit entry is written **before** the merge commit, so a landed change can never lack a log entry. The target ref moves with a compare-and-swap.
- Identity is the kernel's real uid (`os.Getuid`), never `$USER`. govcode runs as the invoking user and has no setuid component.
- `sensitive: true` forces `two_person_rule: true`. In strict mode the policy must be root-owned and not writable by others, and unknown fields are rejected.

## Known limitations (read before an ATO)

1. **Signing keys are files.** A user's key is protected by file permissions (0600, owner check). Anyone with that user's uid, or root, can sign as them. To bind keys to a person, put them on a PIV/CAC token or an HSM. The `sign.Signer` interface is the integration point; a PKCS#11 signer is not implemented yet.
2. **FIPS.** The release build links Go Cryptographic Module v1.0.0 in FIPS 140-3 mode (`GOFIPS140=v1.0.0`; `GODEBUG=fips140=on` is the default). The Go 1.27.4 toolchain lists v1.0.0 as certified (`lib/fips140/certified.txt`). Your crypto reviewer should still record the CMVP certificate number in the ATO package.
3. **Truncation detection needs landed commits.** Activity after the last landed commit, such as proposals that were rejected or never decided, is protected by the chain and `chattr +a` but has no git anchor. Copy the log head (`govcode audit verify` prints it) to WORM media or your SIEM on a schedule.
4. **The sandbox depends on the kernel.** Without unprivileged user namespaces, `sandbox.mode: required` refuses to run, which is correct. `best-effort` falls back to running commands unsandboxed and records `sandbox=none` in the audit log.
5. **The model can be wrong.** The approval step is the control. The test gate and the diff review reduce risk but do not replace code review.
6. **Root is trusted.** A malicious administrator can remove `chattr +a`, replace the binary, or edit the keyring. That is out of scope for an application and in scope for your host controls.
7. **Regulatory mapping.** The attribution and provenance requirement you cited (DoWI 8430.01) has not been mapped clause by clause here. The controls above produce the evidence: who requested, what the model did, when, who approved, and a tamper-evident record. Have your compliance reviewer map them to the instruction's exact text.

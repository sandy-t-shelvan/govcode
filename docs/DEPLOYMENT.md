# High-side deployment (ISSO / administrator)

This guide installs govcode for one repository on a closed network. Run every command as root unless it says otherwise. Paths match `deploy/policy.example.json`.

## 0. What crosses the boundary

Prepare both items on the low side, then transfer them through your approved cross-domain process or media-transfer procedure:

1. **Release directory** `govcode-<version>/`, built with `scripts/build-release.sh`. It contains the binary, `manifest.json` and its `.sig`, `sbom.cdx.json`, `aibom.cdx.json`, the model lock, `deploy/` and `docs/`.
2. **Staged model directory**, built with `scripts/stage-models.sh`. It contains `models.lock.json` and its `.sig`, `weights/*.gguf`, `SHA256SUMS` and its `.sig`, `aibom.cdx.json`, and the `Modelfile.*` files.

The two **public** keys (`release.pub`, `models.pub`) also cross. Their fingerprints are confirmed out of band, for example read aloud and checked against `govcode keygen`'s key id. Private keys never cross.

## 1. Verify before installing

```bash
sha256sum -c govcode-0.1.0/SHA256SUMS
```

```bash
govcode-0.1.0/bin/govcode model verify -dir /media/xfer/models -key /media/xfer/models.pub
```

The second command checks the lock signature and then re-hashes every weight file, which takes several minutes for 18 GB. Do not load anything into the model server until it prints `all artifacts match the lock`.

## 2. Install

```bash
install -d -m 755 /opt/govcode/bin /opt/govcode/models /etc/govcode/trust /etc/govcode/keys
```

```bash
install -m 755 govcode-0.1.0/bin/govcode /opt/govcode/bin/govcode && ln -sf /opt/govcode/bin/govcode /usr/local/bin/govcode
```

```bash
install -m 644 govcode-0.1.0/manifest.json govcode-0.1.0/manifest.json.sig /opt/govcode/
```

```bash
install -m 644 /media/xfer/release.pub /media/xfer/models.pub /etc/govcode/trust/
```

```bash
cp -r /media/xfer/models/. /opt/govcode/models/ && chmod -R a-w /opt/govcode/models
```

System dependencies (listed in the SBOM): `git` ≥ 2.38, `bubblewrap`, `bash`, the model server, and your compilers (gcc/g++, GNAT, GnuCOBOL, gfortran). bubblewrap needs unprivileged user namespaces (`sysctl kernel.unprivileged_userns_clone=1` on Debian-family systems; on RHEL check `user.max_user_namespaces`).

## 3. Model server (Ollama, loopback only)

```bash
install -m 644 govcode-0.1.0/deploy/ollama/govcode-ollama.service /etc/systemd/system/ollama.service && systemctl daemon-reload && systemctl enable --now ollama
```

```bash
cd /opt/govcode/models && sudo -u ollama ollama create govcode-devstral:24b-q4km -f Modelfile.devstral-small-24b
```

```bash
curl -s http://127.0.0.1:11434/api/tags
```

The digest that Ollama reports must equal `serve.ollama_manifest_digest` in the lock. The staging host recorded that digest by importing the same GGUF with the same Modelfile and the same Ollama version. If the digests differ, the Modelfile or the Ollama version differs from staging; fix that rather than editing the lock. govcode checks the digest on every start when `verify_digest` is true.

`num_ctx` is set in three places, and all three must agree: the Modelfile (`PARAMETER num_ctx 32768`), the lock (`serve.num_ctx`), and the policy (`model.num_ctx`). govcode also sends `num_ctx` on every request through Ollama's native `/api/chat` endpoint (the `/v1` OpenAI shim ignores it), and refuses to start if the policy and the lock disagree.

For vLLM or llama.cpp instead, use `deploy/vllm/serve.sh` or `deploy/llamacpp/serve.sh`. Both verify the weights first and bind to 127.0.0.1. Set `model.backend` to `openai` and `model.endpoint` to `http://127.0.0.1:8000/v1` (vLLM) or `http://127.0.0.1:8080/v1` (llama.cpp).

Hardware for a 32k context at Q4_K_M:

| Model | Weights | KV cache (32k, fp16) | Fits |
|---|---|---|---|
| Qwen3-Coder-30B-A3B (MoE, 3B active) | 18.6 GB | ~3 GB | one 24 GB GPU (tight) or 48 GB; usable on CPU with ≥ 32 GB RAM because only 3B parameters are active per token |
| Devstral-Small-2507 (24B dense) | 14.3 GB | ~5 GB | one 24 GB GPU |

## 4. Repository, users and shared state

Proposers and approvers share the repository and the state directory through a group. Nobody else gets access, and nothing is world-readable: the state is classified at the level of the code.

```bash
groupadd govcode-radar && usermod -aG govcode-radar jdoe && usermod -aG govcode-radar asmith && usermod -aG govcode-radar dev1
```

```bash
git -C /srv/git/work/radar-fw config core.sharedRepository group && chgrp -R govcode-radar /srv/git/work/radar-fw && chmod -R g+rwX,o-rwx /srv/git/work/radar-fw
```

```bash
install -d -m 2770 -g govcode-radar /var/lib/govcode/radar-fw /var/lib/govcode/radar-fw/audit
```

```bash
install -m 660 -g govcode-radar /dev/null /var/lib/govcode/radar-fw/audit/log.jsonl && chattr +a /var/lib/govcode/radar-fw/audit/log.jsonl
```

`chattr +a` means that even the file's owner can only append; only root can remove the flag. With `audit.require_append_only: true`, govcode refuses to run if the flag is missing. Back the log up to WORM media on your normal schedule. Its objects directory (`audit/objects/`) holds the full content and must be backed up too.

## 5. Keys

Each user generates their own key, and the private half never leaves their home directory:

```bash
govcode keygen
```

Run that command as the user, not as root. The user then gives `~/.config/govcode/signing.pub` to the ISSO, who installs it as root:

```bash
install -m 644 /tmp/jdoe-signing.pub /etc/govcode/keys/jdoe.pub
```

The keyring trusts `<user>.pub` only if the file is owned by root or by that user's own uid, and is not group- or world-writable. That ownership binding is what stops one person from signing as another. To rotate a key, add `jdoe.2.pub`; once old entries no longer need verifying, remove the old file.

## 6. Policy

```bash
install -m 644 -o root -g root govcode-0.1.0/deploy/policy.example.json /etc/govcode/policy.json
```

Edit `repo_root`, `state_dir`, `approvers`, `classification`, the test command and the allowlist. In strict mode govcode refuses a policy that is not root-owned or that is group- or world-writable, so a developer cannot add themselves as an approver. Unknown fields are rejected, so a typo cannot silently disable a control.

## 7. Acceptance

As a developer, and then as an approver:

```bash
cd /srv/git/work/radar-fw && govcode verify
```

Every line must read PASS. Then run one proposal through to approval, and finish with:

```bash
govcode audit verify
```

For a full scripted acceptance test with three users, use `scripts/e2e/two-person.sh` on a **disposable** VM; it creates OS users. That script has not been run in the development environment. Run it as part of site acceptance.

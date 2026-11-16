# Supply chain: what the reviewer checks

## The binary

| Check | How |
|---|---|
| No third-party code | `go version -m bin/govcode` lists **zero** `dep` lines. `go.mod` has no `require`, and there is no `go.sum`. The test `TestGoModHasNoRequires` enforces this. |
| No hidden network | `TestNoHiddenNetwork` fails the build if anything but `netguard`/`llm` imports a network package or bypasses the loopback-only client. A planted `http.Get` was confirmed to fail it. |
| No downloads at build time | `scripts/build-release.sh` sets `GOPROXY=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local`. |
| Reproducible | The script builds twice and fails if the two SHA-256s differ (`-trimpath -buildvcs=false -ldflags=-buildid=`, `CGO_ENABLED=0`). Rebuild from the same commit with the same Go version to get the same hash. |
| FIPS 140-3 crypto | `GOFIPS140=v1.0.0` links Go Cryptographic Module v1.0.0, which the Go 1.27.4 toolchain lists as **certified** (`$(go env GOROOT)/lib/fips140/certified.txt` → `v1.0.0-c2097c7c`); `go version -m` shows `DefaultGODEBUG=fips140=on`. Ed25519 (FIPS 186-5) and SHA-256 are the only algorithms in use. Record the CMVP certificate number in the ATO package. |
| Patched toolchain | `go.mod` requires Go `1.27.4`, so older toolchains refuse to build. Go 1.24.7 had 36 reachable standard-library vulnerabilities; govulncheck reports none for 1.27.4 and runs in CI on every PR. |
| Signed | `manifest.json` lists every file in the release with its SHA-256 and is signed with the release key (`manifest.json.sig`). |
| Self-check at runtime | In strict mode, `govcode` hashes its own executable and refuses to run unless that hash is in the signed manifest. |

Build a release on a clean, connected-but-controlled build host:

```bash
govcode keygen -o /secure/release.key
```

```bash
scripts/build-release.sh 0.1.0 /secure/release.key
```

## SBOM

`govcode sbom -lock models/models.lock.json -o sbom.cdx.json` writes CycloneDX 1.6 with:

- **govcode**: version, SHA-256 of the running binary, build settings from the embedded build info.
- **go-stdlib**: the Go version linked in.
- **System tools** govcode invokes (git, bubblewrap, bash, ollama, llama-server, vllm): resolved path, version string and SHA-256 **on the host where the command runs**. Re-run `govcode sbom` on the high-side host, and compare its system-tool hashes against the site baseline.
- **Models**: from the lock (see below).

## Models

### Pins (`models/models.lock.json`)

| Model | Upstream (first party) | Revision | Served artifact |
|---|---|---|---|
| Qwen3-Coder-30B-A3B-Instruct | `Qwen/Qwen3-Coder-30B-A3B-Instruct` | `b2cff646eb4bb1d68355c01b18ae02e7cf42d120` | Q4_K_M GGUF quantized by us with llama.cpp `b12447` (`a06044b9…`) |
| Devstral-Small-2507 | `mistralai/Devstral-Small-2507` | `bd165ab26cebbcc2eea2c4ecbfc07f3ac42b3c39` | first-party `mistralai/Devstral-Small-2507_gguf@ee2f0c00…` Q4_K_M, SHA-256 `1bcc2b1b…1796` |

Every upstream weight shard is pinned by the SHA-256 published in the hub's LFS metadata at that exact revision: 16 shards for Qwen and 10 for Devstral. Small text files (tokenizer, config, chat template) are pinned by git blob id; staging verifies them and records their SHA-256. A third-party Qwen GGUF (`unsloth`, revision `b17cb02d…`) is listed as `reference_prequantized` only. Self-quantizing from first-party weights is the default because it keeps the provenance chain first-party.

Fields marked `FILL_AT_STAGING` cannot be known before staging: the SHA-256 of the GGUF we produce, and the Ollama manifest digest. `govcode model verify` and the preflight treat an unfilled hash as a **failure**.

### Pipeline

```
LOW SIDE                                                    HIGH SIDE
scripts/stage-models.sh out/ models-signing.key
  download at pinned revision ── verify every SHA-256
  build llama.cpp at pinned commit ── convert ── quantize Q4_K_M
  hash GGUF ── ollama create ── record manifest digest
  write aibom.cdx.json ── sign models.lock.json, aibom, SHA256SUMS
                       ── transfer out/ + models.pub ──▶     govcode model verify -dir … -key models.pub
                                                            ollama create … (same Modelfile)
                                                            govcode verify  (digest + lock signature at every start)
```

### AI-BOM

`govcode aibom -lock models.lock.json` writes CycloneDX 1.6 `machine-learning-model` components with:

- the served artifact's hashes;
- the first-party upstream weights as `pedigree.ancestors`, each shard with its SHA-256;
- the license (Apache-2.0 for both models);
- a `modelCard` (task, considerations, the context-length limit);
- the serving parameters (`num_ctx`, tool-call parser, Ollama digest) as properties.

## Model server hardening

- **Ollama** (`deploy/ollama/govcode-ollama.service`): `OLLAMA_HOST=127.0.0.1`, proxy variables cleared, `IPAddressDeny=any` / `IPAddressAllow=localhost`, `ProtectSystem=strict`, `NoNewPrivileges`.
- **vLLM** (`deploy/vllm/serve.sh`): verifies the weights first, `--host 127.0.0.1`, `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, `VLLM_NO_USAGE_STATS=1`, `DO_NOT_TRACK=1`, and the correct `--tool-call-parser` (`qwen3_coder` or `mistral`).
- **llama.cpp** (`deploy/llamacpp/serve.sh`): verifies first, `--host 127.0.0.1`, `--jinja` for native tool templates, no web UI.

Pinned server versions: Ollama `v0.40.16` (`d63b7026…`), vLLM `v0.34.0` (`0c57b419…`), llama.cpp `b12447` (`a06044b9…`). Each server is its own SBOM subject: get its vendor SBOM, or generate one when you build it.

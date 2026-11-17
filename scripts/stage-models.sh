#!/usr/bin/env bash
# stage-models.sh — LOW SIDE (connected staging host) only.
#
# Downloads the pinned model revisions, verifies every upstream SHA-256
# against models/models.lock.json, quantizes Qwen3-Coder with a pinned
# llama.cpp, imports into Ollama to obtain the manifest digest, fills the
# FILL_AT_STAGING fields, writes the AI-BOM, and signs the lock + AI-BOM with
# the model-signing key. The output directory is what crosses the
# cross-domain solution / media transfer to the high side.
#
#   scripts/stage-models.sh <out_dir> <model-signing.key> [model-id ...]
#
# Requires: git, python3 (+ pip for llama.cpp's converter deps), cmake, a C++
# compiler, curl, sha256sum, jq, ollama (same version as the high side), and
# a built govcode binary on PATH (used to sign and to emit the AI-BOM).
#
# Malware scan (required): set GOVCODE_SCAN_CMD to the site's offline scanner,
# run with site-provided signatures, e.g.
#   GOVCODE_SCAN_CMD="clamscan --no-summary --infected --database=/media/sigs"
#   GOVCODE_SCAN_SIGS="daily.cvd 27471, 2026-11-16"
# It must exit 0 for clean files. The scanner, its version, the signature
# version and the result are written into the signed lock and the AI-BOM.
#
# Only GGUF and safetensors weights are staged. Any lock entry naming a
# pickle-based format (.bin .pt .pth .ckpt .pkl ...) is refused before
# anything is downloaded, and every weight file is checked by content.
set -euo pipefail
: "${GOVCODE_SCAN_CMD:?set GOVCODE_SCAN_CMD to the site malware scanner (see the header)}"
SCAN_BIN=${GOVCODE_SCAN_CMD%% *}
SCAN_VERSION=$($SCAN_BIN --version 2>&1 | head -n1)

LLAMA_CPP_TAG=b12447
LLAMA_CPP_COMMIT=a06044b934db085e373286444e0c15b93635a20c
OUT=${1:?out dir}; KEY=${2:?signing key}; shift 2
IDS=("$@"); [ ${#IDS[@]} -eq 0 ] && IDS=(devstral-small-24b qwen3-coder-30b-a3b)
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK_IN=$ROOT/models/models.lock.json
mkdir -p "$OUT/weights" "$OUT/build"
cp "$LOCK_IN" "$OUT/models.lock.json"
LOCK=$OUT/models.lock.json
govcode model sniff -lock "$LOCK"   # refuse pickle-format entries before any download

hf_get() { # repo revision path dest
  curl -fL --retry 5 -C - -o "$4" "https://huggingface.co/$1/resolve/$2/$3"
}
verify() { # file expected_sha256
  local got; got=$(sha256sum "$1" | cut -d' ' -f1)
  [ "$got" = "$2" ] || { echo "SHA-256 MISMATCH $1: got $got want $2" >&2; exit 1; }
}
setlock() { # jq filter
  local t; t=$(mktemp); jq "$1" "$LOCK" > "$t" && mv "$t" "$LOCK"
}

build_llama_cpp() {
  local d=$OUT/build/llama.cpp
  if [ ! -d "$d" ]; then
    git clone --filter=blob:none https://github.com/ggml-org/llama.cpp "$d"
  fi
  git -C "$d" checkout -q "$LLAMA_CPP_COMMIT"
  [ "$(git -C "$d" rev-parse HEAD)" = "$(git -C "$d" rev-parse "$LLAMA_CPP_COMMIT^{commit}")" ]
  cmake -S "$d" -B "$d/build" -DGGML_NATIVE=OFF -DLLAMA_CURL=OFF >/dev/null
  cmake --build "$d/build" -j --target llama-quantize llama-server >/dev/null
  python3 -m venv "$OUT/build/venv"
  "$OUT/build/venv/bin/pip" install -q -r "$d/requirements/requirements-convert_hf_to_gguf.txt"
}

for id in "${IDS[@]}"; do
  echo "== $id"
  m=$(jq -c --arg id "$id" '.models[] | select(.id==$id)' "$LOCK")
  [ -n "$m" ] || { echo "unknown model $id" >&2; exit 1; }
  repo=$(jq -r .upstream.repo <<<"$m"); rev=$(jq -r .upstream.revision <<<"$m")
  src=$OUT/build/$id-src; mkdir -p "$src"

  if [ "$id" = qwen3-coder-30b-a3b ]; then
    # 1. first-party weights at pinned revision, verified
    jq -c '.upstream.files[]' <<<"$m" | while read -r f; do
      p=$(jq -r .path <<<"$f"); want=$(jq -r .sha256 <<<"$f")
      [ -f "$src/$p" ] || hf_get "$repo" "$rev" "$p" "$src/$p"
      if [ "$want" = FILL_AT_STAGING ]; then
        # small file pinned by git blob id: verify that, then record sha256
        blob=$(jq -r .git_blob_sha1 <<<"$f")
        [ "$(git hash-object "$src/$p")" = "$blob" ] || { echo "git blob mismatch $p" >&2; exit 1; }
        sha=$(sha256sum "$src/$p" | cut -d' ' -f1)
        setlock "(.models[]|select(.id==\"$id\")|.upstream.files[]|select(.path==\"$p\")|.sha256) = \"$sha\""
      else
        verify "$src/$p" "$want"
      fi
      case "$p" in *.safetensors|*.gguf) govcode model sniff "$src/$p" ;; esac
    done
    # 2. quantize with pinned llama.cpp
    build_llama_cpp
    L=$OUT/build/llama.cpp
    f16=$OUT/build/$id-F16.gguf
    gguf=$(jq -r '.artifact.files[0].path' <<<"$m")
    "$OUT/build/venv/bin/python" "$L/convert_hf_to_gguf.py" "$src" --outtype f16 --outfile "$f16"
    "$L/build/bin/llama-quantize" "$f16" "$OUT/weights/$gguf" Q4_K_M
    rm -f "$f16"
  else
    # Devstral: first-party GGUF
    arepo=$(jq -r .artifact.repo <<<"$m"); arev=$(jq -r .artifact.revision <<<"$m")
    gguf=$(jq -r '.artifact.files[0].path' <<<"$m"); want=$(jq -r '.artifact.files[0].sha256' <<<"$m")
    [ -f "$OUT/weights/$gguf" ] || hf_get "$arepo" "$arev" "$gguf" "$OUT/weights/$gguf"
    verify "$OUT/weights/$gguf" "$want"
  fi

  govcode model sniff "$OUT/weights/$gguf"

  # Malware scan with the site's offline scanner; any finding stops staging.
  if ! scan_out=$($GOVCODE_SCAN_CMD "$OUT/weights/$gguf" 2>&1); then
    echo "MALWARE SCAN FAILED for $gguf:" >&2; echo "$scan_out" >&2; exit 1
  fi
  setlock "(.models[]|select(.id==\"$id\")|.staging_scan) = {scanner: \"$SCAN_BIN\", version: $(jq -Rn --arg v "$SCAN_VERSION" '$v'), signatures: $(jq -Rn --arg v "${GOVCODE_SCAN_SIGS:-unrecorded}" '$v'), result: \"clean\", scanned_at: \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

  sha=$(sha256sum "$OUT/weights/$gguf" | cut -d' ' -f1); size=$(stat -c %s "$OUT/weights/$gguf")
  setlock "(.models[]|select(.id==\"$id\")|.artifact.files[0]) |= (.sha256=\"$sha\" | .size=$size)"

  # 3. import into Ollama to get the manifest digest the high side will check
  mf=$ROOT/deploy/ollama/Modelfile.$id
  name=$(jq -r .serve.ollama_name <<<"$m")
  ( cd "$OUT/weights" && sed "s#^FROM .*#FROM ./$gguf#" "$mf" > "Modelfile.$id" && ollama create "$name" -f "Modelfile.$id" )
  cp "$OUT/weights/Modelfile.$id" "$OUT/"
  digest=$(curl -fsS http://127.0.0.1:11434/api/tags | jq -r --arg n "$name" '.models[]|select(.name==$n or .name==($n+":latest"))|.digest')
  [ -n "$digest" ] || { echo "could not read ollama digest for $name" >&2; exit 1; }
  setlock "(.models[]|select(.id==\"$id\")|.serve.ollama_manifest_digest) = \"$digest\""
done

if grep -q FILL_AT_STAGING "$LOCK"; then
  echo "NOTE: FILL_AT_STAGING remains for models not staged in this run:" >&2
  jq -r '.models[]|select(tostring|test("FILL_AT_STAGING"))|.id' "$LOCK" >&2
fi

govcode aibom --lock "$LOCK" --out "$OUT/aibom.cdx.json"
govcode sign --key "$KEY" "$LOCK" "$OUT/aibom.cdx.json"
( cd "$OUT" && find weights -type f -name '*.gguf' -exec sha256sum {} + > SHA256SUMS && govcode sign --key "$KEY" SHA256SUMS )
echo "Staged to $OUT. Transfer the whole directory; verify on the high side with: govcode model verify --dir $OUT"

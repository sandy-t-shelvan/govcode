#!/usr/bin/env bash
# Serve a staged model with vLLM v0.34.0 (commit 0c57b4195da4a6b69a7725908e428053e51e51b8),
# loopback only, fully offline. Verifies weights before loading.
#   deploy/vllm/serve.sh <staged_dir> <model-id> [extra vllm args]
# For vLLM, stage the upstream safetensors (or an AWQ/FP8 quant) rather than GGUF.
set -euo pipefail
DIR=${1:?staged dir}; ID=${2:?model id}; shift 2
govcode model verify --dir "$DIR" --model "$ID" -upstream || { echo "model verification failed; refusing to serve" >&2; exit 1; }
LOCK=$DIR/models.lock.json
CTX=$(jq -r --arg id "$ID" '.models[]|select(.id==$id)|.serve.num_ctx' "$LOCK")
PARSER=$(jq -r --arg id "$ID" '.models[]|select(.id==$id)|.serve.vllm_tool_call_parser' "$LOCK")
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_DATASETS_OFFLINE=1
export VLLM_NO_USAGE_STATS=1 DO_NOT_TRACK=1 VLLM_DO_NOT_TRACK=1
export HTTPS_PROXY= HTTP_PROXY= NO_PROXY='*'
EXTRA=()
# Mistral models: use the pinned tekken.json tokenizer. Config and weights stay in
# the Hugging Face format the lock pins (config.json, model-*-of-*.safetensors);
# --config-format/--load-format mistral would look for consolidated*.safetensors,
# which is not staged, and vLLM would find no weights.
[ "$PARSER" = mistral ] && EXTRA+=(--tokenizer-mode mistral)
exec vllm serve "$DIR/weights/$ID" \
  --host 127.0.0.1 --port 8000 \
  --served-model-name "$ID" \
  --max-model-len "$CTX" \
  --enable-auto-tool-choice --tool-call-parser "$PARSER" \
  --disable-log-requests \
  ${EXTRA[@]+"${EXTRA[@]}"} "$@"

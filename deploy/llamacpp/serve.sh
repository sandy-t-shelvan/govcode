#!/usr/bin/env bash
# Serve a staged GGUF with llama.cpp llama-server (tag b12447,
# commit a06044b934db085e373286444e0c15b93635a20c). Single static binary,
# CPU or GPU, loopback only. --jinja enables the model's native tool-call template.
# If the lock pins serve.llamacpp_chat_template, that verified template replaces
# the one embedded in the GGUF: Devstral-Small-2507's first-party GGUF embeds a
# template with no tool support, and llama-server then drops the tools silently.
# -np 1 gives the one session the whole num_ctx; llama-server otherwise splits
# -c across several slots and each request gets a fraction of the context.
#   deploy/llamacpp/serve.sh <staged_dir> <model-id> [extra args]
set -euo pipefail
DIR=${1:?staged dir}; ID=${2:?model id}; shift 2
govcode model verify --dir "$DIR" --model "$ID" || { echo "model verification failed; refusing to serve" >&2; exit 1; }
LOCK=$DIR/models.lock.json
CTX=$(jq -r --arg id "$ID" '.models[]|select(.id==$id)|.serve.num_ctx' "$LOCK")
GGUF=$(jq -r --arg id "$ID" '.models[]|select(.id==$id)|.artifact.files[0].path' "$LOCK")
TMPL=$(jq -r --arg id "$ID" '.models[]|select(.id==$id)|.serve.llamacpp_chat_template.path // empty' "$LOCK")
EXTRA=()
[ -n "$TMPL" ] && EXTRA+=(--chat-template-file "$DIR/weights/$TMPL")
exec llama-server -m "$DIR/weights/$GGUF" --host 127.0.0.1 --port 8080 \
  -c "$CTX" -np 1 --jinja --no-webui -a "$ID" ${EXTRA[@]+"${EXTRA[@]}"} "$@"

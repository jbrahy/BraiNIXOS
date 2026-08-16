#!/bin/bash
#
# Check that the mini is actually serving a model, by asking it to generate.
#
#   ./bin/mini-serving-check.sh          # report
#   ./bin/mini-serving-check.sh --fix    # recover a poisoned backend
#
# WHY A COMPLETION AND NOT /health
#
# `/health` on llama.cpp checks the HTTP loop, nothing more. When the Metal
# backend dies of `kIOGPUCommandBufferCallbackErrorOutOfMemory`, llama.cpp says
# outright that the backend "is in error state from a previous command buffer
# failure - recreate the backend to recover" -- and from then on `/health`
# keeps answering `{"status":"ok"}` while every completion returns
# `500 Compute error`. Ollama is worse: it returns an empty response with
# `done:false` and HTTP 200, so a naive check sees success.
#
# Both servers on this machine were in exactly that state, silently, and a live
# port plus a green /health was the entire basis for believing otherwise.
#
# WHY THEY COLLIDE
#
# The mini is an M2 Pro with 32 GB and `iogpu.wired_limit_mb` of 28672. The
# coder daemon runs a 32B Q4 model with --mlock and pins ~22.8 GB. Ollama
# auto-loads a model on any request to :11434. There is not room for both, so
# whichever allocates second kills the backend for everyone.

set -u

MINI_HOST="${MINI_HOST:-mini}"
CODER_URL="${CODER_URL:-http://baby-jesus.local:8080}"
OLLAMA_URL="${OLLAMA_URL:-http://baby-jesus.local:11434}"
DO_FIX=0
[ "${1:-}" = "--fix" ] && DO_FIX=1

probe_coder() {
  curl -s --max-time 90 "${CODER_URL}/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -d '{"messages":[{"role":"user","content":"Reply with exactly: ok"}],"max_tokens":8}' 2>/dev/null
}

printf '\n=== coder server (%s) ===\n' "$CODER_URL"
HEALTH="$(curl -s --max-time 10 "${CODER_URL}/health" 2>/dev/null)"
printf '  /health : %s\n' "${HEALTH:-<no answer>}"

BODY="$(probe_coder)"
case "$BODY" in
  *'"choices"'*)
    # No quotes inside the f-string expressions: nested same-type quotes are a
    # syntax error before Python 3.12, and the first version of this died on
    # exactly that while the surrounding `case` still declared success.
    printf '%s' "$BODY" | python3 -c '
import sys, json
d = json.load(sys.stdin)
t = d.get("timings", {})
gen = t.get("predicted_per_second", 0)
pro = t.get("prompt_per_second", 0)
print("  serving : YES")
print("  reply   :", d["choices"][0]["message"]["content"].strip()[:60])
print("  speed   : %.1f tok/s generation, %.1f tok/s prompt" % (gen, pro))
'
    SERVING=1 ;;
  *"Compute error"*)
    printf '  serving : NO -- Metal backend is poisoned (500 Compute error)\n'
    printf '            /health above is not evidence of anything.\n'
    SERVING=0 ;;
  "")
    printf '  serving : NO -- no answer at all; the daemon may be down\n'
    SERVING=0 ;;
  *)
    printf '  serving : NO -- unrecognised reply: %s\n' "$(printf '%s' "$BODY" | head -c 120)"
    SERVING=0 ;;
esac

printf '\n=== ollama (%s) ===\n' "$OLLAMA_URL"
VER="$(curl -s --max-time 10 "${OLLAMA_URL}/api/version" 2>/dev/null)"
printf '  version : %s\n' "${VER:-<no answer>}"
LOADED="$(ssh -o ConnectTimeout=8 "$MINI_HOST" 'export PATH=$PATH:/usr/local/bin:/opt/homebrew/bin:/Applications/Ollama.app/Contents/Resources; ollama ps 2>/dev/null | awk "NR>1{print \$1}"' 2>/dev/null)"
if [ -n "$LOADED" ]; then
  printf '  loaded  : %s\n' "$(printf '%s' "$LOADED" | tr '\n' ' ')"
  printf '  WARNING : this competes with the coder server for wired memory and\n'
  printf '            will poison whichever backend allocates second.\n'
else
  printf '  loaded  : nothing (good -- leaves the wired limit to the coder server)\n'
fi

printf '\n=== memory ===\n'
ssh -o ConnectTimeout=8 "$MINI_HOST" '
  printf "  wired limit : %s MB\n" "$(sysctl -n iogpu.wired_limit_mb)"
  printf "  installed   : %s GB\n" "$(( $(sysctl -n hw.memsize) / 1073741824 ))"
  memory_pressure -Q 2>/dev/null | grep -i "free percentage" | sed "s/^/  /"
  ps aux | grep "[l]lama-server" | awk "{printf \"  server pid %-6s %5.1f GB\n\", \$2, \$6/1048576}"
' 2>/dev/null

if [ "${SERVING:-0}" = 1 ]; then
  printf '\nVERDICT: the mini is serving a model.\n'
  exit 0
fi

printf '\nVERDICT: the mini is NOT serving a model.\n'
if [ "$DO_FIX" != 1 ]; then
  printf 'Re-run with --fix to unload Ollama and recreate the backend.\n'
  exit 1
fi

printf '\n--- fixing ---\n'
# Unload first: kickstarting the coder daemon while Ollama still holds an
# allocation just reproduces the original collision.
ssh -o ConnectTimeout=8 "$MINI_HOST" 'export PATH=$PATH:/usr/local/bin:/opt/homebrew/bin:/Applications/Ollama.app/Contents/Resources
  for m in $(ollama ps 2>/dev/null | awk "NR>1{print \$1}"); do echo "unloading $m"; ollama stop "$m" >/dev/null 2>&1; done' 2>/dev/null
sleep 3
# KeepAlive is set on com.nnl.coder, so this is a restart, not a removal.
ssh -o ConnectTimeout=8 "$MINI_HOST" 'sudo -n launchctl kickstart -k system/com.nnl.coder' 2>/dev/null && printf 'coder daemon kickstarted\n'

printf 'waiting for the model to load'
for i in $(seq 1 30); do
  printf '.'
  sleep 10
  case "$(probe_coder)" in *'"choices"'*) printf '\nrecovered after ~%ds\n' $((i * 10)); exit 0 ;; esac
done
printf '\nstill not serving after 5 minutes -- read /Users/Shared/coder/coder_launchd.err\n'
exit 1

#!/bin/bash
# Ollama speed tuning for Apple Silicon (M3 Pro, 36 GB). Reversible.
# Re-run after a reboot (launchctl env is per-login). Run:  bash "tune-ollama-speed.sh"
set -e

echo "[tune] setting Ollama env vars (GUI login session)…"
launchctl setenv OLLAMA_FLASH_ATTENTION 1     # Metal speedup + unlocks KV-cache quantization
launchctl setenv OLLAMA_KV_CACHE_TYPE q8_0    # ~50% less KV RAM, negligible quality loss
launchctl setenv OLLAMA_KEEP_ALIVE 5m         # stay warm while working; `ollama stop` before Photoshop
launchctl setenv OLLAMA_CONTEXT_LENGTH 8192   # stop 0.40.x auto-ballooning context to 32k (~3 GB wasted)
launchctl setenv OLLAMA_NUM_PARALLEL 1        # one slot = no KV-RAM multiplication

echo "[tune] restarting Ollama so it picks up the new env…"
if pgrep -x "Ollama" >/dev/null 2>&1; then
  osascript -e 'quit app "Ollama"' 2>/dev/null || true; sleep 2; open -a Ollama; sleep 4
elif pgrep -f "ollama serve" >/dev/null 2>&1; then
  pkill -f "ollama serve" || true; sleep 2; (nohup ollama serve >/tmp/ollama-serve.log 2>&1 &); sleep 4
else
  echo "[tune] Ollama not running — env is set for next launch."
fi

echo "[tune] active OLLAMA_* env:"
for v in OLLAMA_FLASH_ATTENTION OLLAMA_KV_CACHE_TYPE OLLAMA_KEEP_ALIVE OLLAMA_CONTEXT_LENGTH OLLAMA_NUM_PARALLEL; do
  printf '  %s=%s\n' "$v" "$(launchctl getenv $v)"
done
echo "[tune] done. To free RAM for heavy apps:  ollama stop qwen3-agent"

# To UNDO: launchctl unsetenv OLLAMA_FLASH_ATTENTION (and the others), then restart Ollama.

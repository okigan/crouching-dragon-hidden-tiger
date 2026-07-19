#!/usr/bin/env bash
# Reproducible vLLM serving for the CDHT red-team generator + blue reasoner.
#
# Serves an OpenAI-compatible endpoint on :$PORT that the orchestrator points
# NEMOTRON_BASE_URL at. Run on any NVIDIA GPU instance (this repo's reference
# box was a Brev `hyperstack_A6000`, 48 GB, serving Qwen2.5-0.5B-Instruct).
#
#   MODEL=Qwen/Qwen2.5-0.5B-Instruct PORT=8000 API_KEY=<secret> ./serve.sh
#
# Model size is bound by GPU VRAM + local disk. A 48 GB A6000 comfortably runs
# up to ~7-9B (bf16) or ~14B (fp8). See README.md for persistence + sizing.
set -euo pipefail

MODEL="${MODEL:-Qwen/Qwen2.5-0.5B-Instruct}"
PORT="${PORT:-8000}"
API_KEY="${API_KEY:?set API_KEY to the shared secret clients must send as a Bearer token}"
GPU_UTIL="${GPU_UTIL:-0.90}"          # fraction of VRAM vLLM reserves for weights + KV cache
VENV="${VENV:-$HOME/vllm/.venv}"

# 1. Install uv + vLLM into a venv (idempotent — skipped if already present).
if [ ! -x "$VENV/bin/vllm" ]; then
  echo "==> installing uv + vLLM into $VENV"
  command -v uv >/dev/null 2>&1 || curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
  uv venv "$VENV"
  uv pip install --python "$VENV/bin/python" vllm
fi

echo "==> serving $MODEL on 0.0.0.0:$PORT (gpu-mem-util $GPU_UTIL)"
exec "$VENV/bin/vllm" serve "$MODEL" \
  --host 0.0.0.0 --port "$PORT" \
  --gpu-memory-utilization "$GPU_UTIL" \
  --api-key "$API_KEY"

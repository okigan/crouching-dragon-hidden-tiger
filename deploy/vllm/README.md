# Self-hosted vLLM (optional LLM backend)

The orchestrator's LLM (red-team attack generation + blue-team reasoning) is any
**OpenAI-compatible** chat endpoint. Two ways to provide it:

- **Hosted (default now):** [OpenRouter](https://openrouter.ai) serves NVIDIA
  Nemotron models — including `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free`
  — for free, no GPU required. Just set the three `NEMOTRON_*` vars (below).
- **Self-hosted vLLM:** run a model on your own GPU box with `serve.sh`. Use this
  when you want a specific/private model or full control.

This directory reproduces the self-hosted path.

## Run it on a GPU instance

Reference box: a [Brev](https://brev.dev) `hyperstack_A6000` (48 GB VRAM), which
served `Qwen/Qwen2.5-0.5B-Instruct`.

```bash
# on the GPU instance (has NVIDIA drivers + CUDA):
git clone <this repo> && cd */deploy/vllm      # or just copy serve.sh over
chmod +x serve.sh

MODEL=Qwen/Qwen2.5-0.5B-Instruct \
PORT=8000 \
API_KEY=$(openssl rand -hex 24) \
./serve.sh
```

`serve.sh` installs `uv` + `vllm` into `~/vllm/.venv` (idempotent) and serves the
model. Note the `API_KEY` you passed — clients send it as a Bearer token.

### Keep it running (survive logout / reboot)

Foreground `serve.sh` dies on logout. For a durable service:

```bash
# quick: detach with nohup
MODEL=... PORT=8000 API_KEY=... nohup ./serve.sh > ~/vllm.log 2>&1 &

# durable: systemd unit
sudo tee /etc/systemd/system/vllm.service >/dev/null <<'UNIT'
[Unit]
Description=vLLM OpenAI server
After=network-online.target
[Service]
User=%i
Environment=MODEL=Qwen/Qwen2.5-0.5B-Instruct
Environment=PORT=8000
Environment=API_KEY=CHANGE_ME
ExecStart=/home/%i/path/to/serve.sh
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl enable --now vllm@$USER
```

### On Brev specifically

```bash
brev ls                                  # find/confirm your instance
brev shell <instance-name>               # ssh in (also sets up `ssh <instance-name>`)
# then run serve.sh as above; expose the port via the instance's firewall/URL.
```

## Point the orchestrator at it

In the repo's `.env`:

```ini
LLM=nemotron
NEMOTRON_BASE_URL=http://<instance-ip>:8000    # the adapter appends /v1/chat/completions
NEMOTRON_KEY=<the API_KEY you set>
NEMOTRON_MODEL=<the MODEL you served>
```

(`nemotron` is just the adapter name for "OpenAI-compatible endpoint" — the model
served is whatever `NEMOTRON_MODEL` says.)

## Model sizing (the hard constraints)

A model must fit **both** GPU VRAM and local disk. On a single 48 GB A6000:

| Model size | bf16 weights | Fits 48 GB A6000? | Disk to download |
|-----------|-------------|-------------------|------------------|
| 0.5–3B    | ~1–6 GB     | easily            | ~1–6 GB          |
| 7–9B      | ~14–18 GB   | yes               | ~14–18 GB        |
| 13–14B    | ~28 GB      | tight (use fp8)   | ~28 GB           |
| 30B (A3B) | ~62 GB      | **no** (needs 2× A6000, or H100 for fp8) | ~62 GB |

Quantized builds cut both: **fp8** ≈ ½ size (needs Hopper for native, or Ampere
via Marlin weight-only); **NVFP4** ≈ ¼ size but **needs a Blackwell GPU**. The
30B-A3B Omni model does not fit a single A6000 — that's why we serve it via
OpenRouter instead.

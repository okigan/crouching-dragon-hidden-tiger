# AI Security Validation Platform

A reproducible AI security lab that **continuously evaluates and improves the
security posture of AI agents**. It runs a closed loop: deploy an agent under a
runtime policy, attack it, have an LLM root-cause the failures and propose
policy hardening, re-attack, and repeat until no vulnerabilities remain.

Implements [docs/PLAN.md](docs/PLAN.md); architecture in [docs/DESIGN.md](docs/DESIGN.md);
status in [TODO.md](TODO.md).

## The four components

| Plan component | Role | This repo |
|----------------|------|-----------|
| NVIDIA OpenShell | Sandboxed agent execution + policy enforcement | `Sandbox` adapter |
| HiddenLayer | Adversarial assessment / vuln discovery | `Assessor` adapter |
| Nemotron on vLLM | OpenAI-compatible reasoning + recommendations | `LLM` adapter |
| Security Orchestrator | Drives the improvement loop | **built here** (`orchestrator/`) |

Three of the four are gated (commercial key / NVIDIA access / GPU). Every one
sits behind a narrow `Protocol` with a **deterministic mock** (default, runs
anywhere) and a **real adapter** guarded by credentials. The orchestrator and
tests depend only on the interfaces — so `git clone && pytest` exercises the
entire loop with zero setup, and real backends swap in via env with no code
changes.

## Quickstart

```bash
python -m pytest                 # 29 tests, deterministic, no network, <1s
python -m orchestrator run       # start from the permissive policy, mock backends
open runs/latest/report.html     # visual progress dashboard
```

Example run — the permissive starting policy has 3 planted weaknesses; the loop
hardens it one finding at a time:

```
| # | patched | open before | open after | max severity |
|---|---------|-------------|------------|--------------|
| 0 | yes     | 3           | 0          | critical     |   # egress default-allow -> deny
| 1 | yes     | 2           | 0          | high         |   # shell_exec -> denied
| 2 | yes     | 1           | 0          | high         |   # system_guard -> on
| 3 | no      | 0           | 0          | info         |   # converged
```

Write traces + a hardened policy:

```bash
python -m orchestrator run --out runs/latest --save-policy runs/hardened.yaml
```

## Visual progress dashboard

Every run writes a self-contained `report.html` (theme-aware, no external deps)
to the `--out` dir. It shows, per iteration: the findings discovered with
severity badges and OPEN/defended state, the analysis (root cause + which
backend produced it + latency), the remediation applied to the policy, and a
trend of open findings converging to zero.

```bash
python -m orchestrator run --out runs/latest --save-policy runs/hardened.yaml
open runs/latest/report.html
```

## Red/Blue co-evolution & the ablation proof

The loop is a two-sided co-evolution (vocabulary from a coworker's
[redblue-arena](docs/redblue-arena/README.md) plan, folded in here): the
**Assessor is the red team** (attacks, produces findings) and the
**LLM + PolicyStore are the blue team** (root-causes, hardens the policy). The
**Sandbox is the sole guard** — whether an attack lands is decided by the
enforced policy, not the harness.

The headline metric is **exfil-success-rate** (fraction of attacks that still
land) and its round-1 → round-N drop. The ablation runs enforcement ON vs OFF
from the same start — the control that proves the *policy* stops the attacks:

```bash
python -m orchestrator ablate --out runs/ablation
# ON  : 100% → 0%  (blue hardens, attacks blocked)
# OFF : 100% → 100% (blue still patches, but enforcement disabled → no effect)
# recursive-intelligence delta = +100%
```

Single runs take `--no-enforce` (or `OPENSHELL_ENFORCE=false`) for the ablation
arm; every dashboard shows the exfil-rate curve and enforcement badge.

## Optionally driving it with a live LLM (vLLM / Nemotron)

The `LLM` backend is optional and defaults to a deterministic mock. Point it at
any OpenAI-compatible vLLM endpoint and the model will **propose which finding
to fix and narrate the root cause**; its choice is validated against known
remediations and **falls back to the heuristic when unusable** — so the loop
converges regardless of how small or slow the model is.

```bash
export LLM=nemotron
export NEMOTRON_BASE_URL=http://REDACTED-VLLM-HOST:8000
export NEMOTRON_MODEL=Qwen/Qwen2.5-0.5B-Instruct
export NEMOTRON_KEY=<your-key>          # export, don't commit
python -m orchestrator run --out runs/live
```

In the dashboard, LLM-driven iterations are tagged `nemotron · <latency>ms`;
fallbacks are tagged `nemotron-fallback`. Tune `NEMOTRON_TIMEOUT` (seconds) if
the endpoint is slow — a timeout falls back rather than failing the run.

## Using the other real services

Copy `.env.example` to `.env` and set backends + credentials:

```bash
SANDBOX=openshell   OPENSHELL_ENDPOINT=... OPENSHELL_KEY=...
ASSESSOR=hiddenlayer HIDDENLAYER_KEY=...
```

OpenShell and HiddenLayer wiring lives in `orchestrator/backends/real.py` as
credential-guarded seams (clearly marked `TODO`); the Nemotron/vLLM adapter in
that file is fully implemented. See [docs/DESIGN.md §8](docs/DESIGN.md).

## Deployment

```bash
docker compose up --build orchestrator      # self-contained (mocks)
docker compose --profile gpu up vllm        # opt-in Nemotron endpoint (GPU)
```

## Layout

```
orchestrator/
  models.py        domain types (Policy, Finding, PolicyPatch, ...)
  interfaces.py    Sandbox / Assessor / LLM / Reporter Protocols
  loop.py          the improvement loop (deploy->assess->analyze->patch)
  policy_store.py  versioned load/save/apply/rollback/diff
  reporter.py      per-iteration traces + Markdown summary
  config.py        env -> backend resolution (mock defaults)
  backends/        mock.py (default) · real.py (guarded stubs) · corpus.py
policies/          baseline.yaml (intentionally under-hardened)
tests/             unit · integration · contract (95% coverage)
```

## Development

```bash
make test    # pytest
make cov     # coverage report
make run     # run the loop, write runs/
```

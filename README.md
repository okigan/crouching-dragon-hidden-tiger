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
python -m orchestrator run       # run the loop on mock backends
```

Example run — baseline policy has 3 planted weaknesses; the loop hardens it:

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

## Using the real services

Copy `.env.example` to `.env` and set backends + credentials:

```bash
SANDBOX=openshell   OPENSHELL_ENDPOINT=... OPENSHELL_KEY=...
ASSESSOR=hiddenlayer HIDDENLAYER_KEY=...
LLM=nemotron        NEMOTRON_BASE_URL=http://vllm:8000
```

The live wiring lives in `orchestrator/backends/real.py` as credential-guarded
seams (clearly marked `TODO`) — the mocks prove the architecture end-to-end
first; see [docs/DESIGN.md §8](docs/DESIGN.md).

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

# Development

Developer guide for Crouching Dragon Hidden Tiger. For what the project does and
the results it produces, see the [README](README.md); for architecture, see
[docs/DESIGN.md](docs/DESIGN.md).

## Setup

Uses [uv](https://docs.astral.sh/uv/) — it creates an isolated env and installs
deps from the lockfile automatically, so there is nothing to `pip install`.

```bash
uv run pytest                    # 29 tests, deterministic, no network, <1s
uv run security-orchestrator run # run the loop on mock backends
```

> No uv? The plain-Python path still works if PyYAML is installed:
> `python3 -m orchestrator run`.

## Commands

```bash
uv run security-orchestrator run    [--policy P] [--enforce/--no-enforce] [--out DIR] [--save-policy F]
uv run security-orchestrator ablate [--policy P] [--out DIR]   # enforcement ON vs OFF
```

Or via Make:

```bash
make test    # pytest
make cov     # coverage report (not gated)
make run     # run the loop, write runs/
make ablate  # run the ablation
```

## Layout

```
orchestrator/
  models.py        domain types (Policy, Finding, PolicyPatch, Assessment, ...)
  interfaces.py    Sandbox / Assessor / LLM / Reporter Protocols
  loop.py          the improvement loop (deploy→assess→analyze→patch)
  policy_store.py  versioned load/save/apply/rollback/diff
  reporter.py      per-round JSON traces, Markdown summary, HTML dashboard
  harness.py       the ablation harness (enforcement ON vs OFF)
  config.py        env → backend resolution (mock defaults)
  backends/        mock.py (default) · real.py (OpenShell/HiddenLayer/Nemotron)
                   · corpus.py (attack cases) · remediation.py (fix table)
policies/          permissive.yaml (start here) · baseline.yaml
tests/             unit · integration · contract
```

## Configuration & backends

Every backend defaults to a deterministic `mock`; real ones opt in via env
(copy [.env.example](.env.example) to `.env`). Nothing here is required to run.

| Env | Values | Purpose |
|-----|--------|---------|
| `SANDBOX` | `mock` \| `openshell` | execution + policy enforcement |
| `ASSESSOR` | `mock` \| `hiddenlayer` | adversarial assessment (red) |
| `LLM` | `mock` \| `nemotron` | reasoning (blue) |
| `OPENSHELL_ENFORCE` | `true` \| `false` | ablation toggle (or `--no-enforce`) |
| `NEMOTRON_BASE_URL` / `NEMOTRON_MODEL` / `NEMOTRON_KEY` / `NEMOTRON_TIMEOUT` | | vLLM endpoint |
| `OPENSHELL_*`, `HIDDENLAYER_*` | | credentials for those services |

**LLM adapter behavior.** With `LLM=nemotron`, the model *proposes* which finding
to fix and narrates the root cause; its choice is validated against the known
remediation table and **falls back to the deterministic heuristic** when the
response is unusable or the endpoint is slow/unreachable. So enabling a live
model (even a tiny one) adds real analysis without ever risking convergence.

**OpenShell / HiddenLayer.** The adapters in `orchestrator/backends/real.py` are
credential-guarded seams (clearly marked `TODO`); the Nemotron/vLLM adapter in
that file is fully implemented.

## Testing

```bash
uv run pytest
```

Fast, deterministic, no network. Covers the domain model, policy store, each mock
backend, the full loop (convergence, no-progress guard, max-iters), and contract
tests that the real adapters satisfy the same Protocols as the mocks (live calls
skipped without credentials). Tests for the live vLLM adapter and the ablation
harness are deferred (they need real endpoints).

CI (`.github/workflows/ci.yml`) runs the suite plus a `run` and `ablate`
smoke-check on every push and PR, via uv.

## Deployment

```bash
docker compose up --build orchestrator      # self-contained (mock backends)
docker compose --profile gpu up vllm        # opt-in Nemotron endpoint (GPU)
```

## Regenerating the sample report image

The README image is `docs/sample-report.png` — a screenshot of a mock run's
`report.html`. To refresh it, generate a run (`make run`) and screenshot
`runs/latest/report.html` in a browser at ~940px wide, light theme.

## Branch workflow

`main` is protected: changes go through a pull request and the `test` CI check
must pass before merge (no direct pushes or force-pushes to `main`).

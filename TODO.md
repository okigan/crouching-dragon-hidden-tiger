# TODO — AI Security Validation Platform

Tracking for implementing [docs/PLAN.md](docs/PLAN.md) per [docs/DESIGN.md](docs/DESIGN.md).
Status: ☐ todo · ◐ in progress · ☑ done

## Milestone 0 — Docs & scaffold
- ☑ Read PLAN.md, identify gated components, choose adapter+mock architecture
- ☑ Write DESIGN.md
- ☑ Write TODO.md (this file)
- ☑ Project scaffold: package layout, pyproject, .gitignore, git init

## Milestone 1 — Core domain (unit-tested)
- ☑ `models.py` — Policy, Finding, Assessment, Recommendation, PolicyPatch, results
- ☑ `interfaces.py` — Sandbox / Assessor / LLM / PolicyStore / Reporter Protocols
- ☑ Policy schema + `baseline.yaml`
- ☑ PolicyStore: load/save/apply-patch/diff/rollback + tests

## Milestone 2 — Mock backends (the engine that runs anywhere)
- ☑ MockSandbox — in-process policy enforcement, observable violations
- ☑ MockAssessor — fixed attack corpus, findings gated by policy
- ☑ MockLLM — heuristic root-cause + policy patch + new tests
- ☑ Reporter — per-iteration traces + Markdown summary
- ☑ Unit tests for each mock

## Milestone 3 — The improvement loop
- ☑ `loop.py` — deploy→assess→analyze→patch→re-assess with convergence + guards
- ☑ Integration test: loop converges to zero findings, deterministic
- ☑ Integration test: no-progress guard terminates
- ☑ CLI entrypoint (`python -m orchestrator run ...`)

## Milestone 4 — Real adapter seams (guarded stubs)
- ☑ OpenShellSandbox stub + credential guard + contract test
- ☑ HiddenLayerAssessor stub + credential guard + contract test
- ☑ NemotronLLM (OpenAI-compatible client) + credential guard + contract test

## Milestone 5 — Deployment & repro
- ☑ Dockerfile (orchestrator)
- ☑ docker-compose.yml (orchestrator default; vllm gpu profile)
- ☑ .env.example, README with quickstart
- ☑ Makefile / task runner (test, run, lint)

## Milestone 6 — Continuous testing / CI
- ☑ GitHub Actions workflow: pytest on push
- ☑ Coverage gate + fast deterministic suite

## Backlog / stretch
- ☐ Richer attack corpus (multi-turn, encoding, tool-chaining)
- ☐ Policy patch validity via constraint solver rather than heuristics
- ☐ HTML dashboard for run reports
- ☐ Real OpenShell/HiddenLayer/Nemotron live integration tests (needs creds)

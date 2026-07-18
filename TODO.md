# TODO — Crouching Dragon Hidden Tiger

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

## Milestone 7 — Live LLM + visual view (added)
- ☑ Permissive starting policy (`policies/permissive.yaml`), now CLI default
- ☑ NemotronLLM: live vLLM call, JSON parse, tolerant keyword match, heuristic
     fallback (verified against dev endpoint, Qwen2.5-0.5B, ~250ms/iter)
- ☑ Shared remediation module used by both mock and real adapters
- ☑ Recommendation provenance (source/latency/narrative) threaded to reporter
- ☑ Self-contained HTML dashboard (`report.html`): findings, remediation,
     convergence trend; theme-aware
- ☑ Published as shareable Artifact

## Milestone 8 — Incorporate coworker's redblue-arena (added)
- ☑ Review airdropped plan + tarball (scaffold/plans only, no impl)
- ☑ Preserve their plan + reference files under `docs/redblue-arena/`
- ☑ Red/Blue vocabulary mapping (Assessor=red, LLM+PolicyStore=blue) in DESIGN §9
- ☑ Boundary invariant: sandbox is the sole guard (`_unenforced` when off)
- ☑ Ablation enforce toggle (`--enforce/--no-enforce`, `OPENSHELL_ENFORCE`)
- ☑ Exfil-success-rate + round delta metric; featured in dashboard
- ☑ `orchestrator ablate` — enforcement ON vs OFF recursive-intelligence delta
- ☐ Not incorporated (out of scope): CF Workers/R2/D1, Brev, GSAP, submission

## Backlog / stretch
- ☐ Richer attack corpus (multi-turn, encoding, tool-chaining)
- ☐ Try a larger model on the endpoint; measure how choices/narrative improve
- ☐ Policy patch validity via constraint solver rather than heuristics
- ☐ Real OpenShell/HiddenLayer live integration (needs creds)
- ☐ Tests for the vLLM adapter (deferred per request)

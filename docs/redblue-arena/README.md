# redblue-arena — coworker plan (incorporated)

A coworker shared a hackathon-framed sibling of this platform
(`organized-ai/redblue-arena`, AITX × NVIDIA Claw Agent Hackathon). Their raw
plan and reference files are **kept out of this public repo** (they contain the
coworker's own infrastructure identifiers and machine paths). What matters here
is what we folded into our running code.

## What we folded into *this* platform

The directly-applicable mechanics are implemented in our code (not just
documented). See [../DESIGN.md](../DESIGN.md) §9.

| Their idea | Where it lives here |
|------------|---------------------|
| Red team vs blue team co-evolution | Assessor = **red**, LLM+PolicyStore = **blue** (DESIGN §9) |
| Boundary invariant (policy is the *sole* guard) | Sandbox enforcement model + DESIGN §9 |
| Ablation toggle `OPENSHELL_ENFORCE=on/off` | `LoopConfig.enforce` / `--enforce` / env `OPENSHELL_ENFORCE` |
| Exfil-success-rate delta across rounds | `Assessment.success_rate`, `RunResult` delta, dashboard |
| Recursive-Intelligence proof (enforce on vs off) | `python -m orchestrator ablate` |

The two-network topology that illustrates the boundary invariant (control-net
internal, data-net egress-open) is preserved as
[`docker-compose.reference.yml`](docker-compose.reference.yml).

## Deliberately **not** incorporated (hackathon-specific infra)

Cloudflare Workers/Assets/R2/D1, Brev GPU provisioning, GSAP dashboard,
wrangler deploy, submission bundle. These serve the competition surface, not our
local reproducible lab. Our vLLM/Nemotron adapter already covers the "reasoning
on a self-hosted OpenAI-compatible endpoint" requirement.

# redblue-arena — coworker plan (incorporated)

Source: airdropped by a coworker (2026-07-18) — the hackathon-framed sibling of
this platform (`organized-ai/redblue-arena`, AITX × NVIDIA Claw Agent
Hackathon). The tarball was **scaffold + planning only** (the `services/*` dirs
were one-line README stubs); the substantive content is preserved here:

- `IMPLEMENTATION-MASTER-PLAN.md` — full plan, phases, track/bounty matrix.
- `docker-compose.reference.yml` — their two-network topology (control-net
  internal, data-net egress-open) illustrating the boundary invariant.
- `CLAUDE.reference.md` — their project intent + boundary invariant statement.

## What we folded into *this* platform

The directly-applicable mechanics are now implemented in our running code (not
just documented). See [../DESIGN.md](../DESIGN.md) §9.

| Their idea | Where it lives here |
|------------|---------------------|
| Red team vs blue team co-evolution | Assessor = **red**, LLM+PolicyStore = **blue** (DESIGN §9) |
| Boundary invariant (policy is the *sole* guard) | Sandbox enforcement model + DESIGN §9 |
| Ablation toggle `OPENSHELL_ENFORCE=on/off` | `LoopConfig.enforce` / `--enforce` / env `OPENSHELL_ENFORCE` |
| Exfil-success-rate delta across rounds | `Assessment.success_rate`, `RunResult` delta, dashboard |
| Recursive-Intelligence proof (enforce on vs off) | `python -m orchestrator ablate` |

## Deliberately **not** incorporated (hackathon-specific infra)

Cloudflare Workers/Assets/R2/D1, Brev GPU provisioning, GSAP dashboard,
wrangler deploy, submission bundle. These serve the competition surface, not our
local reproducible lab. Our vLLM/Nemotron adapter already covers the "reasoning
on a self-hosted OpenAI-compatible endpoint" requirement.

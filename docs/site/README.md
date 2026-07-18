# Hackathon docs site

Static docs / landing site for the AITX × NVIDIA Claw Agent Hackathon
(Recursive Intelligence track). Deployed as **Cloudflare Worker Assets** (not Pages).

**Live:** https://redblue-arena-site.jordan-691.workers.dev/redblue-arena/

## Surfaces
- `public/redblue-arena/index.html` — landing / hackathon doc (demo slot, interactive
  axonometric map, six-stage pipeline, stack, honest status table)
- `guide/` — quick start (`uv run security-orchestrator run` / `ablate`), phases
- `wiki/` — glossary of services and terms
- `arch/` — topology, the loop, stores, boundary invariant
- `visual/` — interactive round-by-round arena (exfil 100% → 0%)
- `style.css` — shared stylesheet

## Deploy
```bash
cd docs/site && wrangler deploy   # assets-only Worker, [assets] dir = ./public
```

## Notes
- GitHub links point to `okigan/crouching-dragon-hidden-tiger`; Guide quick-start and
  the landing status table reflect the real `uv` / `security-orchestrator` flow and the
  honest status legend.
- Branding is still "Red/Blue Arena" with `/redblue-arena/` paths; rebrand to
  "Crouching Dragon Hidden Tiger" is a pending follow-up.
- Reflects the corrected two-defense-layer model: HiddenLayer (detection) + OpenShell
  (enforcement) are complementary defenses; the red team is a separate attacker,
  optionally sourced from HiddenLayer's APE taxonomy.

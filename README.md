# Crouching Dragon Hidden Tiger

**An AI security lab that hardens an agent's NVIDIA OpenShell runtime policy until attacks stop working — automatically, and proves it.**

You start with a permissively-configured AI agent running under an [NVIDIA
OpenShell](docs/PLAN.md) sandbox. An **attack corpus** probes it, **HiddenLayer**
detects the threats, and a blue team (an LLM) reads each landed attack and
tightens the OpenShell policy — the cycle repeats until no attack lands. The
result is a **hardened OpenShell policy** plus a **measured
before/after** you can put in front of anyone.

## What you get from one run

```bash
uv run security-orchestrator run --save-policy runs/latest/hardened.yaml
```

- **A hardened OpenShell policy** (`runs/latest/hardened.yaml`). The starting
  policy (open egress, `shell_exec`/`code_exec` allowed) is rewritten to deny
  egress by default and drop the dangerous tools.
- **A defense-in-depth result: attack-success-rate 60% → 0%.** HiddenLayer
  catches the obvious attacks at the content layer immediately; the ones that
  **evade detection** land until OpenShell is hardened to stop them.
- **The detection gaps, made explicit** — which prompts *passed through*
  HiddenLayer, and the exact OpenShell control added to catch each.
- **A visual report** (`runs/latest/report.html`) with a two-layer view
  (HiddenLayer vs OpenShell) per attack and the curve to zero.

### The report it produces

![Sample run report — a live HiddenLayer run; 3 attacks evade detection and OpenShell is hardened to catch them](docs/sample-report.png)

*A real run with `ASSESSOR=hiddenlayer`. The **Bypass analysis** panel is
two-sided: attacks that **bypass HiddenLayer** (0 / few signals → stopped by
OpenShell) and attacks that **bypass OpenShell** (no capability control → stopped
by HiddenLayer). The two-layer table shows, per round, the HiddenLayer **signal
count** and whether **OpenShell** blocked it (LANDED = bypassed both). Each
remediation expands to the exact **OpenShell config applied** and links to the
**real documentation** — OWASP LLM Top-10, MITRE ATLAS, HiddenLayer docs, and the
**HiddenLayer APE** technique/objective the attack uses.*

The red team is grounded in two real references: HiddenLayer's [**APE
taxonomy**](https://ape.hiddenlayer.com/) classifies each attack's technique
(how) and objective (what), and each attack targets an **OpenShell** protection
surface (egress, tools, prompt). The loop then captures which prompts **evade
HiddenLayer detection** and which **escape OpenShell** — the detection gaps.

## Two layers of defense (and the ablation)

Attacks are stopped by **two layers**: **HiddenLayer** detects malicious content,
and **OpenShell** enforces capabilities (egress, tools). An attack **lands** only
if it evades *both* — HiddenLayer doesn't detect it *and* OpenShell doesn't deny
the capability it needs. The interesting ones are the **detection gaps**:
benign-sounding attacks HiddenLayer misses, which only OpenShell can catch.

The ablation toggles the OpenShell layer to prove it's doing the work — with it
off, the detection gaps stay open (HiddenLayer still catches the obvious ones):

```bash
uv run security-orchestrator ablate
```

| OpenShell enforcement | attack-success start → end | converges? |
|-----------------------|----------------------------|-----------|
| **ON**  | 60% → 0%   | yes — OpenShell closes the gaps |
| **OFF** | 60% → 86%  | no — the gaps never close |

Both start at 60% (HiddenLayer catches 2 of 5 outright). With enforcement ON,
OpenShell is hardened until the 3 evaders are caught too; with it OFF they keep
landing. The gap is the recursive-intelligence signal. (The default run uses an
OpenShell-compatible policy model; live OpenShell is a credential-guarded
adapter — see the status table below.)

## How it works

A defense-in-depth co-evaluation loop (attack corpus → detection → hardening).
Each round:

1. **Deploy** the agent under the current OpenShell policy in the sandbox.
2. **Attack & detect.** The **attack corpus** (the adversary) is run against the
   deployed defenses; **HiddenLayer** detects and classifies each threat
   (prompt-injection, PII, code, …), and the assessor reports which attacks land.
3. **Analyze (blue).** An LLM root-causes the worst finding and proposes an
   OpenShell policy patch (validated so it only ever tightens).
4. **Patch & re-test.** Apply the patch, add a regression test, run again.
5. **Stop** when no attack lands (converged), or the findings stall.

It maps onto the four-component security stack from the original brief
([docs/PLAN.md](docs/PLAN.md)):

| Component | Role | Here |
|-----------|------|------|
| NVIDIA OpenShell | Capability/egress enforcement (sole guard on the egress path) | `Sandbox` |
| HiddenLayer | Runtime **detection** of malicious content (the content-defense layer) | `Assessor` (detector) |
| Nemotron on vLLM | Reasoning that proposes fixes (the blue team) | `LLM` |
| Security Orchestrator | Drives the loop | built here |

Each sits behind an interface with a **real adapter** (the default — a normal
run exercises the live OpenShell + HiddenLayer + Nemotron systems, with
credentials from `.env`) and a **deterministic mock** used **only by the test
suite** (offline, no credentials; pinned in `tests/conftest.py`). So `pytest`
runs anywhere, while an actual run reflects the real systems.

## Try it

```bash
uv run security-orchestrator run --out runs/latest --save-policy runs/hardened.yaml
open runs/latest/report.html
```

Point it at a real vLLM/Nemotron endpoint to have an actual model drive the blue
team (optional — falls back to the heuristic if the model returns anything
unusable, so the loop always converges):

```bash
export LLM=nemotron NEMOTRON_BASE_URL=http://YOUR_VLLM_HOST:8000 \
       NEMOTRON_MODEL=<served-model-id> NEMOTRON_KEY=<key>
uv run security-orchestrator run --out runs/live
```

Use the **live HiddenLayer** detection layer (real prompt-injection/PII/code
detection driving the findings) with the `hiddenlayer` extra:

```bash
export ASSESSOR=hiddenlayer HIDDENLAYER_CLIENT_ID=<id> HIDDENLAYER_CLIENT_SECRET=<secret>
uv run --extra hiddenlayer security-orchestrator run --out runs/live
```

## Dynamic red team (`--generate`)

Instead of a fixed corpus, generate attacks on the fly. For each APE technique,
the vLLM crafts an evasion prompt, it's **screened** against HiddenLayer, and the
ones that **evade detection** are added to the corpus — then the loop hardens
OpenShell to catch them:

```bash
export LLM=nemotron NEMOTRON_BASE_URL=http://YOUR_VLLM_HOST:8000 NEMOTRON_MODEL=<id> NEMOTRON_KEY=<key>
export ASSESSOR=hiddenlayer HIDDENLAYER_CLIENT_ID=<id> HIDDENLAYER_CLIENT_SECRET=<secret>
uv run --extra hiddenlayer security-orchestrator run --generate 3
# → generated 2/3 evasion attack(s) (APE-grounded, passed screening) → added to corpus
```

The clauses come from the vendored [APE taxonomy](third_party/ape-taxonomy/)
(`ape.py` / `redteam.py`). Offline (mock backends) it uses a deterministic
generator so `--generate` runs anywhere.

## More

- **Design & diagrams:** [docs/DESIGN.md](docs/DESIGN.md)
- **Development, testing, config, deployment:** [DEVELOP.md](DEVELOP.md)
- **The original brief:** [docs/PLAN.md](docs/PLAN.md)

## Tracks & bounties targeted

Built for the AITX × NVIDIA hackathon. Status reflects what is **actually
demonstrated in this repo** versus sponsor integrations that are wired as
credential-guarded seams (`orchestrator/backends/real.py`) awaiting access —
honest, not aspirational.

| Target | Type | Status | What backs it |
|--------|------|--------|---------------|
| **Recursive Intelligence** | Track | ✅ Demonstrated | Run-over-run improvement is *measured*: the ablation harness reports exfil-success-rate 100%→0% with enforcement on vs. a flat 100% control (`security-orchestrator ablate`), and the loop is **adaptive** — each round re-generates attacks seeded on the prior round's survivors, so the blue team hardens against an escalating red team (convergence curve in every report). |
| **NVIDIA OpenShell** (policy is the sole guard) | Bounty | ✅ Demonstrated | Real OpenShell gateway is the *sole* guard: the loop deploys a live sandbox, translates our policy to OpenShell YAML and `policy set`s it, and **observes** egress enforcement by exec'ing a real `curl` inside the sandbox each round (allow-listed host 200 → 403 after blue removes it). The blue-team LLM **authors the policy ops** directly via structured output (`response_format` json_schema), validated against the schema. Enforcement on/off ablation proves the policy — not the harness — stops attacks. |
| **HiddenLayer Runtime Security** | Bounty | ✅ Demonstrated | Every attack is screened through HiddenLayer's live prompt analyzer; real, **distinct** detections drive the findings and the assessor is **fail-closed** on API/WAF errors. The red team is grounded in the full vendored **APE taxonomy** — all 47 techniques × 22 objectives (1034 specs), sweepable end-to-end (`make taxonomy-sweep`). Enable with `ASSESSOR=hiddenlayer`. |
| **Best Use of Nemotron** | Bounty | ✅ Demonstrated | Nemotron 3 Nano Omni (30B-A3B) served via OpenRouter drives both the red-team generator and the blue-team policy author; point `NEMOTRON_MODEL` at any served model to swap it (verified against Nemotron on OpenRouter and self-hosted Qwen). |
| **Best Use of vLLM** | Bounty | ✅ Demonstrated | A self-hosted OpenAI-compatible vLLM endpoint (`deploy/vllm/`) serves the model that drives the loop, selectable per-run in the web UI alongside OpenRouter; ran end-to-end against it. |
| **Most Commercializable** | Bounty (optional) | ○ Narrative | Positioning: autonomous-agent security co-evaluation as a product. |

Legend: ✅ demonstrated · ◑ architected, real integration pending credentials ·
○ narrative only. Real backends are the default; the offline mocks are **test-only**
(selected solely by `SANDBOX`/`ASSESSOR`/`LLM=mock` for unit/integration tests and
the offline `make taxonomy-sweep`) and never a silent fallback in a real run.

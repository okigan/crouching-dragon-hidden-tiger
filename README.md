# Crouching Dragon Hidden Tiger

**An AI security lab that hardens an agent's NVIDIA OpenShell runtime policy until attacks stop working — automatically, and proves it.**

You start with a permissively-configured AI agent running under an [NVIDIA
OpenShell](docs/PLAN.md) sandbox. A red team attacks it, a blue team (an LLM)
reads each failure and tightens the OpenShell policy, and the cycle repeats until
no attack lands. The result is a **hardened OpenShell policy** plus a **measured
before/after** you can put in front of anyone.

## What you get from one run

```bash
uv run security-orchestrator run --save-policy runs/latest/hardened.yaml
```

- **A hardened OpenShell policy** (`runs/latest/hardened.yaml`). The starting
  policy (open egress, `shell_exec` allowed, no injection guard) is rewritten
  into one that denies egress by default, drops the dangerous tool, and enables
  the prompt guard.
- **A headline result: exfil-success-rate 100% → 0%.** Every attack lands at the
  start; none land at the end. That drop is the whole point.
- **A visual report** (`runs/latest/report.html`) showing every round: what was
  attacked, what the blue team changed, and the curve to zero.
- **A recursive-intelligence delta** proving the *policy* did the work, not the
  test harness (see the ablation below).

### The report it produces

![Sample run report — a live HiddenLayer run hardening the OpenShell policy over 6 rounds](docs/sample-report.png)

*A real run with `ASSESSOR=hiddenlayer`: the **OpenShell policy evolution** panel
shows each version bump and the live HiddenLayer signal that triggered it
(prompt-injection `LLM01`, `input_pii`, `input_code`); the rounds below show the
five detections converging to zero. Each remediation expands to the exact
**OpenShell config applied** and links to the **real documentation** for that
detection (OWASP LLM Top-10, MITRE ATLAS, HiddenLayer docs).*

## The proof it isn't cheating: the ablation

The NVIDIA OpenShell sandbox is the **sole guard** — an attack is stopped by the
OpenShell policy, not by the harness. (The default run enforces this with an
OpenShell-compatible policy model; live OpenShell is a credential-guarded
adapter — see the status table below.) Run the same loop with enforcement ON vs
OFF:

```bash
uv run security-orchestrator ablate
```

| enforcement | exfil-success start → end | delta |
|-------------|---------------------------|-------|
| **ON**  | 100% → 0%   | **−100%** |
| **OFF** | 100% → 100% | 0% |

With enforcement OFF the blue team still learns and patches, but the guard never
takes effect, so attacks keep landing. Only the enforced run drops to zero — the
gap is the recursive-intelligence signal.

## How it works

A red-team / blue-team co-evolution loop. Each round:

1. **Deploy** the agent under the current OpenShell policy in the sandbox.
2. **Attack (red).** An assessor runs an adversarial corpus — data-exfiltration,
   tool-abuse, prompt-injection — and reports which attacks landed.
3. **Analyze (blue).** An LLM root-causes the worst finding and proposes an
   OpenShell policy patch (validated so it only ever tightens).
4. **Patch & re-test.** Apply the patch, add a regression test, run again.
5. **Stop** when no attack lands (converged), or the findings stall.

It maps onto the four-component security stack from the original brief
([docs/PLAN.md](docs/PLAN.md)):

| Component | Role | Here |
|-----------|------|------|
| NVIDIA OpenShell | Sandboxed execution + policy enforcement (the sole guard) | `Sandbox` |
| HiddenLayer | Adversarial assessment (the red team) | `Assessor` |
| Nemotron on vLLM | Reasoning that proposes fixes (the blue team) | `LLM` |
| Security Orchestrator | Drives the loop | built here |

Each sits behind an interface with a **deterministic mock** (default, runs
anywhere with no credentials) and a **real adapter** that swaps in via env — so
the whole thing runs offline out of the box. The **HiddenLayer** (red team) and
**vLLM/Nemotron** (blue team) adapters are wired against the live services;
OpenShell is a credential-guarded seam (see the status table below).

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

Use the **live HiddenLayer** red team (real prompt-injection detection driving
the findings) with the `hiddenlayer` extra:

```bash
export ASSESSOR=hiddenlayer HIDDENLAYER_CLIENT_ID=<id> HIDDENLAYER_CLIENT_SECRET=<secret>
uv run --extra hiddenlayer security-orchestrator run --out runs/live
```

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
| **Recursive Intelligence** | Track | ✅ Demonstrated | Run-over-run improvement is *measured*: the ablation harness reports exfil-success-rate 100%→0% with enforcement on vs. a flat 100% control — `security-orchestrator ablate`, plus the convergence curve in every report. |
| **Best Use of vLLM** | Bounty | ✅ Demonstrated | A live OpenAI-compatible vLLM endpoint drives the blue team (`NemotronLLM`), with response validation and a heuristic fallback. Ran end-to-end against a self-hosted endpoint. |
| **NVIDIA OpenShell** (policy is the sole guard) | Bounty | ◑ Architected | The sandbox models OpenShell as the *sole* egress guard, with the enforcement on/off ablation that proves the policy — not the harness — stops attacks. Real OpenShell CLI/schema wiring is a seam. |
| **HiddenLayer Runtime Security** | Bounty | ✅ Demonstrated | Every attack payload is sent through HiddenLayer's live prompt analyzer; real, **distinct** detections (OWASP LLM01 prompt-injection, `input_pii`, `input_code`, unsafe-input) drive the findings, each mapping to a different OpenShell control, and the assessor is **fail-closed** on API/WAF errors. Enable with `ASSESSOR=hiddenlayer`. |
| **Best Use of Nemotron** | Bounty | ◑ Ready | The vLLM adapter is model-agnostic and runs today against any served model; point `NEMOTRON_MODEL` at Nemotron to make it the reasoning model for the blue team. |
| **Most Commercializable** | Bounty (optional) | ○ Narrative | Positioning: autonomous-agent security co-evaluation as a product. |

Legend: ✅ demonstrated · ◑ architected, real integration pending credentials ·
○ narrative only.

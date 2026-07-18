# Crouching Dragon Hidden Tiger

**An AI security lab that hardens an agent's NVIDIA OpenShell runtime policy until attacks stop working — automatically, and proves it.**

You start with a permissively-configured AI agent running under an [NVIDIA
OpenShell](docs/PLAN.md) sandbox. A red team attacks it, a blue team (an LLM)
reads each failure and tightens the OpenShell policy, and the cycle repeats until
no attack lands. The result is a **hardened OpenShell policy** plus a **measured
before/after** you can put in front of anyone.

## What you get from one run

```bash
uv run security-orchestrator run
```

- **A hardened OpenShell policy.** The starting policy (open egress, `shell_exec`
  allowed, no injection guard) is rewritten into one that denies egress by
  default, drops the dangerous tool, and enables the prompt guard — saved to
  `runs/latest/`.
- **A headline result: exfil-success-rate 100% → 0%.** Every attack lands at the
  start; none land at the end. That drop is the whole point.
- **A visual report** (`runs/latest/report.html`) showing every round: what was
  attacked, what the blue team changed, and the curve to zero.
- **A recursive-intelligence delta** proving the *policy* did the work, not the
  test harness (see the ablation below).

### The report it produces

![Sample run report — permissive policy hardened to convergence over 4 rounds](docs/sample-report.png)

*Each round: the findings discovered (severity + OPEN/defended), the remediation
the blue team applied to the policy, and the exfil-success-rate trending to zero.
With a live LLM the remediation is tagged `nemotron`; the default uses a
deterministic heuristic so the run is reproducible with zero setup.*

## The proof it isn't cheating: the ablation

The NVIDIA OpenShell sandbox is the **sole guard** — an attack is stopped by the
OpenShell policy, not by the harness. Run the same loop with enforcement ON vs
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
the whole thing runs offline out of the box, and connects to the real services
when you have them.

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

## More

- **Design & diagrams:** [docs/DESIGN.md](docs/DESIGN.md)
- **Development, testing, config, deployment:** [DEVELOP.md](DEVELOP.md)
- **The original brief:** [docs/PLAN.md](docs/PLAN.md)

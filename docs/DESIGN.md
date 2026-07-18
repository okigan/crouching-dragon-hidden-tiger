# DESIGN — Crouching Dragon Hidden Tiger

> Companion to [PLAN.md](PLAN.md). This document turns the high-level plan into a
> concrete, buildable architecture. See [../TODO.md](../TODO.md) for status.

## 1. Guiding constraints

The plan names four components, three of which are **gated** in a normal dev
environment:

| Component | Availability | Consequence |
|-----------|--------------|-------------|
| NVIDIA OpenShell | NVIDIA-gated / evolving | Cannot pull & run freely |
| HiddenLayer | Commercial SaaS, API key | No key in CI/local |
| Nemotron on vLLM | Needs GPU + NGC access | Won't run on a laptop / CI |
| Security Orchestrator | **We build this** | Fully ours |

**Design principle: adapter seams + local mocks.** Every external component sits
behind a narrow Python `Protocol`. Each has (a) a **mock** implementation that
runs anywhere (deterministic, no network, used by default + in CI) and (b) a
**real** implementation guarded behind config/credentials. The orchestrator and
its tests never import a concrete backend directly — they resolve one from
config. This makes the platform *reproducible* (the plan's stated objective)
regardless of whether the gated services are present.

## 2. Component model

```mermaid
flowchart TD
    ORCH["Security Orchestrator<br/>(improvement loop)"]
    ORCH --> SB["Sandbox — OpenShell<br/>the sole guard<br/>mock | real"]
    ORCH --> AS["Assessor — HiddenLayer<br/>mock | real"]
    ORCH --> LLM["LLM — Nemotron<br/>mock | real"]
    ORCH --> PS["PolicyStore<br/>versioned yaml"]
    ORCH --> RP["Reporter<br/>traces · json / md / html"]

    class AS red
    class LLM,PS blue

    classDef red fill:#3a1418,stroke:#b3153b,color:#f0808f
    classDef blue fill:#12233a,stroke:#3457d5,color:#8fb2ff
```

Orange = **assessment** (the attack corpus, run and detected via HiddenLayer);
blue = **remediation** (the blue reasoner + policy store). HiddenLayer is a
detection layer, not the attacker — see §9.

### Interfaces (`orchestrator/interfaces.py`)

- **`Sandbox`** — deploy/run the target agent under a policy.
  `deploy(agent, policy) -> Handle`, `exec(handle, action) -> ExecResult`,
  `teardown(handle)`. Mock enforces policy in-process (network/fs/tool
  allow-lists) so violations are observable without OpenShell.
- **`Assessor`** — run adversarial assessments against a deployed agent.
  `assess(handle) -> Assessment` returning a list of `Finding`s
  (id, category, severity, attack vector, evidence). The corpus spans
  data-exfiltration, tool-abuse, prompt-injection, PII-exfiltration, and
  code-injection — each mapping to a distinct OpenShell control. The
  HiddenLayer assessor sends each payload to the live prompt analyzer; the mock
  evaluates them offline.
- **`LLM`** — OpenAI-compatible chat completion.
  `analyze(assessment, policy) -> Recommendation` (root cause, proposed policy
  patch, new test cases). Mock uses rule-based heuristics keyed off finding
  categories, so the loop demonstrably converges offline.
- **`PolicyStore`** — load/save/version policies (`policies/*.yaml`), diff,
  rollback.
- **`Reporter`** — persist per-iteration traces + a run summary
  (`runs/<ts>/`), emit human-readable Markdown.

### Data model (`orchestrator/models.py`, dataclasses)

`Policy`, `Finding` (severity: info|low|medium|high|critical), `Assessment`,
`Recommendation`, `PolicyPatch`, `IterationResult`, `RunResult`.

## 3. The improvement loop (`orchestrator/loop.py`)

Direct realization of PLAN.md "Workflow":

```mermaid
flowchart TD
    START(["load initial policy"]) --> DEPLOY["sandbox.deploy: agent + policy"]
    DEPLOY --> EFF{"enforce?"}
    EFF -- "off (ablation)" --> UNGUARD["policy stripped, all attacks land"]
    EFF -- "on" --> GUARD["policy enforced"]
    UNGUARD --> ASSESS
    GUARD --> ASSESS["assessor.assess (RED): exfil-success-rate"]
    ASSESS --> OPEN{"open findings?"}
    OPEN -- "none" --> CONV(["converged"])
    OPEN -- "same as last round" --> STALL(["no-progress stop"])
    OPEN -- "some" --> ANALYZE["llm.analyze (BLUE): root cause + patch"]
    ANALYZE --> VALID{"patch valid and tightens?"}
    VALID -- "no" --> NOREM(["no applicable remediation"])
    VALID -- "yes" --> APPLY["policy_store.apply, new version"]
    APPLY --> GROW["assessor.add_tests: regression"]
    GROW --> DEPLOY

    class ASSESS red
    class ANALYZE,APPLY blue
    classDef red fill:#3a1418,stroke:#b3153b,color:#f0808f
    classDef blue fill:#12233a,stroke:#3457d5,color:#8fb2ff
```

The pseudocode below is the same loop, showing the actual calls:

```
policy = policy_store.load(initial)
for i in range(max_iters):
    handle     = sandbox.deploy(agent, policy)
    assessment = assessor.assess(handle)          # HiddenLayer
    reporter.record(i, assessment)
    open_findings = assessment.unresolved()
    if not open_findings:                          # convergence
        break
    rec   = llm.analyze(assessment, policy)        # Nemotron
    if rec.patch and rec.patch.is_valid(policy):
        policy = policy_store.apply(rec.patch)     # validated change
    assessor.add_tests(rec.new_tests)              # regression growth
    sandbox.teardown(handle)
report = reporter.summarize()
```

Termination: no open findings, OR `max_iters` reached, OR no-progress guard
(two consecutive iterations with an identical open-finding set → stop, avoids
infinite loops when the LLM can't make progress).

## 4. Policy schema (`policies/baseline.yaml`)

```yaml
version: 1
network:   { default: deny, allow: [] }          # egress allow-list
filesystem:{ read: [/workspace], write: [/workspace/out] }
tools:     { allow: [http_get, file_read], deny: [shell_exec] }
prompt:    { system_guard: true, max_input_tokens: 4000 }
```

A `PolicyPatch` is a structured diff (add/remove allow-list entries, flip a
default, toggle a guard). `is_valid` rejects patches that widen the attack
surface without addressing an open finding.

## 5. Deployment (`docker-compose.yml`)

- `orchestrator` — always built from this repo.
- `vllm` — profile `gpu`; OpenAI-compatible Nemotron endpoint (opt-in).
- Mock backends need no services; the default `docker compose up orchestrator`
  runs the full loop self-contained. Real backends enabled via `.env`
  (`ASSESSOR=hiddenlayer`, `LLM=nemotron`, `SANDBOX=openshell`, + keys/URLs).

## 6. Testing strategy (continuous)

- **Unit** — models, policy patch/validate/rollback, each mock backend.
- **Integration** — full loop on mocks converges to zero findings and is
  deterministic (seeded); no-progress guard terminates; regression tests grow.
- **Contract** — real adapters checked against the same `Protocol` the mocks
  satisfy (import/shape tests; live calls skipped without creds).
- Run: `pytest -q`. Target: fast (<5s), no network, deterministic. CI-ready.

## 7. Config resolution (`orchestrator/config.py`)

Backends chosen by env with `mock` defaults, so `git clone && pytest` works
with zero setup. A `Settings` object is threaded through; no global state.

## 8. Out of scope (initial)

The **HiddenLayer** (Assessor) and **Nemotron/vLLM** (LLM) adapters are fully
implemented against the live services (`orchestrator/backends/real.py`);
HiddenLayer's prompt analyzer supplies real detections and the adapter is
fail-closed. **OpenShell** (Sandbox) remains a credential-guarded seam. The
mocks prove the architecture end-to-end with zero setup; real backends swap in
via env without touching the loop.

## 9. Roles: attacker, defense-in-depth, and the blue reasoner

> **Correcting an earlier mislabel.** HiddenLayer is a **detection layer**, not
> the red team. Its API (`prompt_analyzer` / Runtime Security) *inspects* an
> interaction and classifies threats; it does not *generate* attacks. Earlier
> revisions of this doc called the `Assessor` "the red team" — that conflated
> two different things. The accurate model:

- **Adversarial input — the red side.** The **attack corpus** (payloads we
  author, `DEFAULT_CORPUS`) is the adversary. A future LLM red-team *generator*
  would produce these dynamically; today they are curated.
- **Defense in depth — two layers.**
  - **HiddenLayer Runtime Security** — the *content* layer. It detects and
    classifies malicious content (prompt injection, PII, code, …) with
    OWASP/MITRE mappings; a guardrail policy decides which detected categories to
    block.
  - **NVIDIA OpenShell** — the *capability* layer. It enforces egress / tool /
    filesystem controls and remains the **sole guard on the egress path** (data
    cannot leave except as the policy allows — a different layer from content
    detection, so the two do not conflict).
- **Blue reasoner.** The `LLM` (Nemotron) + `PolicyStore` read the detections and
  outcomes and harden the layer that fits each finding — content threats at
  HiddenLayer, capability/egress threats at OpenShell.

**When does an attack land?** Only if *neither* layer neutralizes it: HiddenLayer
does not detect-and-block it, and OpenShell does not deny the capability it
needs. Different classes are naturally mitigated at different layers — data
exfiltration at OpenShell (egress), prompt injection at HiddenLayer or OpenShell's
system guard, PII at HiddenLayer (redact/block).

**Ablation / recursive-intelligence delta.** `LoopConfig.enforce` /
`--no-enforce` / `OPENSHELL_ENFORCE=false`. With defenses off, blue still learns
but neither layer takes effect, so attack-success-rate stays flat; with defenses
on it drops to zero. `Assessment.success_rate()` = fraction of attacks that still
land; `RunResult.success_delta` is the round-1 → round-N drop; `orchestrator
ablate` reports the difference — the "recursive intelligence" signal.

**Honesty ledger (real vs modeled).**
- *Real:* HiddenLayer detections (live API), the OpenShell-compatible policy
  schema, the loop, and the metrics.
- *Modeled:* whether an attack ultimately *lands* is computed from the defense
  state — there is no real target agent yet; HiddenLayer's *block* action is
  modeled by our guardrail policy (in production these map to the HiddenLayer
  project policy's `block_*` flags); OpenShell enforcement is a stub.

## 10. Reasonable pivot & roadmap

The pivot is **from "HiddenLayer = red team" to "defense-in-depth
co-evaluation":** keep the loop, but model HiddenLayer as the content-detection
layer alongside OpenShell's capability layer, with the corpus as the adversary.

- **Phase A — framing (done).** Corrected the roles here and in the README.
- **Phase B — two-layer defense (done).** Every attack is evaluated against both
  layers (`backends/evaluate.py`): HiddenLayer detection *and* OpenShell
  enforcement. An attack lands only if it evades both; the corpus mixes overt
  attacks (HiddenLayer catches them) with **evasion** attacks (`hl_detects=False`,
  verified against the live API) that slip detection and force OpenShell
  hardening. The report surfaces a **Detection gaps** panel and a per-attack
  two-layer table (HiddenLayer passed/detected · OpenShell open/blocked · stopped
  by). A detection is currently *modeled* as a block; wiring HiddenLayer's real
  `block_*` project policy is future work.
- **Phase C — APE grounding (done).** The corpus is grounded in two real
  references: each attack names its HiddenLayer **APE** technique (how) +
  objective (what) and the **OpenShell** control (surface) it targets. Findings
  link to the APE taxonomy alongside OWASP/MITRE, with CC BY-ND attribution. See
  `references.py` (`ape_refs`) and `backends/corpus.py`.
- **Phase D — LLM red-team generator (in progress).** The taxonomy is vendored
  verbatim (`third_party/ape-taxonomy/ape.json`, CC BY-ND) and loaded by
  `orchestrator/ape.py`; `orchestrator/redteam.py` turns an APE technique clause
  into an LLM instruction that crafts an *evasion* prompt. Verified end-to-end:
  feeding the **HLT05.13 Pretexting** clause to the cloud vLLM produced a prompt
  that **evaded** live HiddenLayer — a real detection gap. Remaining: wire the
  generator into the loop (generate → screen against live HiddenLayer → add
  survivors to the corpus → harden OpenShell), plus a real target agent (observe
  "landing"), `runtime.evaluate_interaction` over full interactions, and driving
  HiddenLayer's project block policy via the API.

This is adapted from a coworker's `redblue-arena` plan
([redblue-arena/](redblue-arena/README.md)); we keep the mechanics that fit a
runnable lab, not the hackathon cloud infra.

"""Shared remediation knowledge: which policy control neutralizes each finding
category, and how to turn an assessment into a Recommendation.

Both the mock LLM and the real (Nemotron/vLLM) adapter use this. The real
adapter lets the model *choose* which finding to address and narrate the root
cause, but validates that choice against this table and falls back here when the
(small) model returns something unusable — so the loop always converges.
"""

from __future__ import annotations

from ..models import (
    Assessment,
    AttackCase,
    Finding,
    PolicyPatch,
    Recommendation,
)

# category -> remediation recipe. `doc` is the OpenShell control documentation
# shown to the blue-team model so it chooses from described controls, not bare
# keywords (see NemotronLLM.analyze).
REMEDIATION: dict[str, dict] = {
    "data_exfiltration": {
        "keyword": "network_default_deny",
        "op": {"op": "set_default", "path": "network.default", "value": "deny"},
        "control": "network.default_deny",
        "root_cause": "Egress is default-allow, permitting data exfiltration.",
        "doc": "sets network.default=deny and drops the exfil host from "
               "network.allow — deny-by-default egress so the agent cannot reach "
               "any host that is not explicitly allow-listed.",
        # Also drop the finding's exfil host from the egress allow-list — with a
        # live OpenShell sandbox this is what actually denies the observed egress
        # (deny-by-default alone leaves a whitelisted host reachable).
        "remove_egress_host": True,
    },
    "tool_abuse": {
        "keyword": "deny_shell_exec",
        "op": {"op": "tool_deny", "path": "tools.deny", "value": "shell_exec"},
        "control": "tools.deny:shell_exec",
        "root_cause": "Dangerous tool shell_exec is reachable by the agent.",
        "doc": "adds shell_exec to tools.deny — removes the shell tool from the "
               "agent's capability set so it cannot run shell commands.",
    },
    "prompt_injection": {
        "keyword": "enable_system_guard",
        "op": {"op": "set_flag", "path": "prompt.system_guard", "value": True},
        "control": "prompt.system_guard",
        "root_cause": "No system-prompt guard, so injected instructions win.",
        "doc": "sets prompt.system_guard=true — pins the system prompt so injected "
               "'ignore previous instructions' style overrides are rejected.",
    },
    "pii_exfiltration": {
        "keyword": "redact_pii",
        "op": {"op": "set_flag", "path": "prompt.pii_redaction", "value": True},
        "control": "prompt.pii_redaction",
        "root_cause": "PII is neither redacted nor blocked, allowing leakage.",
        "doc": "sets prompt.pii_redaction=true — redacts PII/secret patterns from "
               "the agent's inputs and outputs so they cannot be leaked.",
    },
    "code_injection": {
        "keyword": "deny_code_exec",
        "op": {"op": "tool_deny", "path": "tools.deny", "value": "code_exec"},
        "control": "tools.deny:code_exec",
        "root_cause": "An arbitrary code-execution tool is reachable by the agent.",
        "doc": "adds code_exec to tools.deny — removes the code-execution tool so "
               "the agent cannot run arbitrary os/subprocess code.",
    },
}

KEYWORD_TO_CATEGORY = {v["keyword"]: k for k, v in REMEDIATION.items()}

# What the model may pick, formatted for the prompt.
REMEDIATION_MENU = ", ".join(sorted(KEYWORD_TO_CATEGORY))

# The same menu, documented — each keyword with what its OpenShell control does.
CONTROL_DOCS = "\n".join(
    f"- {r['keyword']}: {r['doc']}"
    for _, r in sorted(REMEDIATION.items(), key=lambda kv: kv[1]["keyword"])
)

# A concise, accurate primer on how OpenShell actually enforces policy, so the
# blue-team model reasons with the right mental model. Grounded in NVIDIA's
# OpenShell docs (architecture/security-policy.md + docs/reference/policy-schema)
# — paraphrased, not copied.
OPENSHELL_PRIMER = (
    "OpenShell enforcement model (how the controls above are actually applied):\n"
    "- Default-deny: if no rule matches a request it is DENIED, and explicit deny "
    "rules win over any allow rule. Hardening a gap means removing an allowance or "
    "flipping the default to deny — never adding a broad allow.\n"
    "- Network egress is a per-destination allow-list (host + port + method, "
    "optionally per calling binary). Egress to any host not explicitly allow-listed "
    "is blocked; wildcards are permitted only in the first DNS label (bare '*' and "
    "TLD wildcards are rejected).\n"
    "- Capabilities/tools: the agent runs unprivileged with reduced Linux "
    "capabilities and seccomp; denying a tool removes that capability entirely.\n"
    "- Filesystem is Landlock-enforced read-only/read-write path sets ('/' and '..' "
    "are rejected as overly broad)."
)


def control_for(category: str) -> str:
    r = REMEDIATION.get(category)
    return r["control"] if r else ""


def pick_highest_severity(assessment: Assessment) -> Finding | None:
    openf = assessment.unresolved()
    if not openf:
        return None
    return max(openf, key=lambda f: (f.severity, f.id))


def build_recommendation(
    target: Finding,
    *,
    source: str,
    narrative: str = "",
    latency_ms: float = 0.0,
) -> Recommendation:
    """Turn a chosen finding into a validated Recommendation + regression test."""
    remedy = REMEDIATION.get(target.category)
    if remedy is None:
        return Recommendation(
            root_cause=f"no known remediation for {target.category}",
            patch=PolicyPatch(),
            source=source,
            latency_ms=latency_ms,
            llm_narrative=narrative,
        )
    ops = [dict(remedy["op"])]
    # For egress findings, also remove the whitelisted exfil host so a live
    # OpenShell sandbox truly denies it (observed: reachable -> 403 next round).
    if remedy.get("remove_egress_host") and target.egress_host:
        ops.append({"op": "allow_remove", "path": "network.allow",
                    "value": target.egress_host})
    patch = PolicyPatch(
        ops=ops,
        rationale=remedy["root_cause"],
        addresses=frozenset({target.id}),
    )
    regression = AttackCase(
        id=f"REG-{target.id}",
        category=target.category,
        severity=target.severity,
        # Reuse the real attack payload so the regression case is itself a live
        # attack (a real detector re-checks it), not a placeholder string.
        payload=target.attack_vector,
        requires_control=remedy["control"],
        # Carry over the detection outcome: a landed finding evaded HiddenLayer,
        # so its regression guard is also an evasion case OpenShell must hold.
        hl_detects=target.hl_detected,
        # Keep probing the same real host so the regression is observed too.
        egress_host=target.egress_host,
    )
    return Recommendation(
        root_cause=narrative or remedy["root_cause"],
        patch=patch,
        new_tests=[regression],
        source=source,
        latency_ms=latency_ms,
        llm_narrative=narrative,
    )


def heuristic_recommendation(assessment: Assessment) -> Recommendation:
    """Deterministic fallback: fix the single highest-severity open finding."""
    target = pick_highest_severity(assessment)
    if target is None:
        return Recommendation("no open findings", PolicyPatch(), source="heuristic")
    return build_recommendation(target, source="heuristic")

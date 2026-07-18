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

# category -> remediation recipe
REMEDIATION: dict[str, dict] = {
    "data_exfiltration": {
        "keyword": "network_default_deny",
        "op": {"op": "set_default", "path": "network.default", "value": "deny"},
        "control": "network.default_deny",
        "root_cause": "Egress is default-allow, permitting data exfiltration.",
    },
    "tool_abuse": {
        "keyword": "deny_shell_exec",
        "op": {"op": "tool_deny", "path": "tools.deny", "value": "shell_exec"},
        "control": "tools.deny:shell_exec",
        "root_cause": "Dangerous tool shell_exec is reachable by the agent.",
    },
    "prompt_injection": {
        "keyword": "enable_system_guard",
        "op": {"op": "set_flag", "path": "prompt.system_guard", "value": True},
        "control": "prompt.system_guard",
        "root_cause": "No system-prompt guard, so injected instructions win.",
    },
}

KEYWORD_TO_CATEGORY = {v["keyword"]: k for k, v in REMEDIATION.items()}

# What the model may pick, formatted for the prompt.
REMEDIATION_MENU = ", ".join(sorted(KEYWORD_TO_CATEGORY))


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
    patch = PolicyPatch(
        ops=[dict(remedy["op"])],
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

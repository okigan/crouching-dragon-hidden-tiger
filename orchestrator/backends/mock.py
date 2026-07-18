"""Deterministic, network-free mock backends.

These are the default implementations: they let `git clone && pytest` exercise
the entire improvement loop with zero credentials or GPUs, and they make the
loop's convergence a testable property. Real backends (backends/real.py) satisfy
the same Protocols and swap in via config.
"""

from __future__ import annotations

from ..models import (
    AttackCase,
    Assessment,
    Finding,
    Policy,
    PolicyPatch,
    Recommendation,
    Severity,
)
from .corpus import DEFAULT_CORPUS


class MockSandbox:
    """In-process 'deployment'. There is no real isolation; instead the policy
    is what gets assessed, which is faithful to how the loop reasons."""

    def __init__(self) -> None:
        self._deployed: dict[str, tuple[str, Policy]] = {}
        self._counter = 0

    def deploy(self, agent: str, policy: Policy) -> str:
        self._counter += 1
        handle = f"mock-{self._counter}"
        self._deployed[handle] = (agent, policy.copy())
        return handle

    def teardown(self, handle: str) -> None:
        self._deployed.pop(handle, None)

    def policy_for(self, handle: str) -> Policy:
        return self._deployed[handle][1]


class MockAssessor:
    """Runs the corpus against a policy. A case yields a Finding iff the control
    it requires is not active in that policy."""

    def __init__(self, corpus: list[AttackCase] | None = None) -> None:
        self._corpus: list[AttackCase] = list(
            corpus if corpus is not None else DEFAULT_CORPUS
        )

    def assess(self, handle: str, policy: Policy) -> Assessment:
        active = policy.controls()
        findings: list[Finding] = []
        for case in self._corpus:
            defended = case.requires_control in active
            findings.append(
                Finding(
                    id=case.id,
                    category=case.category,
                    severity=case.severity,
                    attack_vector=case.payload,
                    evidence=(
                        f"defended by {case.requires_control}"
                        if defended
                        else f"missing control {case.requires_control}"
                    ),
                    resolved=defended,
                )
            )
        return Assessment(findings=findings)

    def add_tests(self, cases: list[AttackCase]) -> None:
        known = {c.id for c in self._corpus}
        for c in cases:
            if c.id not in known:
                self._corpus.append(c)
                known.add(c.id)

    @property
    def corpus_size(self) -> int:
        return len(self._corpus)


# Maps a finding category to the patch op that installs the fixing control, plus
# a regression test to add. This is the mock stand-in for Nemotron's reasoning.
_REMEDIATION: dict[str, dict] = {
    "data_exfiltration": {
        "op": {"op": "set_default", "path": "network.default", "value": "deny"},
        "root_cause": "Egress is default-allow, permitting exfiltration.",
    },
    "tool_abuse": {
        "op": {"op": "tool_deny", "path": "tools.deny", "value": "shell_exec"},
        "root_cause": "Dangerous tool shell_exec is reachable by the agent.",
    },
    "prompt_injection": {
        "op": {"op": "set_flag", "path": "prompt.system_guard", "value": True},
        "root_cause": "No system-prompt guard, so injected instructions win.",
    },
}


class MockLLM:
    """Heuristic reasoning: addresses the single highest-severity open finding
    per iteration (fix-one-at-a-time makes convergence observable across
    multiple iterations). Returns an empty patch for categories it can't fix,
    which the no-progress guard then catches."""

    def analyze(self, assessment: Assessment, policy: Policy) -> Recommendation:
        open_findings = assessment.unresolved()
        if not open_findings:
            return Recommendation(root_cause="no open findings", patch=PolicyPatch())

        target = max(open_findings, key=lambda f: (f.severity, f.id))
        remedy = _REMEDIATION.get(target.category)
        if remedy is None:
            return Recommendation(
                root_cause=f"no known remediation for {target.category}",
                patch=PolicyPatch(),
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
            payload=f"regression guard for {target.id}",
            requires_control=_control_for(target.category),
        )
        return Recommendation(
            root_cause=remedy["root_cause"],
            patch=patch,
            new_tests=[regression],
        )


def _control_for(category: str) -> str:
    return {
        "data_exfiltration": "network.default_deny",
        "tool_abuse": "tools.deny:shell_exec",
        "prompt_injection": "prompt.system_guard",
    }.get(category, "")

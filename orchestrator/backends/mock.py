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
    Recommendation,
)
from .corpus import DEFAULT_CORPUS
from .remediation import heuristic_recommendation


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


class MockLLM:
    """Heuristic reasoning stand-in: addresses the single highest-severity open
    finding per iteration (fix-one-at-a-time makes convergence observable across
    iterations). Shares its remediation logic with the real adapter's fallback."""

    def analyze(self, assessment: Assessment, policy: Policy) -> Recommendation:
        return heuristic_recommendation(assessment)

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
from ..references import refs_for_category
from .corpus import DEFAULT_CORPUS
from .evaluate import evaluate
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

    # Representative HiddenLayer signals for the simulated (offline) detector.
    _SIGNALS = {
        "prompt_injection": ("prompt_injection", "unsafe_input"),
        "pii_exfiltration": ("input_pii", "unsafe_input"),
    }

    def assess(self, handle: str, policy: Policy) -> Assessment:
        findings: list[Finding] = []
        for case in self._corpus:
            signals = (
                self._SIGNALS.get(case.category, ("unsafe_input",))
                if case.hl_detects else ()
            )
            hl_note = (
                f"HiddenLayer detected (simulated): {', '.join(signals)}"
                if case.hl_detects
                else "0 signals — bypassed HiddenLayer (simulated)"
            )
            findings.append(
                evaluate(
                    case, case.hl_detects, hl_note, policy,
                    refs_for_category(case.category), hl_signals=signals,
                )
            )
        return Assessment(findings=findings)

    def add_tests(self, cases: list[AttackCase]) -> None:
        known = {c.id for c in self._corpus}
        for c in cases:
            if c.id not in known:
                self._corpus.append(c)
                known.add(c.id)

    def detect(self, prompt: str) -> bool:
        """Screening hook for the generator. The mock has no real detector, so it
        treats generated candidates as evasions (they are crafted to slip past
        content detection)."""
        return False

    @property
    def corpus_size(self) -> int:
        return len(self._corpus)


class MockLLM:
    """Heuristic reasoning stand-in: addresses the single highest-severity open
    finding per iteration (fix-one-at-a-time makes convergence observable across
    iterations). Shares its remediation logic with the real adapter's fallback."""

    def analyze(self, assessment: Assessment, policy: Policy) -> Recommendation:
        return heuristic_recommendation(assessment)

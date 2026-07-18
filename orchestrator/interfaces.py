"""Adapter seams. Every external component (OpenShell, HiddenLayer, Nemotron)
is reachable only through one of these Protocols. The orchestrator depends on
these abstractions, never on a concrete backend — see docs/DESIGN.md §2.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import (
    AttackCase,
    Assessment,
    Policy,
    Recommendation,
)


@runtime_checkable
class Sandbox(Protocol):
    """Secure execution environment for the target agent (NVIDIA OpenShell)."""

    def deploy(self, agent: str, policy: Policy) -> str:
        """Deploy ``agent`` under ``policy``; return an opaque handle."""

    def teardown(self, handle: str) -> None:
        ...


@runtime_checkable
class Assessor(Protocol):
    """Adversarial security testing (HiddenLayer)."""

    def assess(self, handle: str, policy: Policy) -> Assessment:
        """Run the attack corpus against the deployed agent under ``policy``."""

    def add_tests(self, cases: list[AttackCase]) -> None:
        """Grow the corpus with regression cases (from LLM recommendations)."""


@runtime_checkable
class LLM(Protocol):
    """OpenAI-compatible reasoning endpoint (Nemotron on vLLM)."""

    def analyze(self, assessment: Assessment, policy: Policy) -> Recommendation:
        """Root-cause the findings and propose a validated remediation."""


@runtime_checkable
class Reporter(Protocol):
    """Persists traces and emits human-readable run summaries."""

    def record_iteration(self, index: int, assessment: Assessment, policy: Policy) -> None:
        ...

    def summarize(self, run) -> str:  # run: RunResult (avoid import cycle in hint)
        ...

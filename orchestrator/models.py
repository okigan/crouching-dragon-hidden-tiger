"""Core domain data model for Crouching Dragon Hidden Tiger.

Pure data + small pure helpers. No I/O, no backend imports — this module is the
shared vocabulary every component (mock or real) speaks. See docs/DESIGN.md §2.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered so severities compare and sort naturally (critical is largest)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]

    def __str__(self) -> str:  # human-facing (reports, CLI)
        return self.name.lower()


@dataclass(frozen=True)
class DocRef:
    """A link to real documentation for a finding's threat class (e.g. the
    OWASP LLM Top-10 entry or MITRE ATLAS technique the detector mapped it to)."""

    source: str  # "OWASP", "MITRE ATLAS", "HiddenLayer"
    label: str   # "LLM01", "AML.T0051", ...
    name: str
    url: str


@dataclass(frozen=True)
class Finding:
    """A single vulnerability surfaced by an Assessor."""

    id: str
    category: str  # e.g. prompt_injection, data_exfiltration, tool_abuse, jailbreak
    severity: Severity
    attack_vector: str
    evidence: str
    resolved: bool = False
    references: tuple[DocRef, ...] = ()  # real docs for this threat class
    # Defense-in-depth outcome (§9): which layer, if any, stopped this attack.
    hl_detected: bool = False        # HiddenLayer flagged the payload (content layer)
    openshell_blocked: bool = False  # OpenShell policy denies the capability
    hl_signals: tuple[str, ...] = () # the HiddenLayer signals that fired (empty = bypass)

    def resolve(self) -> "Finding":
        return replace(self, resolved=True)


@dataclass
class Assessment:
    """The result of one adversarial assessment pass."""

    findings: list[Finding] = field(default_factory=list)

    def unresolved(self) -> list[Finding]:
        return [f for f in self.findings if not f.resolved]

    def open_ids(self) -> frozenset[str]:
        return frozenset(f.id for f in self.unresolved())

    def max_severity(self) -> Severity:
        openf = self.unresolved()
        return max((f.severity for f in openf), default=Severity.INFO)

    def success_rate(self) -> float:
        """Exfil-success-rate: fraction of attack cases that still land (are not
        defended by the enforced policy). The headline metric — it drops toward
        zero as blue hardens the policy across rounds."""
        if not self.findings:
            return 0.0
        return len(self.unresolved()) / len(self.findings)


@dataclass
class PolicyPatch:
    """A structured, auditable change to a policy.

    ``ops`` is a list of operations, each a dict with keys:
      - op: "allow_add" | "allow_remove" | "set_default" | "set_flag" |
            "tool_deny" | "tool_allow"
      - path: dotted policy path, e.g. "network.allow", "tools.deny",
              "network.default", "prompt.system_guard"
      - value: entry / default / flag value
    """

    ops: list[dict[str, Any]] = field(default_factory=list)
    rationale: str = ""
    addresses: frozenset[str] = frozenset()  # finding ids this patch targets

    def is_empty(self) -> bool:
        return not self.ops

    def widens_surface(self) -> bool:
        """True if any op relaxes a control (grows the attack surface)."""
        for op in self.ops:
            kind = op.get("op")
            if kind in ("allow_add", "tool_allow"):
                return True
            if kind == "set_default" and op.get("value") == "allow":
                return True
            if kind == "set_flag" and op.get("value") is False:
                return True
        return False

    def is_valid(self, policy: "Policy") -> bool:
        """A patch is valid if it targets an open finding and does not widen
        the attack surface (defense-in-depth: we only ever tighten here)."""
        if self.is_empty():
            return False
        if self.widens_surface():
            return False
        return bool(self.addresses)


@dataclass
class Recommendation:
    """LLM output: analysis plus a proposed remediation."""

    root_cause: str
    patch: PolicyPatch
    new_tests: list["AttackCase"] = field(default_factory=list)
    # Provenance for the visual report: which backend produced this and how.
    source: str = "heuristic"  # heuristic | nemotron | nemotron-fallback
    latency_ms: float = 0.0
    llm_narrative: str = ""  # raw model text, when an LLM was consulted


@dataclass(frozen=True)
class AttackCase:
    """A reproducible adversarial test case an Assessor can execute."""

    id: str
    category: str
    severity: Severity
    payload: str
    # Which OpenShell control neutralizes this attack; when the control is active
    # the assessor treats the capability layer as blocking it.
    requires_control: str = ""
    # Whether HiddenLayer's content detection is expected to flag this payload.
    # False = an evasion / detection gap that only OpenShell can catch. The live
    # HiddenLayer assessor overrides this with the real API verdict; the mock and
    # the offline default use it directly.
    hl_detects: bool = True
    # Grounding in HiddenLayer's APE taxonomy (ape.hiddenlayer.com): which
    # adversarial-prompt technique this attack uses (how) and objective (what).
    ape_technique: str = ""  # e.g. "HLT05.13"
    ape_objective: str = ""  # e.g. "HLG01.03"


@dataclass
class Policy:
    """Runtime protection policy enforced by the Sandbox. Mirrors the yaml
    schema in policies/baseline.yaml (see docs/DESIGN.md §4)."""

    version: int = 1
    network: dict[str, Any] = field(
        default_factory=lambda: {"default": "deny", "allow": []}
    )
    filesystem: dict[str, Any] = field(
        default_factory=lambda: {"read": [], "write": []}
    )
    tools: dict[str, Any] = field(
        default_factory=lambda: {"allow": [], "deny": []}
    )
    prompt: dict[str, Any] = field(
        default_factory=lambda: {
            "system_guard": False,
            "pii_redaction": False,
            "max_input_tokens": 4000,
        }
    )

    def copy(self) -> "Policy":
        return Policy(
            version=self.version,
            network=copy.deepcopy(self.network),
            filesystem=copy.deepcopy(self.filesystem),
            tools=copy.deepcopy(self.tools),
            prompt=copy.deepcopy(self.prompt),
        )

    # --- dotted-path access used by patches -------------------------------
    def _section(self, section: str) -> dict[str, Any]:
        if not hasattr(self, section):
            raise KeyError(f"unknown policy section: {section}")
        return getattr(self, section)

    def get_path(self, path: str) -> Any:
        section, _, key = path.partition(".")
        return self._section(section)[key]

    def controls(self) -> frozenset[str]:
        """The set of active protection controls, named the way AttackCases
        reference them via ``requires_control``."""
        active: set[str] = set()
        if self.network.get("default") == "deny":
            active.add("network.default_deny")
        if self.prompt.get("system_guard"):
            active.add("prompt.system_guard")
        if self.prompt.get("pii_redaction"):
            active.add("prompt.pii_redaction")
        for tool in self.tools.get("deny", []):
            active.add(f"tools.deny:{tool}")
        return frozenset(active)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "network": copy.deepcopy(self.network),
            "filesystem": copy.deepcopy(self.filesystem),
            "tools": copy.deepcopy(self.tools),
            "prompt": copy.deepcopy(self.prompt),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        base = cls()
        return cls(
            version=int(data.get("version", base.version)),
            network={**base.network, **data.get("network", {})},
            filesystem={**base.filesystem, **data.get("filesystem", {})},
            tools={**base.tools, **data.get("tools", {})},
            prompt={**base.prompt, **data.get("prompt", {})},
        )


@dataclass
class IterationResult:
    index: int
    open_before: frozenset[str]
    open_after: frozenset[str]
    applied_patch: PolicyPatch | None
    max_severity: Severity


@dataclass
class RunResult:
    iterations: list[IterationResult] = field(default_factory=list)
    converged: bool = False
    stop_reason: str = ""
    final_policy: Policy | None = None
    enforce: bool = True
    success_rates: list[float] = field(default_factory=list)  # per round

    @property
    def iteration_count(self) -> int:
        return len(self.iterations)

    @property
    def initial_success(self) -> float:
        return self.success_rates[0] if self.success_rates else 0.0

    @property
    def final_success(self) -> float:
        return self.success_rates[-1] if self.success_rates else 0.0

    @property
    def success_delta(self) -> float:
        """Round-1 → round-N drop in exfil-success-rate (positive = improvement)."""
        return self.initial_success - self.final_success

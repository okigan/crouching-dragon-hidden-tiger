"""The security improvement loop — the heart of the platform.

Directly realizes the PLAN.md workflow: deploy → assess → analyze → patch →
re-assess, repeating until no new vulnerabilities remain. Depends only on the
Protocols in interfaces.py, so it runs identically over mock or real backends.
"""

from __future__ import annotations

from dataclasses import dataclass

from .interfaces import LLM, Assessor, Reporter, Sandbox
from .models import IterationResult, Policy, RunResult
from .policy_store import PolicyStore


@dataclass
class LoopConfig:
    agent: str = "target-agent"
    max_iters: int = 10


class SecurityOrchestrator:
    def __init__(
        self,
        sandbox: Sandbox,
        assessor: Assessor,
        llm: LLM,
        store: PolicyStore,
        reporter: Reporter,
        config: LoopConfig | None = None,
    ) -> None:
        self.sandbox = sandbox
        self.assessor = assessor
        self.llm = llm
        self.store = store
        self.reporter = reporter
        self.config = config or LoopConfig()

    def run(self) -> RunResult:
        result = RunResult()
        prev_open: frozenset[str] | None = None

        for i in range(self.config.max_iters):
            policy: Policy = self.store.current
            handle = self.sandbox.deploy(self.config.agent, policy)
            try:
                assessment = self.assessor.assess(handle, policy)
                open_before = assessment.open_ids()

                # Convergence: nothing left to fix.
                if not open_before:
                    self.reporter.record_iteration(i, assessment, policy)
                    result.iterations.append(
                        IterationResult(i, open_before, open_before, None,
                                        assessment.max_severity())
                    )
                    result.converged = True
                    result.stop_reason = "no open findings"
                    break

                # No-progress guard: identical open set to last iteration means
                # the LLM cannot make headway — stop rather than spin forever.
                if prev_open is not None and open_before == prev_open:
                    self.reporter.record_iteration(i, assessment, policy)
                    result.iterations.append(
                        IterationResult(i, open_before, open_before, None,
                                        assessment.max_severity())
                    )
                    result.stop_reason = "no progress (stalled findings)"
                    break

                rec = self.llm.analyze(assessment, policy)
                applied = None
                if not rec.patch.is_empty() and rec.patch.is_valid(policy):
                    self.store.apply(rec.patch)
                    applied = rec.patch
                if rec.new_tests:
                    self.assessor.add_tests(rec.new_tests)

                self.reporter.record_iteration(i, assessment, policy, rec)
                result.iterations.append(
                    IterationResult(
                        index=i,
                        open_before=open_before,
                        open_after=frozenset(),  # measured next iteration
                        applied_patch=applied,
                        max_severity=assessment.max_severity(),
                    )
                )
                prev_open = open_before

                # If the LLM had no valid patch, further iterations can't help.
                if applied is None:
                    result.stop_reason = "no applicable remediation"
                    break
            finally:
                self.sandbox.teardown(handle)
        else:
            result.stop_reason = "max iterations reached"

        result.final_policy = self.store.current
        return result

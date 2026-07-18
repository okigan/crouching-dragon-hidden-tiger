from orchestrator.backends.mock import MockAssessor, MockLLM, MockSandbox
from orchestrator.loop import LoopConfig, SecurityOrchestrator
from orchestrator.models import (
    Assessment,
    AttackCase,
    Finding,
    Policy,
    Recommendation,
    PolicyPatch,
    Severity,
)
from orchestrator.policy_store import PolicyStore
from orchestrator.reporter import Reporter

POLICY_PATH = "policies/baseline.yaml"


def build(store=None, assessor=None, llm=None, max_iters=10):
    return SecurityOrchestrator(
        sandbox=MockSandbox(),
        assessor=assessor or MockAssessor(),
        llm=llm or MockLLM(),
        store=store or PolicyStore.load(POLICY_PATH),
        reporter=Reporter(),
        config=LoopConfig(max_iters=max_iters),
    )


def test_loop_converges_to_zero_findings():
    store = PolicyStore.load(POLICY_PATH)
    orch = build(store=store)
    result = orch.run()
    assert result.converged is True
    assert result.stop_reason == "no open findings"
    # 3 HiddenLayer-evading attacks land; each fixed in OpenShell, +1 verify = 4
    assert result.iteration_count == 4
    # starts at 60% (3 of 5 land), converges to 0
    assert result.success_rates[0] == 0.6
    assert result.final_success == 0.0
    # OpenShell hardened for the evaders only (the 2 detected ones were caught
    # by HiddenLayer, so no OpenShell control was needed for them)
    fp = result.final_policy
    assert fp.network["default"] == "deny"
    assert "shell_exec" in fp.tools["deny"]
    assert "code_exec" in fp.tools["deny"]


def test_loop_is_deterministic():
    r1 = build().run()
    r2 = build().run()
    assert r1.iteration_count == r2.iteration_count
    assert r1.converged == r2.converged
    assert r1.final_policy.to_dict() == r2.final_policy.to_dict()


class StuckLLM:
    """Never produces a usable patch -> loop must not spin forever."""

    def analyze(self, assessment, policy):
        return Recommendation(root_cause="stuck", patch=PolicyPatch())


def test_no_applicable_remediation_terminates():
    result = build(llm=StuckLLM()).run()
    assert result.converged is False
    assert result.stop_reason == "no applicable remediation"
    assert result.iteration_count == 1


class OneStaleFinding:
    """Assessor that always reports the same single open finding, and an LLM
    that 'fixes' nothing -> exercises the no-progress guard path."""

    def assess(self, handle, policy):
        return Assessment(findings=[
            Finding("STALE", "unknown_cat", Severity.MEDIUM, "v", "e")
        ])

    def add_tests(self, cases):
        pass


def test_no_progress_guard_terminates():
    # Real MockLLM returns empty patch for unknown category -> first iter stops
    # with "no applicable remediation". To reach the no-progress branch we use an
    # LLM that always claims to patch but the assessor never improves.
    class PretendPatchLLM:
        def analyze(self, assessment, policy):
            # valid-looking patch that does not change controls the assessor checks
            return Recommendation(
                root_cause="pretend",
                patch=PolicyPatch(
                    ops=[{"op": "tool_deny", "path": "tools.deny", "value": "noop"}],
                    addresses=frozenset({"STALE"}),
                ),
            )

    orch = build(assessor=OneStaleFinding(), llm=PretendPatchLLM(), max_iters=10)
    result = orch.run()
    assert result.stop_reason == "no progress (stalled findings)"
    assert result.converged is False


def test_max_iters_respected():
    # tiny cap with a productive but slow scenario
    result = build(max_iters=1).run()
    assert result.iteration_count == 1

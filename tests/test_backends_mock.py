from orchestrator.backends.mock import MockAssessor, MockLLM, MockSandbox
from orchestrator.models import AttackCase, Policy, Severity


def weak_policy() -> Policy:
    p = Policy()
    p.network["default"] = "allow"  # Policy() defaults to deny; open it up
    p.prompt["system_guard"] = False
    p.tools["deny"] = []
    return p


def hardened_policy() -> Policy:
    p = Policy()
    p.network["default"] = "deny"
    p.prompt["system_guard"] = True
    p.prompt["pii_redaction"] = True
    p.tools["deny"] = ["shell_exec", "code_exec"]
    return p


def test_sandbox_deploy_teardown():
    sb = MockSandbox()
    h = sb.deploy("agent", Policy())
    assert sb.policy_for(h) is not None
    sb.teardown(h)


def test_assessor_findings_gated_by_policy():
    assessor = MockAssessor()
    weak = assessor.assess("h", weak_policy())  # open egress, no guard, no deny
    # only the 3 HiddenLayer-evading attacks land; the 2 it detects are caught
    assert len(weak.unresolved()) == 3
    assert {f.id for f in weak.unresolved()} == {"ATK-101", "ATK-102", "ATK-103"}

    strong = assessor.assess("h", hardened_policy())
    assert strong.unresolved() == []  # all defended


def test_assessor_add_tests_dedupes():
    assessor = MockAssessor()
    n = assessor.corpus_size
    case = AttackCase("NEW", "tool_abuse", Severity.HIGH, "p", "x")
    assessor.add_tests([case])
    assessor.add_tests([case])  # duplicate id ignored
    assert assessor.corpus_size == n + 1


def test_llm_targets_highest_severity_open_finding():
    assessor = MockAssessor()
    assessment = assessor.assess("h", weak_policy())
    rec = MockLLM().analyze(assessment, weak_policy())
    # highest severity landed (evader) finding, ties by id: ATK-103 (CRITICAL code)
    assert rec.patch.addresses == {"ATK-103"}
    assert rec.patch.ops[0]["path"] == "tools.deny"
    assert rec.new_tests and rec.new_tests[0].id == "REG-ATK-103"


def test_llm_empty_patch_when_no_open_findings():
    rec = MockLLM().analyze(MockAssessor().assess("h", hardened_policy()), Policy())
    assert rec.patch.is_empty()

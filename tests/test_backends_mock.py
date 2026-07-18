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
    assert len(weak.unresolved()) == 5

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
    # highest severity, ties broken by id: ATK-005 (CRITICAL) is addressed first
    assert rec.patch.addresses == {"ATK-005"}
    assert rec.patch.ops[0]["path"] == "tools.deny"
    assert rec.new_tests and rec.new_tests[0].id == "REG-ATK-005"


def test_llm_empty_patch_when_no_open_findings():
    rec = MockLLM().analyze(MockAssessor().assess("h", hardened_policy()), Policy())
    assert rec.patch.is_empty()

from orchestrator.models import (
    Assessment,
    Finding,
    Policy,
    PolicyPatch,
    Severity,
)


def test_severity_ordering_and_parse():
    assert Severity.CRITICAL > Severity.HIGH > Severity.LOW
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse(4) is Severity.CRITICAL
    assert str(Severity.MEDIUM) == "medium"


def test_assessment_open_and_max_severity():
    a = Assessment(findings=[
        Finding("A", "tool_abuse", Severity.HIGH, "v", "e", resolved=False),
        Finding("B", "prompt_injection", Severity.CRITICAL, "v", "e", resolved=True),
    ])
    assert a.open_ids() == {"A"}
    assert a.max_severity() is Severity.HIGH  # B is resolved


def test_policy_controls_reflect_hardening():
    p = Policy()
    p.network["default"] = "deny"
    p.prompt["system_guard"] = True
    p.tools["deny"] = ["shell_exec"]
    controls = p.controls()
    assert "network.default_deny" in controls
    assert "prompt.system_guard" in controls
    assert "tools.deny:shell_exec" in controls


def test_policy_roundtrip_dict():
    p = Policy.from_dict({"version": 3, "network": {"default": "deny"}})
    assert p.version == 3
    assert p.network["default"] == "deny"
    assert Policy.from_dict(p.to_dict()).to_dict() == p.to_dict()


def test_patch_validity_rules():
    p = Policy()
    # widening the surface is always invalid
    widen = PolicyPatch(
        ops=[{"op": "allow_add", "path": "network.allow", "value": "x"}],
        addresses=frozenset({"A"}),
    )
    assert widen.widens_surface() is True
    assert widen.is_valid(p) is False

    # tightening + targets a finding = valid
    tighten = PolicyPatch(
        ops=[{"op": "set_default", "path": "network.default", "value": "deny"}],
        addresses=frozenset({"A"}),
    )
    assert tighten.is_valid(p) is True

    # tightening but addresses nothing = invalid
    assert PolicyPatch(
        ops=[{"op": "set_flag", "path": "prompt.system_guard", "value": True}]
    ).is_valid(p) is False

    # empty patch = invalid
    assert PolicyPatch().is_valid(p) is False

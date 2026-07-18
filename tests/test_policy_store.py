import pytest

from orchestrator.models import Policy, PolicyPatch
from orchestrator.policy_store import PolicyError, PolicyStore

POLICY_PATH = "policies/baseline.yaml"


def test_load_baseline():
    store = PolicyStore.load(POLICY_PATH)
    p = store.current
    assert p.network["default"] == "allow"
    assert "shell_exec" in p.tools["allow"]
    assert p.prompt["system_guard"] is False


def test_apply_tool_deny_moves_out_of_allow_and_versions():
    store = PolicyStore.load(POLICY_PATH)
    patch = PolicyPatch(
        ops=[{"op": "tool_deny", "path": "tools.deny", "value": "shell_exec"}],
        addresses=frozenset({"ATK-002"}),
    )
    before_v = store.current.version
    store.apply(patch)
    assert store.current.version == before_v + 1
    assert "shell_exec" in store.current.tools["deny"]
    assert "shell_exec" not in store.current.tools["allow"]
    assert store.version_count == 2


def test_rollback_restores_previous():
    store = PolicyStore.load(POLICY_PATH)
    patch = PolicyPatch(
        ops=[{"op": "set_flag", "path": "prompt.system_guard", "value": True}],
        addresses=frozenset({"ATK-003"}),
    )
    store.apply(patch)
    assert store.current.prompt["system_guard"] is True
    store.rollback()
    assert store.current.prompt["system_guard"] is False
    with pytest.raises(PolicyError):
        store.rollback()  # nothing left


def test_apply_invalid_patch_rejected():
    store = PolicyStore.load(POLICY_PATH)
    with pytest.raises(PolicyError):
        store.apply(PolicyPatch())  # empty -> invalid


def test_diff_reports_changed_sections():
    store = PolicyStore.load(POLICY_PATH)
    older = store.current.copy()
    store.apply(PolicyPatch(
        ops=[{"op": "set_default", "path": "network.default", "value": "deny"}],
        addresses=frozenset({"ATK-001"}),
    ))
    d = store.diff(older, store.current)
    assert "network" in d
    assert d["network"]["before"]["default"] == "allow"
    assert d["network"]["after"]["default"] == "deny"


def test_save_roundtrip(tmp_path):
    store = PolicyStore.load(POLICY_PATH)
    out = tmp_path / "hardened.yaml"
    store.save(out)
    reloaded = PolicyStore.load(out)
    assert reloaded.current.to_dict() == store.current.to_dict()

"""Offline tests for the Policy -> real OpenShell policy.yaml translation."""

from orchestrator.backends.openshell_policy import to_openshell
from orchestrator.models import Policy


def test_deny_egress_produces_no_endpoints():
    # our hardened policy (network default deny) -> OpenShell deny-all egress
    p = Policy(network={"default": "deny", "allow": []})
    out = to_openshell(p)
    assert out["network_policies"] == {}          # no endpoints => blocked
    assert out["version"] == 1


def test_allow_hosts_become_enforced_endpoints():
    p = Policy(network={"default": "allow", "allow": ["api.github.com"]})
    eps = to_openshell(p)["network_policies"]["egress_allow"]["endpoints"]
    assert eps[0]["host"] == "api.github.com"
    assert eps[0]["enforcement"] == "enforce"
    assert eps[0]["access"] == "read-only"


def test_static_filesystem_paths_preserved():
    # /app must be present or a live `policy set` is rejected by OpenShell
    out = to_openshell(Policy())
    assert "/app" in out["filesystem_policy"]["read_only"]
    assert out["process"]["run_as_user"] == "sandbox"
    assert out["landlock"]["compatibility"] == "best_effort"


def test_extra_filesystem_paths_merge():
    p = Policy(filesystem={"read": ["/data"], "write": ["/out"]})
    fs = to_openshell(p)["filesystem_policy"]
    assert "/data" in fs["read_only"] and "/out" in fs["read_write"]

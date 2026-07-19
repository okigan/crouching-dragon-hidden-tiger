"""The observed OpenShell-egress path: the assessor exec's a real egress attempt
inside a live sandbox and uses that verdict instead of the modeled control (see
DESIGN §9). All stubbed — no gateway, no network."""

from orchestrator.backends import real
from orchestrator.backends.evaluate import evaluate
from orchestrator.backends.remediation import build_recommendation
from orchestrator.models import AttackCase, Finding, Policy, Severity


# --- OpenShellSandbox.egress_probe interprets curl exit codes ------------------

def _sandbox_with_exec(result):
    s = real.OpenShellSandbox("http://gw:8080")
    s.exec = lambda handle, cmd, timeout=60.0: result  # inject
    return s


def test_egress_probe_reachable_is_not_blocked():
    s = _sandbox_with_exec((0, "200"))
    blocked, note = s.egress_probe("h", "example.com")
    assert blocked is False and "SUCCEEDED" in note


def test_egress_probe_denied_is_blocked():
    s = _sandbox_with_exec((56, "curl: (56) CONNECT tunnel failed, response 403\n000"))
    blocked, note = s.egress_probe("h", "example.com")
    assert blocked is True and "DENIED" in note and "403" in note


# --- evaluate() prefers the observed verdict over the modeled control ----------

def test_evaluate_uses_observed_over_model():
    case = AttackCase(id="ATK-101", category="data_exfiltration",
                      severity=Severity.CRITICAL, payload="exfil",
                      requires_control="network.default_deny", hl_detects=False,
                      egress_host="example.com")
    # Modeled would say "not blocked" under a permissive policy; observed says blocked.
    f = evaluate(case, False, "0 signals", Policy(), (), observed=(True, "DENIED"))
    assert f.openshell_blocked is True and f.openshell_observed is True
    assert f.resolved is True and f.egress_host == "example.com"
    assert "DENIED" in f.evidence


def test_evaluate_modeled_when_not_observed():
    case = AttackCase(id="ATK-101", category="data_exfiltration",
                      severity=Severity.CRITICAL, payload="exfil",
                      requires_control="network.default_deny", egress_host="example.com")
    permissive = Policy(network={"default": "allow", "allow": []})
    f = evaluate(case, False, "0 signals", permissive, ())  # not blocked (modeled)
    assert f.openshell_observed is False and f.openshell_blocked is False


# --- HiddenLayerAssessor observes egress cases when a prober is wired ----------

class _NoDetect:
    class prompt_analyzer:
        @staticmethod
        def create(**kwargs):
            class R:
                def to_dict(self):
                    return {"categories": {}, "frameworks": {}}
            return R()


def test_assessor_observes_egress_with_prober():
    a = real.HiddenLayerAssessor("cid", "sec")
    a._client = _NoDetect()
    seen = {}

    def prober(handle, host):
        seen["args"] = (handle, host)
        return True, f"egress to {host} DENIED by OpenShell"

    a.set_prober(prober)
    result = a.assess("sandbox-1", Policy())  # permissive default
    atk101 = next(f for f in result.findings if f.id == "ATK-101")
    assert seen["args"] == ("sandbox-1", "example.com")
    assert atk101.openshell_observed is True and atk101.openshell_blocked is True
    assert atk101.resolved is True
    # A non-egress case (no egress_host) stays modeled, not observed.
    non_egress = next(f for f in result.findings if not f.egress_host)
    assert non_egress.openshell_observed is False


# --- remediation removes the whitelisted exfil host from the allow-list --------

def test_exfil_remediation_removes_egress_host():
    finding = Finding(id="ATK-101", category="data_exfiltration",
                      severity=Severity.CRITICAL, attack_vector="exfil",
                      evidence="", egress_host="example.com")
    rec = build_recommendation(finding, source="heuristic")
    kinds = {(op["op"], op.get("value")) for op in rec.patch.ops}
    assert ("set_default", "deny") in kinds
    assert ("allow_remove", "example.com") in kinds
    assert rec.new_tests[0].egress_host == "example.com"  # regression stays observed

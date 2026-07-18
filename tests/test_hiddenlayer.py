"""Offline tests for the HiddenLayer adapter: stub the client so no SDK or
network is needed. Covers the detection→finding mapping and fail-closed."""

import pytest

from orchestrator.backends import real
from orchestrator.models import Policy
from orchestrator.interfaces import Assessor


class _FakeResp:
    def __init__(self, categories):
        self._d = {"categories": categories,
                   "frameworks": {"owasp": [{"label": "LLM01", "name": "Prompt Injection"}]}}

    def to_dict(self):
        return self._d


class _FakePromptAnalyzer:
    def __init__(self, categories, raises=None):
        self._categories = categories
        self._raises = raises

    def create(self, **kwargs):
        if self._raises:
            raise self._raises
        return _FakeResp(self._categories)


class _FakeClient:
    def __init__(self, categories, raises=None):
        self.prompt_analyzer = _FakePromptAnalyzer(categories, raises)


def _assessor_with(client) -> real.HiddenLayerAssessor:
    a = real.HiddenLayerAssessor("cid", "secret")
    a._client = client  # inject; bypasses lazy SDK import
    return a


def weak() -> Policy:
    p = Policy()
    p.network["default"] = "allow"
    return p


def hardened() -> Policy:
    p = Policy()
    p.network["default"] = "deny"
    p.prompt["system_guard"] = True
    p.prompt["pii_redaction"] = True
    p.tools["deny"] = ["shell_exec", "code_exec"]
    return p


def test_requires_both_credentials():
    with pytest.raises(real.MissingCredentials):
        real.HiddenLayerAssessor(None, None)
    with pytest.raises(real.MissingCredentials):
        real.HiddenLayerAssessor("cid", None)


def test_satisfies_assessor_protocol():
    assert isinstance(real.HiddenLayerAssessor("cid", "sec"), Assessor)


def test_detected_attacks_caught_at_content_layer():
    # HiddenLayer flags every payload -> caught at the content layer, resolved
    # regardless of the OpenShell policy (nothing lands).
    a = _assessor_with(_FakeClient({"prompt_injection": True, "unsafe_input": True}))
    result = a.assess("h", weak())
    assert result.unresolved() == []
    assert all(f.hl_detected for f in result.findings)
    f0 = result.findings[0]
    assert f0.hl_signals == ("prompt_injection", "unsafe_input")  # real signals captured
    assert "HiddenLayer detected 2 signal(s)" in f0.evidence and "[LLM01]" in f0.evidence


def test_evaders_pass_hiddenlayer_and_fall_to_openshell():
    # HiddenLayer detects nothing -> every attack evades the content layer and
    # must be caught by OpenShell.
    a = _assessor_with(_FakeClient({}))
    landed = a.assess("h", weak())
    assert len(landed.unresolved()) == 5           # nothing blocks them
    f = landed.findings[0]
    assert f.hl_detected is False and f.openshell_blocked is False
    assert f.hl_signals == ()  # no signals fired -> bypassed HiddenLayer
    assert "bypassed HiddenLayer" in f.evidence and "LANDED" in f.evidence

    a2 = _assessor_with(_FakeClient({}))
    blocked = a2.assess("h", hardened())            # OpenShell now blocks them
    assert blocked.unresolved() == []
    assert all(f.openshell_blocked and not f.hl_detected for f in blocked.findings)


def test_fail_closed_on_api_error():
    # API/WAF error -> treated as NOT detected (fail closed), so OpenShell must
    # catch it; it lands under a permissive policy.
    a = _assessor_with(_FakeClient({}, raises=RuntimeError("cloudflare 403")))
    result = a.assess("h", weak())
    assert len(result.unresolved()) == 5
    assert "fail-closed" in result.findings[0].evidence
    a2 = _assessor_with(_FakeClient({}, raises=RuntimeError("boom")))
    assert a2.assess("h", hardened()).unresolved() == []


def test_detections_cached_per_payload():
    calls = {"n": 0}

    class CountingAnalyzer(_FakePromptAnalyzer):
        def create(self, **kwargs):
            calls["n"] += 1
            return _FakeResp({"prompt_injection": True})

    client = _FakeClient({"prompt_injection": True})
    client.prompt_analyzer = CountingAnalyzer({"prompt_injection": True})
    a = _assessor_with(client)
    a.assess("h", weak())
    a.assess("h", weak())  # second round: same payloads -> cache hit
    assert calls["n"] == 5  # 5 distinct payloads, analyzed once each

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
    p.tools["deny"] = ["shell_exec"]
    return p


def test_requires_both_credentials():
    with pytest.raises(real.MissingCredentials):
        real.HiddenLayerAssessor(None, None)
    with pytest.raises(real.MissingCredentials):
        real.HiddenLayerAssessor("cid", None)


def test_satisfies_assessor_protocol():
    assert isinstance(real.HiddenLayerAssessor("cid", "sec"), Assessor)


def test_flagged_threats_open_until_policy_defends():
    flagged = {"prompt_injection": True, "unsafe_input": True}
    a = _assessor_with(_FakeClient(flagged))
    weak_findings = a.assess("h", weak())
    assert len(weak_findings.unresolved()) == 3
    assert "HiddenLayer flagged [LLM01]" in weak_findings.findings[0].evidence

    a2 = _assessor_with(_FakeClient(flagged))
    assert a2.assess("h", hardened()).unresolved() == []  # policy defends all


def test_unflagged_payload_is_not_a_finding():
    a = _assessor_with(_FakeClient({}))  # nothing detected
    assert a.assess("h", weak()).unresolved() == []


def test_fail_closed_on_api_error():
    a = _assessor_with(_FakeClient({}, raises=RuntimeError("cloudflare 403")))
    result = a.assess("h", weak())
    # error -> treated as a threat, unresolved under a permissive policy
    assert len(result.unresolved()) == 3
    assert "fail-closed" in result.findings[0].evidence
    # ...but a defending policy still resolves it
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
    assert calls["n"] == 3  # 3 distinct payloads, analyzed once each

"""Contract tests: real adapters satisfy the same Protocols as the mocks, and
config resolves backends from env. Live calls are never made here (no creds)."""

import pytest

from orchestrator.backends import mock, real
from orchestrator.config import Settings
from orchestrator.interfaces import LLM, Assessor, Sandbox


def test_mocks_satisfy_protocols():
    assert isinstance(mock.MockSandbox(), Sandbox)
    assert isinstance(mock.MockAssessor(), Assessor)
    assert isinstance(mock.MockLLM(), LLM)


def test_real_adapters_satisfy_protocols_when_configured():
    sb = real.OpenShellSandbox("http://gateway:8080")
    assessor = real.HiddenLayerAssessor("hl-client-id", "hl-client-secret")
    llm = real.NemotronLLM("http://vllm:8000")
    assert isinstance(sb, Sandbox)
    assert isinstance(assessor, Assessor)
    assert isinstance(llm, LLM)


def test_real_adapters_require_credentials():
    with pytest.raises(real.MissingCredentials):
        real.OpenShellSandbox(None, None)
    with pytest.raises(real.MissingCredentials):
        real.HiddenLayerAssessor(None, None)
    with pytest.raises(real.MissingCredentials):
        real.NemotronLLM(None)


def test_config_defaults_to_mock():
    s = Settings.from_env(env={})
    assert isinstance(s.build_sandbox(), mock.MockSandbox)
    assert isinstance(s.build_assessor(), mock.MockAssessor)
    assert isinstance(s.build_llm(), mock.MockLLM)


def test_config_selects_real_backends():
    s = Settings.from_env(env={
        "SANDBOX": "openshell", "OPENSHELL_GATEWAY_ENDPOINT": "http://gw:8080",
        "ASSESSOR": "hiddenlayer",
        "HIDDENLAYER_CLIENT_ID": "cid", "HIDDENLAYER_CLIENT_SECRET": "sec",
        "LLM": "nemotron", "NEMOTRON_BASE_URL": "http://vllm:8000",
    })
    assert isinstance(s.build_sandbox(), real.OpenShellSandbox)
    assert isinstance(s.build_assessor(), real.HiddenLayerAssessor)
    assert isinstance(s.build_llm(), real.NemotronLLM)


def test_config_unknown_backend_raises():
    with pytest.raises(ValueError):
        Settings.from_env(env={"LLM": "bogus"}).build_llm()

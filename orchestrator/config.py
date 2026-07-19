"""Backend resolution from environment. Defaults are the REAL backends —
OpenShell + HiddenLayer + Nemotron — so a normal invocation exercises the live
systems (credentials come from .env; see .env.example). Mocks are for the test
suite only and are opted into explicitly with SANDBOX/ASSESSOR/LLM=mock (the test
suite sets these; see tests/conftest.py)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .backends import mock, real
from .interfaces import LLM, Assessor, Sandbox


@dataclass
class Settings:
    sandbox: str = "openshell"
    assessor: str = "hiddenlayer"
    llm: str = "nemotron"
    enforce: bool = True  # OPENSHELL_ENFORCE ablation toggle

    openshell_gateway_endpoint: str | None = None
    openshell_insecure: bool = True
    hiddenlayer_client_id: str | None = None
    hiddenlayer_client_secret: str | None = None
    hiddenlayer_env: str = "prod-us"
    hiddenlayer_project: str | None = None
    nemotron_base_url: str | None = None
    nemotron_key: str | None = None
    nemotron_model: str = "nemotron"
    nemotron_timeout: float = 20.0

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        e = env if env is not None else os.environ
        return cls(
            sandbox=e.get("SANDBOX", "openshell"),
            assessor=e.get("ASSESSOR", "hiddenlayer"),
            llm=e.get("LLM", "nemotron"),
            enforce=e.get("OPENSHELL_ENFORCE", "true").lower() not in ("false", "0", "off"),
            openshell_gateway_endpoint=e.get("OPENSHELL_GATEWAY_ENDPOINT"),
            openshell_insecure=e.get("OPENSHELL_GATEWAY_INSECURE", "true").lower()
            not in ("false", "0", "off"),
            hiddenlayer_client_id=e.get("HIDDENLAYER_CLIENT_ID"),
            hiddenlayer_client_secret=e.get("HIDDENLAYER_CLIENT_SECRET"),
            hiddenlayer_env=e.get("HIDDENLAYER_ENV", "prod-us"),
            hiddenlayer_project=e.get("HIDDENLAYER_PROJECT"),
            nemotron_base_url=e.get("NEMOTRON_BASE_URL"),
            nemotron_key=e.get("NEMOTRON_KEY", "not-needed"),
            nemotron_model=e.get("NEMOTRON_MODEL", "nemotron"),
            nemotron_timeout=float(e.get("NEMOTRON_TIMEOUT", "20")),
        )

    def build_sandbox(self) -> Sandbox:
        if self.sandbox == "mock":
            return mock.MockSandbox()
        if self.sandbox == "openshell":
            return real.OpenShellSandbox(
                self.openshell_gateway_endpoint, self.openshell_insecure
            )
        raise ValueError(f"unknown SANDBOX={self.sandbox}")

    def build_assessor(self) -> Assessor:
        if self.assessor == "mock":
            return mock.MockAssessor()
        if self.assessor == "hiddenlayer":
            return real.HiddenLayerAssessor(
                self.hiddenlayer_client_id,
                self.hiddenlayer_client_secret,
                self.hiddenlayer_env,
                self.hiddenlayer_project,
            )
        raise ValueError(f"unknown ASSESSOR={self.assessor}")

    def build_generator(self):
        """Red-team attack generator. The offline MockGenerator is TEST-ONLY —
        selected only by an explicit LLM=mock (unit/integration tests, the
        offline `make taxonomy-sweep`). A real run uses the configured LLM and
        fails loudly if it isn't set, rather than silently generating canned
        attacks."""
        from . import generator

        if self.llm == "mock":
            return generator.MockGenerator()
        if self.llm == "nemotron":
            if not self.nemotron_base_url:
                raise real.MissingCredentials(
                    "Nemotron generator requires NEMOTRON_BASE_URL "
                    "(set LLM=mock only for tests)")
            return generator.NemotronGenerator(
                self.nemotron_base_url, self.nemotron_key,
                self.nemotron_model, self.nemotron_timeout,
            )
        raise ValueError(f"unknown LLM={self.llm}")

    def build_llm(self) -> LLM:
        if self.llm == "mock":
            return mock.MockLLM()
        if self.llm == "nemotron":
            return real.NemotronLLM(
                self.nemotron_base_url,
                self.nemotron_key,
                self.nemotron_model,
                self.nemotron_timeout,
            )
        raise ValueError(f"unknown LLM={self.llm}")

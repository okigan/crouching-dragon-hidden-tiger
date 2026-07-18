"""Backend resolution from environment. Defaults are all `mock`, so the platform
runs with zero setup; real backends opt in via env (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .backends import mock, real
from .interfaces import LLM, Assessor, Sandbox


@dataclass
class Settings:
    sandbox: str = "mock"
    assessor: str = "mock"
    llm: str = "mock"
    enforce: bool = True  # OPENSHELL_ENFORCE ablation toggle

    openshell_endpoint: str | None = None
    openshell_key: str | None = None
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
            sandbox=e.get("SANDBOX", "mock"),
            assessor=e.get("ASSESSOR", "mock"),
            llm=e.get("LLM", "mock"),
            enforce=e.get("OPENSHELL_ENFORCE", "true").lower() not in ("false", "0", "off"),
            openshell_endpoint=e.get("OPENSHELL_ENDPOINT"),
            openshell_key=e.get("OPENSHELL_KEY"),
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
            return real.OpenShellSandbox(self.openshell_endpoint, self.openshell_key)
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
        """Red-team attack generator. Uses the vLLM when the LLM backend is
        Nemotron and configured; otherwise a deterministic offline mock."""
        from . import generator

        if self.llm == "nemotron" and self.nemotron_base_url:
            return generator.NemotronGenerator(
                self.nemotron_base_url, self.nemotron_key,
                self.nemotron_model, self.nemotron_timeout,
            )
        return generator.MockGenerator()

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

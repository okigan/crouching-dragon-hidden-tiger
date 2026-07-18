"""Real adapter stubs for the gated components.

Each satisfies the same Protocol as its mock and guards on credentials. The live
wiring is intentionally left as clearly-marked TODO seams (see docs/DESIGN.md
§8): the architecture is proven end-to-end on mocks first, and these swap in
without touching the loop once credentials/endpoints are available.
"""

from __future__ import annotations

from ..models import AttackCase, Assessment, Policy, Recommendation


class MissingCredentials(RuntimeError):
    pass


class OpenShellSandbox:
    """NVIDIA OpenShell secure execution environment."""

    def __init__(self, endpoint: str | None, api_key: str | None) -> None:
        if not endpoint or not api_key:
            raise MissingCredentials("OpenShell requires endpoint + api key")
        self.endpoint = endpoint
        self.api_key = api_key

    def deploy(self, agent: str, policy: Policy) -> str:  # pragma: no cover
        # TODO: translate Policy -> OpenShell sandbox spec, POST to endpoint,
        # return the sandbox/session id.
        raise NotImplementedError("OpenShell live deploy not yet wired")

    def teardown(self, handle: str) -> None:  # pragma: no cover
        raise NotImplementedError


class HiddenLayerAssessor:
    """HiddenLayer adversarial assessment service."""

    def __init__(self, api_key: str | None, project: str | None = None) -> None:
        if not api_key:
            raise MissingCredentials("HiddenLayer requires an api key")
        self.api_key = api_key
        self.project = project

    def assess(self, handle: str, policy: Policy) -> Assessment:  # pragma: no cover
        # TODO: kick off a HiddenLayer scan against the deployed agent, poll for
        # completion, map results -> [Finding].
        raise NotImplementedError("HiddenLayer live assess not yet wired")

    def add_tests(self, cases: list[AttackCase]) -> None:  # pragma: no cover
        raise NotImplementedError


class NemotronLLM:
    """Nemotron served on vLLM via an OpenAI-compatible API."""

    def __init__(
        self,
        base_url: str | None,
        api_key: str | None = "not-needed",
        model: str = "nemotron",
    ) -> None:
        if not base_url:
            raise MissingCredentials("Nemotron requires a base_url")
        self.base_url = base_url
        self.api_key = api_key
        self.model = model

    def analyze(  # pragma: no cover
        self, assessment: Assessment, policy: Policy
    ) -> Recommendation:
        # TODO: build a security-analysis prompt from (assessment, policy), call
        # POST {base_url}/v1/chat/completions, parse a structured Recommendation
        # (root cause + PolicyPatch + new AttackCases) out of the response.
        raise NotImplementedError("Nemotron live analyze not yet wired")

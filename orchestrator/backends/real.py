"""Real adapter stubs for the gated components.

Each satisfies the same Protocol as its mock and guards on credentials. The live
wiring is intentionally left as clearly-marked TODO seams (see docs/DESIGN.md
§8): the architecture is proven end-to-end on mocks first, and these swap in
without touching the loop once credentials/endpoints are available.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from ..models import AttackCase, Assessment, Policy, Recommendation
from .remediation import (
    REMEDIATION,
    REMEDIATION_MENU,
    build_recommendation,
    heuristic_recommendation,
    pick_highest_severity,
)


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


_SYSTEM = (
    "You are a security analyst hardening an AI agent's runtime policy. "
    "For the single most severe open finding, give a one-sentence root cause and "
    "choose exactly one remediation from the allowed list. "
    "Respond with ONLY a JSON object: "
    '{"finding_id": "<id>", "root_cause": "<one sentence>", '
    '"remediation": "<one of the allowed keywords>"}.'
)


class NemotronLLM:
    """LLM analysis served on vLLM via an OpenAI-compatible API (Nemotron, or the
    Qwen endpoint in dev).

    The model *proposes* which finding to fix and narrates the root cause; we
    validate its choice against the known remediation table and fall back to the
    deterministic heuristic when the response is unusable. So enabling the LLM
    adds real analysis without ever risking loop convergence — which matters
    because the dev endpoint runs a tiny 0.5B model.
    """

    def __init__(
        self,
        base_url: str | None,
        api_key: str | None = "not-needed",
        model: str = "nemotron",
        timeout: float = 20.0,
    ) -> None:
        if not base_url:
            raise MissingCredentials("Nemotron requires a base_url")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    # --- HTTP -------------------------------------------------------------
    def _chat(self, user: str) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": 200,
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    # --- analyze ----------------------------------------------------------
    def analyze(self, assessment: Assessment, policy: Policy) -> Recommendation:
        target = pick_highest_severity(assessment)
        if target is None:
            return heuristic_recommendation(assessment)

        openf = assessment.unresolved()
        listing = "\n".join(
            f"- {f.id} [{f.category}, severity={f.severity}] {f.evidence}"
            for f in openf
        )
        prompt = (
            f"Open findings:\n{listing}\n\n"
            f"Allowed remediation keywords: {REMEDIATION_MENU}\n"
            "Pick the most severe finding and its remediation."
        )

        t0 = time.perf_counter()
        try:
            raw = self._chat(prompt)
        except (urllib.error.URLError, TimeoutError, OSError, KeyError, ValueError):
            # endpoint slow/unreachable/misbehaving -> deterministic fallback
            return _tag(heuristic_recommendation(assessment), "nemotron-fallback")
        latency_ms = (time.perf_counter() - t0) * 1000.0

        choice = _parse(raw)
        chosen = _validate_choice(choice, openf)
        if chosen is None:
            # model returned junk -> keep the model's narrative but use heuristic target
            rec = build_recommendation(
                target, source="nemotron-fallback",
                narrative=(choice or {}).get("root_cause", "") if choice else "",
                latency_ms=latency_ms,
            )
            return rec

        finding, narrative = chosen
        return build_recommendation(
            finding, source="nemotron", narrative=narrative, latency_ms=latency_ms
        )


def _tag(rec: Recommendation, source: str) -> Recommendation:
    rec.source = source
    return rec


def _parse(raw: str) -> dict | None:
    """Extract the first JSON object from a possibly-noisy model response."""
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except ValueError:
        return None


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _validate_choice(choice: dict | None, open_findings):
    """Return (finding, narrative) if the model picked a real open finding whose
    remediation keyword corresponds to that finding's category. Keyword matching
    is tolerant (the small model tends to add prefixes like "enable_"), so we
    normalize and check containment against the expected keyword."""
    if not choice:
        return None
    fid = str(choice.get("finding_id", "")).strip()
    keyword = _norm(str(choice.get("remediation", "")))
    narrative = str(choice.get("root_cause", "")).strip()
    finding = {f.id: f for f in open_findings}.get(fid)
    if finding is None:
        return None
    remedy = REMEDIATION.get(finding.category)
    if remedy is None:
        return None
    expected = _norm(remedy["keyword"])
    if not keyword or (expected not in keyword and keyword not in expected):
        return None
    return finding, narrative

"""Real adapters for the gated components.

Each satisfies the same Protocol as its mock and guards on credentials. The
Nemotron/vLLM (LLM) and HiddenLayer (Assessor) adapters are fully wired; the
OpenShell (Sandbox) adapter is a clearly-marked seam (see docs/DESIGN.md §8).
Backends are resolved from config, so the loop never imports these directly.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from ..models import AttackCase, Assessment, Policy, Recommendation
from ..references import refs_for_category, refs_from_hl_frameworks
from .corpus import DEFAULT_CORPUS
from .evaluate import evaluate
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
    """HiddenLayer Runtime Security as the red team.

    Each attack payload is sent through HiddenLayer's prompt analyzer, which
    returns real threat detections (prompt injection, unsafe input, PII, code,
    DoS, ...) with MITRE/OWASP framework labels. HiddenLayer decides whether an
    attack is a genuine threat; the OpenShell policy decides whether it is
    defended — so live detections drive the loop while it still converges.

    Fail-closed: if the HiddenLayer API (or the WAF in front of it) errors on a
    payload, that payload is treated as an unresolved threat rather than waved
    through. Detections are cached per payload (they do not depend on the
    policy), so re-runs across rounds don't re-bill the same call.

    Requires `pip install hiddenlayer-sdk` (the `hiddenlayer` optional extra);
    the SDK is imported lazily so the default mock path stays dependency-free.
    """

    # HiddenLayer category booleans that count as "this payload is a threat".
    _THREAT_CATEGORIES = (
        "prompt_injection", "unsafe_input", "unsafe_output", "guardrail",
        "input_code", "input_dos", "input_pii", "output_code", "output_pii",
        "output_tool_use",
    )

    def __init__(
        self,
        client_id: str | None,
        client_secret: str | None,
        environment: str = "prod-us",
        project: str | None = None,
        corpus: list[AttackCase] | None = None,
    ) -> None:
        if not client_id or not client_secret:
            raise MissingCredentials(
                "HiddenLayer requires client_id + client_secret"
            )
        self.client_id = client_id
        self.client_secret = client_secret
        self.environment = environment
        self.project = project
        self._corpus: list[AttackCase] = list(
            corpus if corpus is not None else DEFAULT_CORPUS
        )
        self._client = None  # lazy: constructed on first assess()
        self._cache: dict[str, dict] = {}

    def _get_client(self):
        if self._client is None:
            from hiddenlayer import HiddenLayer  # lazy import (optional dep)

            self._client = HiddenLayer(
                client_id=self.client_id,
                client_secret=self.client_secret,
                environment=self.environment,
            )
        return self._client

    def _analyze(self, payload: str) -> dict:
        if payload in self._cache:
            return self._cache[payload]
        try:
            kwargs = {"prompt": payload}
            if self.project:
                kwargs["hl_project_id"] = self.project
            resp = self._get_client().prompt_analyzer.create(**kwargs).to_dict()
            cats = [
                name
                for name, hit in resp.get("categories", {}).items()
                if hit and name in self._THREAT_CATEGORIES
            ]
            owasp = [f["label"] for f in resp.get("frameworks", {}).get("owasp", [])]
            detail = {
                "flagged": bool(cats),
                "labels": owasp or cats,
                "frameworks": resp.get("frameworks", {}),
                "error": None,
            }
        except MissingCredentials:
            raise
        except Exception as exc:  # API/WAF/network error -> fail closed
            detail = {"flagged": True, "labels": [], "frameworks": {}, "error": type(exc).__name__}
        self._cache[payload] = detail
        return detail

    def assess(self, handle: str, policy: Policy) -> Assessment:
        findings = []
        for case in self._corpus:
            det = self._analyze(case.payload)
            # HiddenLayer's live verdict is the content layer. On API/WAF error we
            # fail closed by treating the payload as NOT reliably detected, so the
            # capability layer (OpenShell) is required to catch it.
            hl_detected = det["flagged"] and not det["error"]
            if det["error"]:
                hl_note = f"HiddenLayer error ({det['error']}) — fail-closed, treated as not detected"
                refs = refs_for_category(case.category)
            elif hl_detected:
                hl_note = f"HiddenLayer detected [{', '.join(det['labels']) or 'threat'}]"
                refs = refs_from_hl_frameworks(det.get("frameworks", {}), case.category)
            else:
                hl_note = "passed HiddenLayer — no threat detected"
                refs = refs_for_category(case.category)
            findings.append(evaluate(case, hl_detected, hl_note, policy, refs))
        return Assessment(findings=findings)

    def add_tests(self, cases: list[AttackCase]) -> None:
        known = {c.id for c in self._corpus}
        for c in cases:
            if c.id not in known:
                self._corpus.append(c)
                known.add(c.id)


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

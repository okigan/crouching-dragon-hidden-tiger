"""Real adapters for the gated components.

Each satisfies the same Protocol as its mock and guards on credentials. The
Nemotron/vLLM (LLM) and HiddenLayer (Assessor) adapters are fully wired; the
OpenShell (Sandbox) adapter is a clearly-marked seam (see docs/DESIGN.md §8).
Backends are resolved from config, so the loop never imports these directly.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

from ..models import AttackCase, Assessment, Policy, PolicyPatch, Recommendation
from ..policy_store import PolicyError, PolicyStore
from ..references import refs_for_category, refs_from_hl_frameworks
from .corpus import DEFAULT_CORPUS
from .evaluate import evaluate
from .remediation import (
    CONTROL_DOCS,
    OPENSHELL_PRIMER,
    PATCH_OPS_GUIDE,
    build_recommendation,
    control_for,
    heuristic_recommendation,
    pick_highest_severity,
)


class MissingCredentials(RuntimeError):
    pass


class OpenShellSandbox:
    """Real NVIDIA OpenShell secure execution environment.

    Drives the `openshell` CLI against a running gateway: creates a sandbox,
    translates our Policy into a real OpenShell policy.yaml and loads it, and can
    exec commands inside the sandbox. Enforcement (egress / filesystem / process)
    is real — seccomp / Landlock / network namespaces via the gateway.

    Needs the `openshell` CLI on PATH (`uv tool install openshell`) and a gateway
    endpoint (the docker-compose `openshell-gateway` service, or any gateway).
    """

    def __init__(self, gateway_endpoint: str | None, insecure: bool = True,
                 create_timeout: float = 300.0) -> None:
        if not gateway_endpoint:
            raise MissingCredentials("OpenShell requires a gateway endpoint")
        self.endpoint = gateway_endpoint
        self.insecure = insecure
        self.create_timeout = create_timeout
        self._env = {
            **os.environ,
            "OPENSHELL_GATEWAY_ENDPOINT": gateway_endpoint,
            "OPENSHELL_GATEWAY_INSECURE": "true" if insecure else "false",
        }

    def _cli(self, *args: str, timeout: float = 120.0):
        import subprocess
        return subprocess.run(
            ["openshell", *args], env=self._env, capture_output=True,
            text=True, timeout=timeout,
        )

    def deploy(self, agent: str, policy: Policy) -> str:
        import tempfile
        import uuid
        from .openshell_policy import to_openshell_yaml

        name = f"cdht-sandbox-{uuid.uuid4().hex[:8]}"
        # Non-interactive: without a command, `create` defaults to an interactive
        # shell and blocks on a relay/TTY that doesn't exist headless. Run `true`
        # (sandbox is kept since we don't pass --no-keep), then set policy + exec.
        r = self._cli("sandbox", "create", "--name", name, "--no-auto-providers",
                      "--no-tty", "--", "true", timeout=self.create_timeout)
        if r.returncode != 0:
            raise RuntimeError(f"openshell sandbox create failed: {r.stderr.strip()}")
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(to_openshell_yaml(policy))
            policy_path = f.name
        r = self._cli("policy", "set", name, "--policy", policy_path, "--wait")
        if r.returncode != 0:
            self.teardown(name)
            raise RuntimeError(f"openshell policy set failed: {r.stderr.strip()}")
        return name

    def exec(self, handle: str, command: list[str], timeout: float = 60.0):
        """Run a command inside the sandbox; return (exit_code, combined output)."""
        r = self._cli("sandbox", "exec", "-n", handle, "--no-tty", "--",
                       *command, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr)

    def teardown(self, handle: str) -> None:
        self._cli("sandbox", "delete", handle)

    def egress_probe(self, handle: str, host: str,
                     timeout: float = 30.0) -> tuple[bool, str]:
        """OBSERVE OpenShell egress enforcement: try to reach ``host`` from inside
        the live sandbox and report whether OpenShell allowed it.

        Returns ``(blocked, note)``. curl exits 0 only when the request actually
        left the sandbox (the exfil landed); OpenShell denies a non-allow-listed
        host at its proxy (HTTP 403 / exit 56), so a non-zero exit == blocked.
        """
        url = host if host.startswith("http") else f"https://{host}/"
        code, out = self.exec(
            handle,
            ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "10", url],
            timeout=timeout,
        )
        detail = " ".join(out.split())[:100]
        if code == 0:
            return False, f"egress to {host} SUCCEEDED (HTTP {detail}) — OpenShell allowed it"
        return True, f"egress to {host} DENIED by OpenShell (exit {code}: {detail})"


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
        # Optional real-execution probe: (handle, host) -> (blocked, note). When
        # set (a live OpenShell sandbox), egress attacks are OBSERVED, not modeled.
        self._prober = None

    def set_prober(self, prober) -> None:
        """Inject a live egress probe (e.g. OpenShellSandbox.egress_probe) so the
        capability layer is observed for attacks that name a real egress_host."""
        self._prober = prober

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
                "signals": cats,
                "labels": owasp or cats,
                "frameworks": resp.get("frameworks", {}),
                "error": None,
            }
        except MissingCredentials:
            raise
        except Exception as exc:  # API/WAF/network error -> fail closed
            detail = {"flagged": True, "signals": [], "labels": [],
                      "frameworks": {}, "error": type(exc).__name__}
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
            signals = tuple(det.get("signals", []))
            if det["error"]:
                hl_note = f"HiddenLayer error ({det['error']}) — fail-closed, treated as not detected"
                refs = refs_for_category(case.category)
            elif hl_detected:
                hl_note = (f"HiddenLayer detected {len(signals)} signal(s): "
                           f"{', '.join(signals)} [{', '.join(det['labels']) or 'threat'}]")
                refs = refs_from_hl_frameworks(det.get("frameworks", {}), case.category)
            else:
                hl_note = "0 signals — bypassed HiddenLayer"
                refs = refs_for_category(case.category)
            # OBSERVE OpenShell enforcement for egress attacks when a live probe
            # is wired; otherwise fall back to the modeled control inference.
            observed = None
            if self._prober is not None and case.egress_host:
                observed = self._prober(handle, case.egress_host)
            findings.append(
                evaluate(case, hl_detected, hl_note, policy, refs,
                         hl_signals=signals, observed=observed)
            )
        return Assessment(findings=findings)

    def add_tests(self, cases: list[AttackCase]) -> None:
        known = {c.id for c in self._corpus}
        for c in cases:
            if c.id not in known:
                self._corpus.append(c)
                known.add(c.id)

    def detect(self, prompt: str) -> bool:
        """Screening hook for the generator: does live HiddenLayer flag this
        prompt? An API/WAF error counts as NOT detected (fail closed — the
        candidate is kept as a gap OpenShell must catch)."""
        det = self._analyze(prompt)
        return det["flagged"] and not det["error"]


_SYSTEM = (
    "You are a security analyst hardening an AI agent's runtime policy enforced by "
    "OpenShell — a capability/egress sandbox. You harden by enabling OpenShell "
    "controls. Each control and exactly what it does at the OpenShell layer:\n"
    f"{CONTROL_DOCS}\n\n"
    f"{OPENSHELL_PRIMER}\n\n"
    f"{PATCH_OPS_GUIDE}\n\n"
    "For the single most severe open finding, give a one-sentence root cause and "
    "AUTHOR the exact policy ops that neutralize it (only tightening ops: "
    "set_default, set_flag, tool_deny, allow_remove; values are strings — use "
    '"true"/"false" for flags). For an exfiltration finding, both deny-by-default '
    "AND removing the target host from network.allow are required. Some findings "
    "(content-only objectives like hallucination, bias, or system-prompt exposure) "
    "have no OpenShell control that stops them — for those return an empty ops list "
    "and say so in the root cause. Respond with ONLY a JSON object: "
    '{"finding_id": "<id>", "root_cause": "<one sentence>", '
    '"ops": [{"op": "<op>", "path": "<dotted.path>", "value": "<string>"}]}.'
)

# Structured-output schema for the remediation (OpenAI-compatible json_schema).
_REMEDIATION_SCHEMA = {
    "name": "remediation",
    "strict": True,
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "finding_id": {"type": "string"},
            "root_cause": {"type": "string"},
            "ops": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "op": {"type": "string",
                               "enum": ["set_default", "set_flag",
                                        "tool_deny", "allow_remove"]},
                        "path": {"type": "string"},
                        "value": {"type": "string"},
                    },
                    "required": ["op", "path", "value"],
                },
            },
        },
        "required": ["finding_id", "root_cause", "ops"],
    },
}


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
    def _post(self, payload: dict) -> str:
        req = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    def _chat(self, user: str, schema: dict | None = None) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            # Generous budget: reasoning models (e.g. Nemotron reasoning on
            # OpenRouter) spend tokens on chain-of-thought before the answer.
            "max_tokens": 1024,
        }
        if not schema:
            return self._post(payload)
        # Prefer strict json_schema structured output; degrade gracefully for
        # endpoints/models that reject it (json_object, then unconstrained) so a
        # capable model gets guaranteed structure without breaking older ones.
        for fmt in ({"type": "json_schema", "json_schema": schema},
                    {"type": "json_object"}, None):
            try:
                return self._post({**payload, "response_format": fmt} if fmt
                                  else payload)
            except urllib.error.HTTPError as exc:
                if exc.code not in (400, 404, 415, 422):
                    raise
        return self._post(payload)

    # --- analyze ----------------------------------------------------------
    def analyze(self, assessment: Assessment, policy: Policy) -> Recommendation:
        target = pick_highest_severity(assessment)
        if target is None:
            return heuristic_recommendation(assessment)

        openf = assessment.unresolved()
        listing = "\n".join(
            f"- {f.id} [{f.category}, severity={f.severity}] {f.evidence}"
            + (f" · exfil host: {f.egress_host}" if f.egress_host else "")
            for f in openf
        )
        active = ", ".join(sorted(policy.controls())) or "none"
        prompt = (
            f"Current OpenShell policy — controls already active: {active}.\n\n"
            f"Open findings (not yet defended):\n{listing}\n\n"
            "Pick the single most severe finding and author the ops that "
            "neutralize it."
        )

        t0 = time.perf_counter()
        try:
            raw = self._chat(prompt, schema=_REMEDIATION_SCHEMA)
        except (urllib.error.URLError, TimeoutError, OSError, KeyError, ValueError):
            # endpoint slow/unreachable/misbehaving -> deterministic fallback
            return _tag(heuristic_recommendation(assessment), "nemotron-fallback")
        latency_ms = (time.perf_counter() - t0) * 1000.0

        choice = _parse(raw)
        by_id = {f.id: f for f in openf}
        finding = by_id.get(str((choice or {}).get("finding_id", "")).strip())
        narrative = str((choice or {}).get("root_cause", "")).strip()

        # The model authored ops directly — use them when they validate and
        # actually neutralize the chosen finding (so convergence is preserved).
        authored = _authored_patch(choice, finding, policy) if finding else None
        if authored is not None:
            rec = build_recommendation(
                finding, source="nemotron", narrative=narrative,
                latency_ms=latency_ms,
            )
            rec.patch.ops = authored.ops  # the model's own policy, validated
            rec.patch.rationale = narrative or rec.patch.rationale
            return rec

        # No usable authored ops -> deterministic remediation for the chosen (or
        # highest-severity) finding; keep the model's narrative for the report.
        return build_recommendation(
            finding or target, source="nemotron-fallback",
            narrative=narrative, latency_ms=latency_ms,
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


_AUTHOR_OPS = {"set_default", "set_flag", "tool_deny", "allow_remove"}


def _authored_patch(choice: dict | None, finding, policy: Policy):
    """Turn the model's authored `ops` into a validated PolicyPatch, or None if
    they're unusable. Accepted only when the ops are tightening, apply cleanly,
    and actually establish the control that neutralizes `finding` (and, for an
    exfil finding, remove its host from the allow-list) — so using the model's
    own policy never costs the loop its convergence guarantee."""
    raw_ops = (choice or {}).get("ops")
    if not isinstance(raw_ops, list) or not raw_ops:
        return None
    ops: list[dict] = []
    for o in raw_ops:
        if not isinstance(o, dict):
            return None
        kind = str(o.get("op", "")).strip()
        path = str(o.get("path", "")).strip()
        if kind not in _AUTHOR_OPS or "." not in path:
            return None
        value: object = o.get("value")
        if kind == "set_flag":
            value = str(value).strip().lower() in ("true", "1", "yes", "on")
        else:
            value = str(value).strip()
        ops.append({"op": kind, "path": path, "value": value})

    patch = PolicyPatch(ops=ops, rationale=str((choice or {}).get("root_cause", "")),
                        addresses=frozenset({finding.id}))
    # tightening-only + targets a finding (rejects surface-widening ops)
    if not patch.is_valid(policy):
        return None
    required = control_for(finding.category)
    if not required:
        return None  # content-only / unknown: no control to establish here
    trial = PolicyStore(policy)
    try:
        trial.apply(patch)
    except PolicyError:
        return None
    cur = trial.current
    if required not in cur.controls():
        return None  # ops don't actually neutralize the finding
    if finding.egress_host and finding.egress_host in cur.network.get("allow", []):
        return None  # exfil host still reachable -> observed egress would land
    return patch

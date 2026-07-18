"""Real documentation links for findings.

Detectors (HiddenLayer) map each detection to standard frameworks — OWASP GenAI
LLM Top-10 and MITRE ATLAS. This module resolves those labels to their canonical
documentation URLs, so the report can link every finding to authoritative docs.
All URLs were verified against the live sites.
"""

from __future__ import annotations

import re

from .models import DocRef

# OWASP GenAI LLM Top-10 (2025). Note the slug quirk: LLM01 differs from the rest.
_OWASP_BASE = "https://genai.owasp.org/llmrisk/"
OWASP: dict[str, tuple[str, str]] = {
    "LLM01": ("Prompt Injection", _OWASP_BASE + "llm01-prompt-injection/"),
    "LLM02": ("Sensitive Information Disclosure",
              _OWASP_BASE + "llm022025-sensitive-information-disclosure/"),
    "LLM03": ("Supply Chain", _OWASP_BASE + "llm032025-supply-chain/"),
    "LLM04": ("Data and Model Poisoning",
              _OWASP_BASE + "llm042025-data-and-model-poisoning/"),
    "LLM05": ("Improper Output Handling",
              _OWASP_BASE + "llm052025-improper-output-handling/"),
    "LLM06": ("Excessive Agency", _OWASP_BASE + "llm062025-excessive-agency/"),
    "LLM07": ("System Prompt Leakage",
              _OWASP_BASE + "llm072025-system-prompt-leakage/"),
    "LLM08": ("Vector and Embedding Weaknesses",
              _OWASP_BASE + "llm082025-vector-and-embedding-weaknesses/"),
    "LLM09": ("Misinformation", _OWASP_BASE + "llm092025-misinformation/"),
    "LLM10": ("Unbounded Consumption",
              _OWASP_BASE + "llm102025-unbounded-consumption/"),
}

_MITRE_NAMES = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0057": "LLM Data Leakage",
}

HIDDENLAYER_DOCS = DocRef(
    "HiddenLayer", "docs", "HiddenLayer Runtime Security",
    "https://docs.hiddenlayer.ai/",
)

# Our finding categories → the canonical framework entries they correspond to.
# Used by the mock assessor and to augment live HiddenLayer detections.
CATEGORY_REFS: dict[str, tuple[str, ...]] = {
    "prompt_injection": ("LLM01", "AML.T0051"),
    "data_exfiltration": ("LLM02",),
    "pii_exfiltration": ("LLM02",),
    "tool_abuse": ("LLM06",),
    "code_injection": ("LLM05",),
}


def _owasp_ref(label: str) -> DocRef | None:
    m = re.search(r"LLM0*(\d+)", label.upper())
    if not m:
        return None
    key = f"LLM{int(m.group(1)):02d}"
    if key not in OWASP:
        return None
    name, url = OWASP[key]
    return DocRef("OWASP", key, name, url)


def _mitre_ref(label: str) -> DocRef | None:
    m = re.match(r"(AML\.T\d+)", label.upper())
    if not m:
        return None
    tid = m.group(1)
    name = _MITRE_NAMES.get(tid, tid)
    return DocRef("MITRE ATLAS", tid, name, f"https://atlas.mitre.org/techniques/{tid}")


def _dedup(refs: list[DocRef]) -> tuple[DocRef, ...]:
    seen: set[str] = set()
    out: list[DocRef] = []
    for r in refs:
        if r.url not in seen:
            seen.add(r.url)
            out.append(r)
    return tuple(out)


def refs_for_category(category: str) -> tuple[DocRef, ...]:
    """Canonical references for one of our finding categories (used offline)."""
    refs: list[DocRef] = []
    for label in CATEGORY_REFS.get(category, ()):
        r = _owasp_ref(label) or _mitre_ref(label)
        if r:
            refs.append(r)
    return _dedup(refs)


def refs_from_hl_frameworks(frameworks: dict, category: str = "") -> tuple[DocRef, ...]:
    """Build references from HiddenLayer's framework mappings, augmented with our
    category defaults and a link to the HiddenLayer docs."""
    refs: list[DocRef] = []
    for entry in frameworks.get("owasp", []):
        r = _owasp_ref(str(entry.get("label", "")))
        if r:
            refs.append(r)
    for entry in frameworks.get("mitre", []):
        r = _mitre_ref(str(entry.get("label", "")))
        if r:
            refs.append(r)
    refs.extend(refs_for_category(category))
    refs.append(HIDDENLAYER_DOCS)
    return _dedup(refs)

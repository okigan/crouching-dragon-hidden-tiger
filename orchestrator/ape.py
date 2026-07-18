"""Loader for the vendored HiddenLayer APE taxonomy (third_party/ape-taxonomy).

The taxonomy is the source of truth for adversarial-prompt techniques (how) and
objectives (what). The red-team loop uses `clause_for()` to feed a technique's
description to an LLM generator that crafts evasion prompts; `technique_name()` /
`objective_name()` back the report's APE reference links.

The file is read verbatim (CC BY-ND — see third_party/ape-taxonomy/README.md);
we only *read* it, never transform and redistribute it.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path


def _candidate_paths() -> list[Path]:
    env = os.environ.get("APE_JSON")
    here = Path(__file__).resolve()
    return [p for p in [
        Path(env) if env else None,
        here.parents[1] / "third_party" / "ape-taxonomy" / "ape.json",
        Path.cwd() / "third_party" / "ape-taxonomy" / "ape.json",
    ] if p is not None]


@lru_cache(maxsize=1)
def _load() -> dict:
    """Return {'techniques': {id: {...}}, 'objectives': {id: {...}}}; empty if the
    taxonomy file can't be found (callers fall back gracefully)."""
    for path in _candidate_paths():
        if path.is_file():
            data = json.loads(path.read_text())
            techniques: dict[str, dict] = {}
            for tactic in data.get("Tactics", []):
                for te in tactic.get("Techniques", []):
                    techniques[te["Technique ID"]] = {
                        "id": te["Technique ID"],
                        "name": te.get("Technique Name", ""),
                        "description": te.get("Technique Description", ""),
                        "tactic": tactic.get("Tactic Name", ""),
                    }
            objectives: dict[str, dict] = {}
            for impact in data.get("Impacts", []):
                for o in impact.get("Objectives", []):
                    objectives[o["Objective ID"]] = {
                        "id": o["Objective ID"],
                        "name": o.get("Objective Name", ""),
                        "description": o.get("Objective Description", ""),
                        "impact": impact.get("Impact Name", ""),
                    }
            return {"techniques": techniques, "objectives": objectives}
    return {"techniques": {}, "objectives": {}}


def available() -> bool:
    return bool(_load()["techniques"])


def technique(tid: str) -> dict | None:
    return _load()["techniques"].get(tid)


def objective(oid: str) -> dict | None:
    return _load()["objectives"].get(oid)


def technique_name(tid: str) -> str | None:
    t = technique(tid)
    return t["name"] if t else None


def objective_name(oid: str) -> str | None:
    o = objective(oid)
    return o["name"] if o else None


def clause_for(tid: str, max_chars: int = 600) -> str:
    """A compact 'clause' describing an APE technique, suitable for feeding to an
    LLM red-team generator ("use this technique to craft a prompt that ...")."""
    t = technique(tid)
    if not t:
        return ""
    desc = " ".join(t["description"].split())
    if len(desc) > max_chars:
        desc = desc[: max_chars - 1].rstrip() + "…"
    return f"APE {t['id']} — {t['name']} ({t['tactic']}): {desc}"

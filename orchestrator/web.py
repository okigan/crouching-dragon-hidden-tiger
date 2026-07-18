"""A light FastAPI front end to browse run reports.

    uv run --extra web uvicorn orchestrator.web:app --port 8090
    # or:  security-orchestrator serve

Lists every run under ``runs/`` (newest first) with its headline metrics, and
serves each run's self-contained report.html + attacks.json. No React — the
reports are already rich static HTML.
"""

from __future__ import annotations

import html
import json
import os
import re
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))

app = FastAPI(title="Crouching Dragon Hidden Tiger")
RUNS_DIR.mkdir(exist_ok=True)
app.mount("/runs", StaticFiles(directory=str(RUNS_DIR)), name="runs")


def _run_dirs() -> list[Path]:
    if not RUNS_DIR.is_dir():
        return []
    dirs = [d for d in RUNS_DIR.iterdir()
            if d.is_dir() and (d / "report.html").exists()]
    return sorted(dirs, key=lambda d: d.stat().st_mtime, reverse=True)


def _summary(run: Path) -> dict:
    """Pull a few headline fields from the run's summary.md + attacks.json."""
    info: dict = {"name": run.name}
    text = (run / "summary.md").read_text() if (run / "summary.md").exists() else ""
    for key, label in [("Converged", "converged"),
                       ("Attack-success-rate", "success"),
                       ("Iterations", "rounds"),
                       ("Enforcement", "enforcement")]:
        m = re.search(rf"- {key}:\s*(.+)", text)
        if m:
            info[label] = m.group(1).strip()
    attacks_f = run / "attacks.json"
    if attacks_f.exists():
        try:
            atk = json.loads(attacks_f.read_text())
            info["bypass_hl"] = sum(1 for a in atk if a.get("bypassed_hiddenlayer"))
            info["bypass_os"] = sum(1 for a in atk if a.get("bypassed_openshell"))
            info["attacks"] = len(atk)
        except ValueError:
            pass
    return info


def _card(info: dict) -> str:
    n = html.escape(info["name"])
    conv = info.get("converged", "?")
    badge = "ok" if conv.lower().startswith("y") else "warn"
    bits = []
    if "success" in info:
        bits.append(f'<span class="k">{html.escape(info["success"])}</span> attack-success')
    if "rounds" in info:
        bits.append(f'<span class="k">{html.escape(info["rounds"])}</span> rounds')
    if "attacks" in info:
        bits.append(f'<span class="k">{info.get("bypass_hl", 0)}</span> bypass HiddenLayer · '
                    f'<span class="k">{info.get("bypass_os", 0)}</span> bypass OpenShell')
    meta = " · ".join(bits)
    return (
        f'<a class="run" href="/runs/{n}/report.html">'
        f'<div class="run-head"><span class="badge {badge}">{html.escape(conv)}</span>'
        f'<b>{n}</b></div>'
        f'<div class="meta">{meta}</div></a>'
    )


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    runs = _run_dirs()
    cards = "".join(_card(_summary(r)) for r in runs) or \
        '<p class="empty">No runs yet — run <code>security-orchestrator run</code>.</p>'
    return _PAGE.replace("{{cards}}", cards).replace("{{count}}", str(len(runs)))


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "runs": len(_run_dirs())}


_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Crouching Dragon Hidden Tiger — runs</title>
<style>
  :root { --bg:#f6f8fa; --fg:#1b1f24; --muted:#5b6570; --card:#fff; --line:#e2e6ea; --accent:#3457d5; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0f1216; --fg:#e6edf3; --muted:#9aa5b1; --card:#171b21; --line:#272d35; --accent:#6f8bff; } }
  * { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--fg);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .wrap { max-width:820px; margin:0 auto; padding:28px 18px 60px; }
  h1 { font-size:22px; margin:0 0 2px; } .sub { color:var(--muted); font-size:13px; margin-bottom:22px; }
  .run { display:block; text-decoration:none; color:inherit; background:var(--card);
    border:1px solid var(--line); border-radius:12px; padding:14px 16px; margin-bottom:12px; }
  .run:hover { border-color:var(--accent); }
  .run-head { display:flex; align-items:center; gap:10px; }
  .badge { font-size:11px; font-weight:700; padding:2px 8px; border-radius:20px; text-transform:uppercase; }
  .badge.ok { background:#12321f; color:#5fdd91; } .badge.warn { background:#3a2410; color:#f0a860; }
  .meta { color:var(--muted); font-size:13px; margin-top:6px; } .meta .k { color:var(--fg); font-weight:600; }
  .empty { color:var(--muted); } code { background:rgba(128,128,128,.15); padding:1px 5px; border-radius:5px; }
</style></head><body><div class="wrap">
  <h1>Crouching Dragon Hidden Tiger</h1>
  <div class="sub">{{count}} run(s) — newest first. Click a run to open its report.</div>
  {{cards}}
</div></body></html>"""

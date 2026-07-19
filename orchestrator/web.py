"""A light FastAPI front end to browse run reports.

    uv run --extra web uvicorn orchestrator.web:app --port 8090
    # or:  security-orchestrator serve

Lists every run under ``runs/`` (newest first) with its headline metrics, and
serves each run's self-contained report.html + attacks.json. No React — the
reports are already rich static HTML.
"""

from __future__ import annotations

import datetime
import html
import json
import os
import re
import threading
from pathlib import Path

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))

app = FastAPI(title="Crouching Dragon Hidden Tiger")
RUNS_DIR.mkdir(exist_ok=True)
app.mount("/runs", StaticFiles(directory=str(RUNS_DIR)), name="runs")

# Single in-flight run at a time (this is a local tool, not a job queue).
_job: dict = {"active": False, "name": None, "error": None}


def _run_loop(name: str, generate: int) -> None:
    """Run one analysis loop in a background thread, writing to runs/<name>.

    Always drives the real backends configured in .env (SANDBOX=openshell);
    the mock sandbox exists only for the test suite, never the web UI.
    """
    try:
        from .config import Settings
        from .generator import generate_attacks
        from .loop import LoopConfig, SecurityOrchestrator
        from .policy_store import PolicyStore
        from .reporter import Reporter

        settings = Settings.from_env(dict(os.environ))
        store = PolicyStore.load("policies/permissive.yaml")
        reporter = Reporter(run_dir=RUNS_DIR / name)
        assessor = settings.build_assessor()
        if generate:
            new = generate_attacks(settings.build_generator(), assessor.detect, generate)
            assessor.add_tests(new)
        orch = SecurityOrchestrator(
            settings.build_sandbox(), assessor, settings.build_llm(),
            store, reporter, LoopConfig(),
        )
        reporter.summarize(orch.run())
    except Exception as exc:  # surface any failure in the UI
        _job["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        _job["active"] = False


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


@app.post("/run")
def run(generate: int = Form(3)):
    """Kick off one analysis loop in the background (real backends via .env)."""
    if not _job["active"]:
        name = "run-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        _job.update(active=True, name=name, error=None)
        threading.Thread(
            target=_run_loop, args=(name, generate), daemon=True
        ).start()
    return RedirectResponse("/", status_code=303)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    runs = _run_dirs()
    cards = "".join(_card(_summary(r)) for r in runs) or \
        '<p class="empty">No runs yet — click <b>Run analysis</b> above.</p>'
    if _job["active"]:
        status = (f'<div class="status run-active">⏳ Running <b>{html.escape(_job["name"] or "")}</b>'
                  " — generating prompts, screening HiddenLayer, hardening OpenShell… "
                  '<a href="/">refresh</a></div>')
    elif _job.get("error"):
        status = f'<div class="status run-error">Last run failed: {html.escape(_job["error"])}</div>'
    else:
        status = ""
    return (_PAGE.replace("{{cards}}", cards)
            .replace("{{count}}", str(len(runs)))
            .replace("{{status}}", status))


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "runs": len(_run_dirs()), "running": _job["active"]}


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
  .runbar { display:flex; align-items:center; gap:10px; flex-wrap:wrap; background:var(--card);
    border:1px solid var(--line); border-radius:12px; padding:12px 14px; margin-bottom:14px; }
  .runbar button { background:var(--accent); color:#fff; border:0; border-radius:8px;
    padding:8px 14px; font-weight:600; font-size:14px; cursor:pointer; }
  .runbar label { color:var(--muted); font-size:13px; }
  .runbar input, .runbar select { font:inherit; padding:5px 8px; border:1px solid var(--line);
    border-radius:7px; background:var(--bg); color:var(--fg); }
  .runbar input { width:56px; }
  .runbar .hint { color:var(--muted); font-size:12px; margin-left:auto; }
  .status { border-radius:10px; padding:9px 12px; margin-bottom:14px; font-size:13px; }
  .run-active { background:rgba(52,87,213,.12); color:var(--accent); }
  .run-error { background:rgba(179,21,59,.12); color:#e0607f; }
</style></head><body><div class="wrap">
  <h1>Crouching Dragon Hidden Tiger</h1>
  <div class="sub">{{count}} run(s) — newest first. Click a run to open its report.</div>
  <form class="runbar" method="post" action="/run">
    <button type="submit">▶ Run analysis</button>
    <label>generate <input name="generate" type="number" value="3" min="0" max="10"></label>
    <span class="hint">real backends: cloud vLLM · HiddenLayer · OpenShell gateway</span>
  </form>
  {{status}}
  {{cards}}
</div></body></html>"""

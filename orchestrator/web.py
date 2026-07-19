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
import socket
import threading
from pathlib import Path

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))
# The image a run executes in (built by docker-compose as `cdht-orchestrator`).
ORCH_IMAGE = os.environ.get("ORCH_IMAGE", "cdht-orchestrator")
# Backend config forwarded from this container's env into each run container.
_ENV_PREFIXES = ("LLM", "ASSESSOR", "SANDBOX", "OPENSHELL", "HIDDENLAYER", "NEMOTRON")

app = FastAPI(title="Crouching Dragon Hidden Tiger")
RUNS_DIR.mkdir(exist_ok=True)
app.mount("/runs", StaticFiles(directory=str(RUNS_DIR)), name="runs")

# Single in-flight run at a time (this is a local demo tool, not a job queue).
_job: dict = {"active": False, "name": None, "container": None, "error": None}

_models_cache: dict = {"models": None}


def _current_model() -> str:
    return os.environ.get("NEMOTRON_MODEL", "")


def _llm_endpoint() -> str:
    base = os.environ.get("NEMOTRON_BASE_URL", "")
    return base.split("://")[-1].rstrip("/") if base else ""


def _available_models() -> list[str]:
    """Models the configured vLLM endpoint actually serves (GET /v1/models).
    Cached; returns [] if the endpoint is unset or unreachable."""
    if _models_cache["models"] is not None:
        return _models_cache["models"]
    models: list[str] = []
    base = os.environ.get("NEMOTRON_BASE_URL")
    if base:
        try:
            import urllib.request
            req = urllib.request.Request(
                base.rstrip("/") + "/v1/models",
                headers={"Authorization": f"Bearer {os.environ.get('NEMOTRON_KEY', '')}"},
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.load(r)
            models = [m["id"] for m in data.get("data", []) if m.get("id")]
        except Exception:
            models = []
    # Aggregators (e.g. OpenRouter) list hundreds of models — too many for a
    # dropdown. Keep it relevant: Nemotron models + anything sharing the
    # configured model's vendor prefix, capped. Small lists pass through as-is.
    cur = _current_model()
    if len(models) > 40:
        vendor = cur.split("/")[0] if "/" in cur else ""
        picked = [m for m in models
                  if "nemotron" in m.lower() or (vendor and m.startswith(vendor))]
        models = picked or models[:40]
    # Always include the configured model, even if listing failed / filtered out.
    if cur and cur not in models:
        models.insert(0, cur)
    _models_cache["models"] = models
    return models


def _host_runs_dir(client, me_id: str) -> str | None:
    """Host path backing our /app/runs bind mount. A run executes as a *sibling*
    container launched through the host Docker daemon, so it must mount the same
    host directory — /app/runs is meaningless to the daemon."""
    me = client.containers.get(me_id)
    for m in me.attrs.get("Mounts", []):
        if m.get("Destination") == "/app/runs":
            return m.get("Source")
    return None


def _launch(name: str, generate: int, model: str = "") -> None:
    """Run one analysis as a *visible sibling container* (cdht-<name>).

    The container appears in `docker ps` while the loop runs, writes its report
    into the shared runs/ volume, and removes itself when done — so a demo can
    be driven entirely from the browser. Always uses the real backends from the
    environment (SANDBOX=openshell); mocks are test-only, never the web UI.
    """
    container = None
    try:
        import docker

        client = docker.from_env()
        host_runs = _host_runs_dir(client, socket.gethostname())
        if not host_runs:
            raise RuntimeError(
                "cannot resolve the host path for /app/runs — launch the web UI "
                "through the docker stack (make stack-up), not a bare process")
        env = {k: v for k, v in os.environ.items()
               if any(k.startswith(p) for p in _ENV_PREFIXES)}
        if model:  # per-run LLM override picked in the UI
            env["NEMOTRON_MODEL"] = model
        container = client.containers.run(
            ORCH_IMAGE,
            command=["run", "--generate", str(generate),
                     "--out", f"/app/runs/{name}",
                     "--save-policy", f"/app/runs/{name}/hardened.yaml"],
            name=f"cdht-{name}",
            detach=True,
            environment=env,
            volumes={host_runs: {"bind": "/app/runs", "mode": "rw"}},
            extra_hosts={"host.docker.internal": "host-gateway"},
        )
        _job["container"] = container.name
        status = container.wait()  # blocks until the run finishes
        code = status.get("StatusCode", 0)
        # The container removes itself below (no lingering entries), so persist
        # its logs to the run dir first — otherwise they vanish with it.
        _save_logs(container, name)
        # A crash and a "did not converge" both exit 1, so the exit code alone
        # can't tell success from failure — the report file is the real signal.
        report_written = (RUNS_DIR / name / "report.html").exists()
        if not report_written:
            tail = container.logs(tail=30).decode("utf-8", "replace")
            _job["error"] = f"run container exited {code} without a report\n{tail}"
    except Exception as exc:  # surface any failure in the UI
        _job["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass
        _job.update(active=False, container=None)


def _save_logs(container, name: str) -> None:
    """Persist the run container's stdout/stderr to runs/<name>/run.log so it
    survives the container's self-removal (viewable in the UI at /runs/…/run.log)."""
    try:
        text = container.logs(timestamps=True).decode("utf-8", "replace")
        run_dir = RUNS_DIR / name
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "run.log").write_text(text)
    except Exception:
        pass


def _run_dirs() -> list[Path]:
    if not RUNS_DIR.is_dir():
        return []
    dirs = [d for d in RUNS_DIR.iterdir()
            if d.is_dir() and (d / "report.html").exists()]
    return sorted(dirs, key=lambda d: d.stat().st_mtime, reverse=True)


def _format_when(iso: str | None, run_name: str) -> str:
    """Human timestamp for a run: the report's Generated time (UTC), falling back
    to the run-<YYYYMMDD-HHMMSS> directory name."""
    if iso:
        try:
            dt = datetime.datetime.fromisoformat(iso)
            return dt.strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            pass
    m = re.match(r"run-(\d{8})-(\d{6})", run_name)
    if m:
        d, t = m.group(1), m.group(2)
        return f"{d[:4]}-{d[4:6]}-{d[6:]} {t[:2]}:{t[2:4]}"
    return ""


def _summary(run: Path) -> dict:
    """Pull a few headline fields from the run's summary.md + attacks.json."""
    info: dict = {"name": run.name}
    text = (run / "summary.md").read_text() if (run / "summary.md").exists() else ""
    for key, label in [("Converged", "converged"),
                       ("Attack-success-rate", "success"),
                       ("Iterations", "rounds"),
                       ("Enforcement", "enforcement"),
                       ("Generated", "when"),
                       ("LLM", "llm")]:
        m = re.search(rf"- {key}:\s*(.+)", text)
        if m:
            info[label] = m.group(1).strip()
    info["when"] = _format_when(info.get("when"), run.name)
    info["has_log"] = (run / "run.log").exists()
    # Chart + final-round "caught by" counts (same framing as the report).
    info.update(_defense_view(run))
    return info


def _defense_view(run: Path) -> dict:
    """From a run's traces.json: the '% defended per round' stacked chart plus
    the final-round counts of attacks caught by HiddenLayer vs OpenShell — the
    same defended framing the detailed report uses, so card and report agree."""
    tf = run / "traces.json"
    if not tf.exists():
        return {}
    try:
        traces = json.loads(tf.read_text())
    except ValueError:
        return {}
    cols = []
    for t in traces:
        fs = t.get("findings", [])
        n = len(fs) or 1
        hl = sum(1 for f in fs if f.get("hl_detected"))
        os_ = sum(1 for f in fs if f.get("openshell_blocked") and not f.get("hl_detected"))
        landed = sum(1 for f in fs if not f.get("resolved"))
        cols.append(
            f'<span class="mcol">'
            f'<i class="ms landed" style="height:{landed / n * 100:.0f}%"></i>'
            f'<i class="ms os" style="height:{os_ / n * 100:.0f}%"></i>'
            f'<i class="ms hl" style="height:{hl / n * 100:.0f}%"></i></span>'
        )
    chart = ('<div class="mchart" title="% defended per round — green HiddenLayer '
             f'+ blue OpenShell, red landed">{"".join(cols)}</div>')
    # final-round layer attribution (exclude REG- regression duplicates)
    final = [f for f in (traces[-1].get("findings", []) if traces else [])
             if not f.get("id", "").startswith("REG-")]
    caught_hl = sum(1 for f in final if f.get("hl_detected"))
    caught_os = sum(1 for f in final
                    if f.get("openshell_blocked") and not f.get("hl_detected"))
    return {"chart": chart, "caught_hl": caught_hl, "caught_os": caught_os}


def _card(info: dict) -> str:
    n = html.escape(info["name"])
    conv = info.get("converged", "?")
    badge = "ok" if conv.lower().startswith("y") else "warn"
    badge_txt = "converged" if badge == "ok" else html.escape(conv)

    # "attacks defended" (higher is better) — same framing as the report. Invert
    # the recorded attack-success-rate "60% → 0% (delta +60%)" into "40% → 100%".
    defended, delta = "", ""
    m = re.match(r"(\d+)%\s*→\s*(\d+)%\s*\(delta\s*([^)]+)\)", info.get("success", ""))
    if m:
        a, b = 100 - int(m.group(1)), 100 - int(m.group(2))
        defended = f"{a}% → {b}%"
        delta = f' <span class="delta">{html.escape(m.group(3).strip())}</span>'

    stats = []
    if defended:
        stats.append(f'<div class="stat"><b>{defended}</b>'
                     f'<em>attacks defended{delta}</em></div>')
    if info.get("rounds"):
        stats.append(f'<div class="stat"><b>{html.escape(info["rounds"])}</b>'
                     f'<em>rounds</em></div>')
    if "caught_hl" in info:
        stats.append(f'<div class="stat"><b>{info.get("caught_hl", 0)} / '
                     f'{info.get("caught_os", 0)}</b>'
                     f'<em>caught by HiddenLayer / OpenShell</em></div>')
    stats_html = f'<div class="stats">{"".join(stats)}</div>'

    sub_bits = []
    if info.get("when"):
        sub_bits.append(f'<span>🕐 {html.escape(info["when"])}</span>')
    if info.get("llm"):
        sub_bits.append(f'<span>🧠 {html.escape(info["llm"])}</span>')
    subline = (f'<div class="run-sub">{"".join(sub_bits)}</div>'
               if sub_bits else "")

    log_link = (f'<a href="/log/{n}">log</a>' if info.get("has_log") else "")
    chart = info.get("chart", "")
    chart_block = (f'<div class="run-chart">{chart}'
                   f'<span class="chart-cap">% defended ↑</span></div>' if chart else "")
    return (
        f'<div class="run">'
        f'<div class="run-main">'
        f'<div class="run-head"><span class="badge {badge}">{badge_txt}</span>'
        f'<a class="run-title" href="/runs/{n}/report.html">{n}</a></div>'
        f'{subline}'
        f'{stats_html}'
        f'<div class="links"><a href="/runs/{n}/report.html">open report</a>{log_link}</div>'
        f'</div>'
        f'{chart_block}'
        f'</div>'
    )


@app.post("/run")
def run(generate: int = Form(3), model: str = Form("")):
    """Launch one analysis run as a visible sibling container (real backends)."""
    if not _job["active"]:
        name = "run-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        _job.update(active=True, name=name, container=None, error=None)
        threading.Thread(
            target=_launch, args=(name, generate, model), daemon=True
        ).start()
    return RedirectResponse("/", status_code=303)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    runs = _run_dirs()
    cards = "".join(_card(_summary(r)) for r in runs) or \
        '<p class="empty">No runs yet — click <b>Run analysis</b> above.</p>'
    if _job["active"]:
        cname = html.escape(_job.get("container") or "starting…")
        status = (f'<div class="status run-active">⏳ Running in container '
                  f'<code>{cname}</code> — generating prompts, screening HiddenLayer, '
                  "hardening OpenShell. Watch it in Docker; it removes itself when done. "
                  '<a href="/">refresh</a></div>')
    elif _job.get("error"):
        status = f'<div class="status run-error">Last run failed: {html.escape(_job["error"])}</div>'
    else:
        status = ""
    return (_PAGE.replace("{{cards}}", cards)
            .replace("{{count}}", str(len(runs)))
            .replace("{{status}}", status)
            .replace("{{llm}}", _llm_control()))


def _llm_control() -> str:
    """The LLM selector for the run bar: a dropdown of the models the endpoint
    serves (current one selected), or plain text if only one/none is known."""
    cur = _current_model()
    endpoint = _llm_endpoint()
    models = _available_models()
    ep = f' <span class="hint">@ {html.escape(endpoint)}</span>' if endpoint else ""
    if len(models) > 1:
        opts = "".join(
            f'<option value="{html.escape(m)}"{" selected" if m == cur else ""}>'
            f'{html.escape(m)}</option>' for m in models
        )
        return (f'<label title="LLM used to generate attacks and reason about '
                f'fixes">🧠 LLM <select name="model">{opts}</select></label>{ep}')
    # single or unknown model → show it, no dropdown (still submit it)
    shown = html.escape(cur or "default")
    return (f'<label>🧠 LLM <input name="model" value="{html.escape(cur)}" '
            f'class="llm-static" readonly></label>{ep}' if cur
            else f'<span class="hint">🧠 LLM: {shown}</span>')


@app.get("/log/{name}", response_class=PlainTextResponse)
def log(name: str) -> PlainTextResponse:
    """Serve a run's captured container log inline as text (it outlives the
    self-removing run container). ``name`` is confined to a child of runs/."""
    p = (RUNS_DIR / name / "run.log").resolve()
    if RUNS_DIR.resolve() not in p.parents or not p.is_file():
        return PlainTextResponse("no log for this run", status_code=404)
    return PlainTextResponse(p.read_text())


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "runs": len(_run_dirs()), "running": _job["active"]}


_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Crouching Dragon Hidden Tiger — runs</title>
<style>
  :root { --bg:#f6f8fa; --fg:#1b1f24; --muted:#5b6570; --card:#fff; --line:#e2e6ea; --accent:#3457d5; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0f1216; --fg:#e6edf3; --muted:#9aa5b1; --card:#171b21; --line:#272d35; --accent:#6f8bff; } }
  * { box-sizing:border-box; } html, body { overflow-x:hidden; }
  body { margin:0; background:var(--bg); color:var(--fg);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  /* Faint dragon (left) + tiger (right) backdrop — the namesake, kept subtle. */
  body::before, body::after { content:""; position:fixed; top:50%;
    transform:translateY(-50%); font-size:52vh; line-height:1; z-index:0;
    opacity:.16; pointer-events:none; user-select:none; }
  body::before { content:"🐉"; left:-.08em; }
  body::after { content:"🐅"; right:-.08em; transform:translateY(-50%) scaleX(-1); }
  @media (prefers-color-scheme: dark) { body::before, body::after { opacity:.20; } }
  @media (max-width:1100px) { body::before, body::after { opacity:.08; } }
  @media (max-width:820px) { body::before, body::after { display:none; } }
  .wrap { max-width:820px; margin:0 auto; padding:28px 18px 60px;
    position:relative; z-index:1; }
  h1 { font-size:22px; margin:0 0 2px; } .sub { color:var(--muted); font-size:13px; margin-bottom:22px; }
  .run { display:flex; align-items:center; gap:20px; text-decoration:none; color:inherit;
    background:var(--card); border:1px solid var(--line); border-radius:14px;
    padding:18px 20px; margin-bottom:14px; box-shadow:0 1px 2px rgba(0,0,0,.04);
    transition:border-color .12s, box-shadow .12s; }
  .run-main { flex:1; min-width:0; }
  .run:hover { border-color:var(--accent); box-shadow:0 3px 12px rgba(52,87,213,.10); }
  .run-head { display:flex; align-items:center; gap:10px; }
  .run-title { text-decoration:none; color:inherit; font-weight:700; font-size:16px;
    font-variant-numeric:tabular-nums; }
  .run-title:hover { color:var(--accent); }
  .run-sub { color:var(--muted); font-size:12px; margin-top:6px; display:flex;
    gap:14px; flex-wrap:wrap; }
  .stats { display:flex; gap:26px; flex-wrap:wrap; margin-top:12px; }
  .stat { display:flex; flex-direction:column; gap:1px; }
  .stat b { font-size:16px; font-weight:700; font-variant-numeric:tabular-nums; }
  .stat em { font-style:normal; color:var(--muted); font-size:11px; }
  .stat .delta { color:#2fbd6b; font-weight:700; }
  .links { margin-top:12px; font-size:12px; display:flex; gap:14px; }
  .links a, .sub-link { color:var(--accent); text-decoration:none; font-weight:500; }
  .links a:hover { text-decoration:underline; }
  .badge { font-size:10px; font-weight:700; padding:3px 9px; border-radius:20px;
    text-transform:uppercase; letter-spacing:.03em; }
  .badge.ok { background:#12321f; color:#5fdd91; } .badge.warn { background:#3a2410; color:#f0a860; }
  .run-chart { display:flex; flex-direction:column; align-items:center; gap:6px; flex:none; }
  .chart-cap { font-size:10px; color:var(--muted); white-space:nowrap; }
  .mchart { display:flex; align-items:flex-end; gap:4px; height:52px; }
  .mcol { width:12px; height:100%; display:flex; flex-direction:column;
    justify-content:flex-end; border-radius:3px; overflow:hidden;
    background:rgba(128,128,128,.12); }
  .ms { width:100%; display:block; }
  .ms.hl { background:#2fbd6b; } .ms.os { background:#3457d5; } .ms.landed { background:#d5304a; }
  .empty { color:var(--muted); } code { background:rgba(128,128,128,.15); padding:1px 5px; border-radius:5px; }
  .runbar { display:flex; align-items:center; gap:10px; flex-wrap:wrap; background:var(--card);
    border:1px solid var(--line); border-radius:12px; padding:12px 14px; margin-bottom:14px; }
  .runbar button { background:var(--accent); color:#fff; border:0; border-radius:8px;
    padding:8px 14px; font-weight:600; font-size:14px; cursor:pointer; }
  .runbar label { color:var(--muted); font-size:13px; }
  .runbar input, .runbar select { font:inherit; padding:5px 8px; border:1px solid var(--line);
    border-radius:7px; background:var(--bg); color:var(--fg); }
  .runbar input.num { width:56px; }
  .runbar select, .runbar .llm-static { max-width:230px; }
  .runbar .hint { color:var(--muted); font-size:12px; }
  .status { border-radius:10px; padding:9px 12px; margin-bottom:14px; font-size:13px; }
  .run-active { background:rgba(52,87,213,.12); color:var(--accent); }
  .run-error { background:rgba(179,21,59,.12); color:#e0607f; }
</style></head><body><div class="wrap">
  <h1>Crouching Dragon Hidden Tiger</h1>
  <div class="sub">{{count}} run(s) — newest first. Click a run to open its report.</div>
  <form class="runbar" method="post" action="/run">
    <button type="submit">▶ Run analysis</button>
    <label title="How many new attack prompts the vLLM should craft and screen this run (0 = corpus only)">
      new AI attacks to generate
      <input class="num" name="generate" type="number" value="3" min="0" max="10"></label>
    {{llm}}
  </form>
  {{status}}
  {{cards}}
</div></body></html>"""

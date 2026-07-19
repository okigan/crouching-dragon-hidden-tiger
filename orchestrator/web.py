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

_index_cache: dict = {"map": None}


def _current_model() -> str:
    return os.environ.get("NEMOTRON_MODEL", "")


def _provider_label(url: str) -> str:
    host = url.split("://")[-1].rstrip("/") if url else ""
    return "OpenRouter" if "openrouter" in host else host


def _providers() -> list[dict]:
    """The LLM endpoints available to run against. The primary is NEMOTRON_* ;
    additional ones come from LLM_PROVIDERS (a JSON list of
    {base_url, key, label}) so the UI can offer, e.g., OpenRouter *and* a
    self-hosted vLLM box at once."""
    provs: list[dict] = []
    base = os.environ.get("NEMOTRON_BASE_URL")
    if base:
        provs.append({"base_url": base, "key": os.environ.get("NEMOTRON_KEY", ""),
                      "label": _provider_label(base)})
    raw = os.environ.get("LLM_PROVIDERS")
    if raw:
        try:
            for p in json.loads(raw):
                if p.get("base_url"):
                    provs.append({
                        "base_url": p["base_url"], "key": p.get("key", ""),
                        "label": p.get("label") or _provider_label(p["base_url"]),
                    })
        except Exception:
            pass
    return provs


def _fetch_models(base: str, key: str) -> list[str]:
    try:
        import urllib.request
        req = urllib.request.Request(
            base.rstrip("/") + "/v1/models",
            headers={"Authorization": f"Bearer {key}"},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.load(r)
        return [m["id"] for m in data.get("data", []) if m.get("id")]
    except Exception:
        return []


def _model_index() -> dict:
    """model id -> the provider that serves it, across all endpoints. Cached.
    Endpoints that list hundreds of models (OpenRouter) are filtered to the
    relevant ones (Nemotron + the configured model's vendor)."""
    if _index_cache["map"] is not None:
        return _index_cache["map"]
    idx: dict = {}
    cur = _current_model()
    for prov in _providers():
        ids = _fetch_models(prov["base_url"], prov["key"])
        if len(ids) > 40:
            vendor = cur.split("/")[0] if "/" in cur else ""
            ids = [m for m in ids
                   if "nemotron" in m.lower() or (vendor and m.startswith(vendor))] \
                or ids[:40]
        for mid in ids:
            idx.setdefault(mid, prov)  # first provider that serves it wins
    if cur and cur not in idx:  # always offer the configured model
        provs = _providers()
        idx[cur] = provs[0] if provs else {"base_url": "", "key": ""}
    _index_cache["map"] = idx
    return idx


def _available_models() -> list[str]:
    return sorted(_model_index().keys())


def _host_runs_dir(client, me_id: str) -> str | None:
    """Host path backing our /app/runs bind mount. A run executes as a *sibling*
    container launched through the host Docker daemon, so it must mount the same
    host directory — /app/runs is meaningless to the daemon."""
    me = client.containers.get(me_id)
    for m in me.attrs.get("Mounts", []):
        if m.get("Destination") == "/app/runs":
            return m.get("Source")
    return None


def _launch(name: str, generate: int, model: str = "",
            tactics: str = "", categories: str = "") -> None:
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
            prov = _model_index().get(model)  # route to the endpoint serving it
            if prov and prov.get("base_url"):
                env["NEMOTRON_BASE_URL"] = prov["base_url"]
                env["NEMOTRON_KEY"] = prov["key"]
        command = ["run", "--generate", str(generate),
                   "--out", f"/app/runs/{name}",
                   "--save-policy", f"/app/runs/{name}/hardened.yaml"]
        if tactics:
            command += ["--tactics", tactics]
        if categories:
            command += ["--categories", categories]
        container = client.containers.run(
            ORCH_IMAGE,
            command=command,
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


def _live_progress() -> str:
    """The latest progress line from the running container's live logs — e.g.
    '[round 2] assessed 11 attacks · 4 landed · 7 defended'. Empty if the
    container isn't up yet or its logs aren't reachable."""
    cname = _job.get("container")
    if not cname:
        return ""
    try:
        import docker

        raw = docker.from_env().containers.get(cname).logs(tail=50)
        text = raw.decode("utf-8", "replace")
    except Exception:
        return ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in reversed(lines):  # newest meaningful step first
        if (ln.startswith("[round") or ln.startswith("generated")
                or "converged" in ln or "visual report" in ln):
            return ln
    return lines[-1] if lines else ""


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
    """From a run's traces.json: a convergence sparkline (share of attacks
    defended, climbing per round toward 100%) plus the final-round counts of
    attacks caught by HiddenLayer vs OpenShell."""
    tf = run / "traces.json"
    if not tf.exists():
        return {}
    try:
        traces = json.loads(tf.read_text())
    except ValueError:
        return {}
    fracs = []
    for t in traces:
        fs = t.get("findings", [])
        n = len(fs) or 1
        landed = sum(1 for f in fs if not f.get("resolved"))
        fracs.append((n - landed) / n)
    chart = _sparkline(fracs)
    # final-round layer attribution (exclude REG- regression duplicates)
    final = [f for f in (traces[-1].get("findings", []) if traces else [])
             if not f.get("id", "").startswith("REG-")]
    caught_hl = sum(1 for f in final if f.get("hl_detected"))
    caught_os = sum(1 for f in final
                    if f.get("openshell_blocked") and not f.get("hl_detected"))
    return {"chart": chart, "caught_hl": caught_hl, "caught_os": caught_os}


def _sparkline(fracs: list[float]) -> str:
    """An SVG area+line sparkline of the defended share (0..1) per round. Ends on
    a marker at the final value; a dashed rule marks the 100%-defended target."""
    if not fracs:
        return ""
    W, H, pad = 148.0, 44.0, 4.0
    pts = fracs if len(fracs) > 1 else fracs * 2
    span = len(pts) - 1
    coords = [
        (pad + (W - 2 * pad) * (i / span), pad + (H - 2 * pad) * (1 - fr))
        for i, fr in enumerate(pts)
    ]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    area = f"{coords[0][0]:.1f},{H - pad:.1f} {line} {coords[-1][0]:.1f},{H - pad:.1f}"
    lx, ly = coords[-1]
    return (
        f'<svg class="spark" viewBox="0 0 {W:.0f} {H:.0f}" '
        f'width="{W:.0f}" height="{H:.0f}" role="img" '
        f'aria-label="share of attacks defended per round">'
        f'<line class="spk-goal" x1="{pad:.0f}" y1="{pad:.0f}" '
        f'x2="{W - pad:.0f}" y2="{pad:.0f}"/>'
        f'<polygon class="spk-area" points="{area}"/>'
        f'<polyline class="spk-line" points="{line}"/>'
        f'<circle class="spk-dot" cx="{lx:.1f}" cy="{ly:.1f}" r="2.6"/>'
        f'</svg>'
    )


def _card(info: dict) -> str:
    n = html.escape(info["name"])
    conv = info.get("converged", "?")
    badge = "ok" if conv.lower().startswith("y") else "warn"
    badge_txt = "converged" if badge == "ok" else html.escape(conv)

    # "attacks defended" (higher is better) — same framing as the report. Invert
    # the recorded attack-success-rate "60% → 0% (delta +60%)" into "40% → 100%".
    hero, trend = "", ""
    m = re.match(r"(\d+)%\s*→\s*(\d+)%\s*\(delta\s*([^)]+)\)", info.get("success", ""))
    if m:
        a, b = 100 - int(m.group(1)), 100 - int(m.group(2))
        hero = f"{b}%"
        trend = (f'<span class="mtrend">from {a}% '
                 f'<b class="delta">{html.escape(m.group(3).strip())}</b></span>')

    meta = []
    if info.get("rounds"):
        meta.append(f'{html.escape(info["rounds"])} rounds')
    if "caught_hl" in info:
        meta.append(f'{info.get("caught_hl", 0)} HL &middot; '
                    f'{info.get("caught_os", 0)} OS caught')
    meta_html = (f'<div class="metric-meta">{"".join(f"<span>{x}</span>" for x in meta)}</div>'
                 if meta else "")

    metrics_html = (
        f'<div class="metrics">'
        f'<span class="mlabel">attacks defended</span>'
        f'<div class="metric-hero"><span class="mnum">{hero or "—"}</span>{trend}</div>'
        f'{meta_html}'
        f'</div>'
    )

    sub_parts = []
    if info.get("when"):
        sub_parts.append(html.escape(info["when"]))
    if info.get("llm"):
        sub_parts.append(html.escape(info["llm"]))
    subline = (f'<div class="run-sub">{" &middot; ".join(sub_parts)}</div>'
               if sub_parts else "")

    log_link = (f'<a href="/log/{n}">log</a>' if info.get("has_log") else "")
    chart = info.get("chart", "")
    chart_block = (f'<div class="run-chart">{chart}'
                   f'<span class="chart-cap">defense per round</span></div>' if chart else "")
    return (
        f'<div class="run">'
        f'<div class="run-id">'
        f'<div class="run-head"><span class="badge {badge}">{badge_txt}</span>'
        f'<a class="run-title" href="/runs/{n}/report.html">{n}</a></div>'
        f'{subline}'
        f'<div class="links"><a href="/runs/{n}/report.html">open report</a>{log_link}</div>'
        f'</div>'
        f'{metrics_html}'
        f'{chart_block}'
        f'</div>'
    )


@app.post("/run")
def run(generate: int = Form(3), model: str = Form(""),
        tactics: list[str] = Form(default=[]),
        categories: list[str] = Form(default=[])):
    """Launch one analysis run as a visible sibling container (real backends).

    `tactics`/`categories` are the checked APE-coverage boxes; a filter is passed
    to the run only when it's a strict subset (all-checked = full taxonomy, no
    filter), and an empty selection is treated as 'all' rather than 'none'."""
    from . import ape
    from .generator import CATEGORIES
    all_tac = {t["id"] for t in ape.tactics()}
    sel_tac = {t for t in tactics if t in all_tac}
    sel_cat = {c for c in categories if c in CATEGORIES}
    tac_arg = ",".join(sorted(sel_tac)) if 0 < len(sel_tac) < len(all_tac) else ""
    cat_arg = ",".join(sorted(sel_cat)) if 0 < len(sel_cat) < len(CATEGORIES) else ""
    if not _job["active"]:
        name = "run-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        _job.update(active=True, name=name, container=None, error=None)
        threading.Thread(
            target=_launch, args=(name, generate, model, tac_arg, cat_arg),
            daemon=True,
        ).start()
    return RedirectResponse("/", status_code=303)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    runs = _run_dirs()
    cards = "".join(_card(_summary(r)) for r in runs) or \
        '<p class="empty">No runs yet — click <b>Run analysis</b> above.</p>'
    if _job["active"]:
        cname = html.escape(_job.get("container") or "starting…")
        prog = html.escape(_live_progress()
                           or "starting the container — generating the attack corpus…")
        status = (
            '<div class="status run-active">'
            f'<div class="st-row"><span class="spin"></span><b>Running</b> '
            f'<code>{cname}</code></div>'
            f'<div class="st-prog">{prog}</div>'
            '<div class="st-sub">generate prompts → screen HiddenLayer → harden '
            'OpenShell · live, auto-refreshing every few seconds</div>'
            "<script>setTimeout(function(){location.reload()},2500)</script>"
            '</div>')
    elif _job.get("error"):
        status = f'<div class="status run-error">Last run failed: {html.escape(_job["error"])}</div>'
    else:
        status = ""
    return (_PAGE.replace("{{cards}}", cards)
            .replace("{{count}}", str(len(runs)))
            .replace("{{status}}", status)
            .replace("{{apefilter}}", _ape_filter())
            .replace("{{llm}}", _llm_control()))


def _llm_control() -> str:
    """The model selector for the run bar: every model across all configured
    endpoints (each option tagged with its provider), current one selected."""
    cur = _current_model()
    idx = _model_index()
    models = sorted(idx.keys())
    if not models:
        shown = html.escape(cur or "default")
        return ('<div class="ctrl grow"><span class="clab">🧠 model</span>'
                f'<span class="static">{shown}</span></div>')
    opts = []
    for m in models:
        prov = idx.get(m, {})
        tag = f' · {html.escape(prov.get("label", ""))}' if prov.get("label") else ""
        sel = " selected" if m == cur else ""
        opts.append(f'<option value="{html.escape(m)}"{sel}>{html.escape(m)}{tag}</option>')
    return ('<div class="ctrl grow"><span class="clab" title="LLM used to generate '
            'attacks and reason about fixes">🧠 model</span>'
            f'<select name="model">{"".join(opts)}</select></div>')


def _chip(name: str, value: str, label: str) -> str:
    return (f'<label class="chip"><input type="checkbox" name="{name}" '
            f'value="{html.escape(value)}" checked>{html.escape(label)}</label>')


def _ape_filter() -> str:
    """Always-visible APE-coverage selector: tactic (how) + category (what)
    chip toggles, all checked by default, that narrow the generation pool."""
    from . import ape
    from .generator import CATEGORIES
    tac = "".join(_chip("tactics", t["id"], f'{t["id"]} · {t["name"]}')
                  for t in ape.tactics())
    cat = "".join(_chip("categories", c, c.replace("_", " "))
                  for c in CATEGORIES)

    def group(field: str, label: str, chips: str) -> str:
        return (
            '<div class="apegroup">'
            f'<div class="gl"><span class="clab">{label}</span>'
            f'<span class="gtog"><a data-all="{field}">all</a>'
            f'<a data-none="{field}">none</a></span></div>'
            f'<div class="chips">{chips}</div></div>'
        )

    return (
        '<div class="apefilter">'
        '<div class="apehead"><b>🎯 APE coverage</b>'
        '<span class="hint">the red team gets <b id="est-k">2</b> tries to breach '
        'each checked category, using the checked tactics — '
        '<b id="est-n">…</b></span></div>'
        '<div class="apecols">'
        f'{group("tactics", "tactics · the “how”", tac)}'
        f'{group("categories", "categories · the “what”", cat)}'
        '</div>'
        "<script>(function(){"
        "function upd(){var k=+(document.getElementById('tries')||{}).value||0,"
        "c=document.querySelectorAll('input[name=\"categories\"]:checked').length,"
        "t=document.querySelectorAll('input[name=\"tactics\"]:checked').length;"
        "var ek=document.getElementById('est-k'),en=document.getElementById('est-n');"
        "if(ek)ek.textContent=k;"
        "if(en)en.textContent=(t&&c)?('up to '+(k*c)+' attempts · '+c+' categories × '+k+' tries')"
        ":'select at least one tactic and category';}"
        "document.querySelectorAll('.gtog a').forEach(function(a){"
        "a.addEventListener('click',function(){var n=a.dataset.all||a.dataset.none,"
        "on=!!a.dataset.all;document.querySelectorAll('input[name=\"'+n+'\"]')"
        ".forEach(function(c){c.checked=on;});upd();});});"
        "document.querySelectorAll('input[name=\"categories\"],input[name=\"tactics\"]')"
        ".forEach(function(c){c.addEventListener('change',upd);});"
        "var ti=document.getElementById('tries');if(ti)ti.addEventListener('input',upd);"
        "upd();})();</script>"
        '</div>'
    )


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
    opacity:.06; pointer-events:none; user-select:none; }
  body::before { content:"🐉"; left:-.1em; }
  body::after { content:"🐅"; right:-.1em; transform:translateY(-50%) scaleX(-1); }
  @media (prefers-color-scheme: dark) { body::before, body::after { opacity:.09; } }
  @media (max-width:1180px) { body::before, body::after { opacity:.04; } }
  @media (max-width:900px) { body::before, body::after { display:none; } }
  .wrap { max-width:1060px; margin:0 auto; padding:40px 28px 80px;
    position:relative; z-index:1; }
  h1 { font-size:24px; margin:0 0 4px; } .sub { color:var(--muted); font-size:13px; margin-bottom:28px; }
  .run { display:grid; grid-template-columns:minmax(240px,1.3fr) minmax(150px,1fr) auto;
    align-items:center; column-gap:36px; row-gap:18px; color:inherit;
    background:var(--card); border:1px solid var(--line); border-radius:14px;
    padding:22px 26px; margin-bottom:12px;
    transition:border-color .14s, box-shadow .14s, transform .14s; }
  .run:hover { border-color:var(--accent);
    box-shadow:0 6px 22px rgba(15,23,42,.08); transform:translateY(-1px); }
  .run-id { min-width:0; }
  .run-head { display:flex; align-items:center; gap:12px; }
  .run-title { text-decoration:none; color:inherit; font-weight:600; font-size:15px;
    font-variant-numeric:tabular-nums; letter-spacing:-.01em; }
  .run-title:hover { color:var(--accent); }
  .run-sub { color:var(--muted); font-size:12.5px; margin-top:7px;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
    font-variant-numeric:tabular-nums; }
  /* metric block */
  .metrics { display:flex; flex-direction:column; gap:5px; min-width:0; }
  .mlabel { font-size:10.5px; font-weight:600; color:var(--muted);
    text-transform:uppercase; letter-spacing:.06em; }
  .metric-hero { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }
  .mnum { font-size:30px; font-weight:680; line-height:1;
    font-variant-numeric:tabular-nums; letter-spacing:-.02em; }
  .mtrend { font-size:12px; color:var(--muted); font-variant-numeric:tabular-nums; }
  .delta { color:#0f9d74; font-weight:700; }
  .metric-meta { display:flex; flex-wrap:wrap; gap:6px 0; margin-top:2px;
    font-size:11.5px; color:var(--muted); font-variant-numeric:tabular-nums; }
  .metric-meta span:not(:last-child)::after { content:"·"; margin:0 8px; opacity:.6; }
  @media (max-width:820px) { .run { grid-template-columns:1fr; column-gap:0; } }
  .links { margin-top:16px; font-size:12px; display:flex; gap:16px; }
  .links a, .sub-link { color:var(--accent); text-decoration:none; font-weight:500; }
  .links a:hover { text-decoration:underline; }
  .badge { font-size:9.5px; font-weight:700; padding:3px 8px; border-radius:5px;
    text-transform:uppercase; letter-spacing:.04em; border:1px solid transparent; }
  .badge.ok { background:rgba(15,157,116,.12); color:#0f9d74; border-color:rgba(15,157,116,.25); }
  .badge.warn { background:rgba(224,138,50,.12); color:#c8791d; border-color:rgba(224,138,50,.25); }
  /* convergence sparkline */
  .run-chart { display:flex; flex-direction:column; align-items:center; gap:7px; flex:none; }
  .chart-cap { font-size:10px; color:var(--muted); white-space:nowrap;
    letter-spacing:.03em; text-transform:uppercase; }
  .spark { display:block; overflow:visible; }
  .spk-area { fill:var(--accent); opacity:.10; stroke:none; }
  .spk-line { fill:none; stroke:var(--accent); stroke-width:1.8;
    stroke-linejoin:round; stroke-linecap:round; }
  .spk-dot { fill:var(--card); stroke:var(--accent); stroke-width:1.8; }
  .spk-goal { stroke:var(--line); stroke-width:1; stroke-dasharray:2 3; }
  .empty { color:var(--muted); } code { background:rgba(128,128,128,.15); padding:1px 5px; border-radius:5px; }
  .runbar { display:flex; align-items:center; gap:16px; flex-wrap:wrap; background:var(--card);
    border:1px solid var(--line); border-radius:14px; padding:16px 20px; margin-bottom:20px; }
  .runbar button { background:var(--accent); color:#fff; border:0; border-radius:9px;
    padding:11px 20px; font-weight:600; font-size:14px; cursor:pointer; white-space:nowrap;
    box-shadow:0 1px 3px rgba(52,87,213,.3); }
  .runbar button:hover { filter:brightness(1.06); }
  .ctrl { display:flex; align-items:center; gap:9px; }
  .ctrl.grow { flex:1; min-width:260px; }
  .clab { color:var(--muted); font-size:12px; font-weight:600; white-space:nowrap; }
  .runbar input, .runbar select { font:inherit; padding:9px 11px; border:1px solid var(--line);
    border-radius:8px; background:var(--bg); color:var(--fg); height:40px; }
  .runbar input:focus, .runbar select:focus { outline:none; border-color:var(--accent); }
  .runbar input.num { width:60px; text-align:center; }
  .ctrl.grow select { flex:1; width:100%; }
  .static { color:var(--fg); font-size:13px; }
  .apefilter { flex-basis:100%; border-top:1px solid var(--line); padding-top:16px;
    margin-top:4px; }
  .apehead { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }
  .apehead b { font-size:14px; }
  .apehead .hint { color:var(--muted); font-size:12px; }
  .apecols { display:grid; grid-template-columns:1fr 1fr; gap:26px 40px; margin-top:16px; }
  @media (max-width:760px) { .apecols { grid-template-columns:1fr; } }
  .apegroup { min-width:0; }
  .gl { display:flex; align-items:center; gap:10px; margin-bottom:11px; }
  .gl .clab { font-size:11px; text-transform:uppercase; letter-spacing:.05em; }
  .gtog { margin-left:auto; display:flex; gap:8px; font-size:11px; }
  .gtog a { color:var(--accent); cursor:pointer; text-decoration:none; }
  .gtog a:hover { text-decoration:underline; }
  .chips { display:flex; flex-wrap:wrap; gap:8px; }
  .chip { display:inline-flex; align-items:center; font-size:12.5px; line-height:1;
    padding:7px 13px; border:1px solid var(--line); border-radius:20px;
    background:var(--bg); color:var(--muted); cursor:pointer; user-select:none;
    white-space:nowrap; transition:border-color .12s, background .12s, color .12s; }
  .chip input { position:absolute; opacity:0; width:0; height:0; }
  .chip:hover { border-color:var(--accent); }
  .chip:has(input:checked) { background:rgba(52,87,213,.12);
    border-color:rgba(52,87,213,.5); color:var(--accent); font-weight:600; }
  .chip:has(input:checked)::before { content:"✓"; margin-right:6px; font-size:11px; }
  .chip:has(input:focus-visible) { outline:2px solid var(--accent); outline-offset:1px; }
  .status { border-radius:10px; padding:14px 18px; margin-bottom:20px; font-size:13px; line-height:1.55; }
  .run-active { background:rgba(52,87,213,.10); border:1px solid rgba(52,87,213,.25); color:var(--fg); }
  .st-row { display:flex; align-items:center; gap:9px; font-size:13px; }
  .st-row code { font-size:12px; }
  .spin { width:13px; height:13px; border-radius:50%; flex:none;
    border:2px solid rgba(52,87,213,.30); border-top-color:var(--accent);
    animation:spin .7s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .st-prog { margin-top:8px; font-size:14px; font-weight:600; color:var(--accent);
    font-variant-numeric:tabular-nums; }
  .st-sub { margin-top:5px; font-size:11.5px; color:var(--muted); }
  .run-error { background:rgba(179,21,59,.12); color:#e0607f; white-space:pre-wrap; }
</style></head><body><div class="wrap">
  <h1>Crouching Dragon Hidden Tiger</h1>
  <div class="sub">{{count}} run(s) — newest first. Click a run to open its report.</div>
  <form class="runbar" method="post" action="/run">
    <button type="submit">▶ Run analysis</button>
    <div class="ctrl">
      <input class="num" name="generate" id="tries" type="number" value="2" min="0" max="10">
      <span class="clab" title="How many times the red team tries to breach EACH selected category (0 = built-in corpus only)">tries / category</span>
    </div>
    {{llm}}
    {{apefilter}}
  </form>
  {{status}}
  {{cards}}
</div></body></html>"""

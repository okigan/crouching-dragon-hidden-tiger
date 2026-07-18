"""Persists per-iteration traces and emits both a Markdown summary and a
self-contained HTML progress dashboard.

The dashboard is the "visual view" of the improvement loop: each iteration shows
the findings discovered, the analysis (root cause + which backend produced it),
the remediation applied, and how the open-finding count trends toward zero.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone

import yaml
from pathlib import Path

from .models import Assessment, Policy, Recommendation, RunResult

_SEV_COLOR = {
    "critical": "#b3153b",
    "high": "#d1660f",
    "medium": "#b8860b",
    "low": "#2d7d46",
    "info": "#4b6584",
}


class Reporter:
    def __init__(self, run_dir: str | Path | None = None) -> None:
        self._traces: list[dict] = []
        self.run_dir = Path(run_dir) if run_dir else None
        if self.run_dir:
            self.run_dir.mkdir(parents=True, exist_ok=True)

    def record_iteration(
        self,
        index: int,
        assessment: Assessment,
        policy: Policy,
        recommendation: Recommendation | None = None,
    ) -> None:
        rec_dict = None
        if recommendation is not None:
            rec_dict = {
                "root_cause": recommendation.root_cause,
                "source": recommendation.source,
                "latency_ms": round(recommendation.latency_ms, 1),
                "narrative": recommendation.llm_narrative,
                "addresses": sorted(recommendation.patch.addresses),
                "ops": recommendation.patch.ops,
            }
        trace = {
            "iteration": index,
            "policy_version": policy.version,
            "success_rate": round(assessment.success_rate(), 3),
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "severity": str(f.severity),
                    "resolved": f.resolved,
                    "hl_detected": f.hl_detected,
                    "openshell_blocked": f.openshell_blocked,
                    "hl_signals": list(f.hl_signals),
                    "evidence": f.evidence,
                    "references": [
                        {"source": r.source, "label": r.label,
                         "name": r.name, "url": r.url}
                        for r in f.references
                    ],
                }
                for f in assessment.findings
            ],
            "open": sorted(assessment.open_ids()),
            "remediation": rec_dict,
        }
        self._traces.append(trace)
        if self.run_dir:
            (self.run_dir / f"iteration-{index:03d}.json").write_text(
                json.dumps(trace, indent=2)
            )

    def summarize(self, run: RunResult) -> str:
        lines = [
            "# Crouching Dragon Hidden Tiger — Run",
            "",
            f"- Generated: {datetime.now(timezone.utc).isoformat()}",
            f"- Iterations: {run.iteration_count}",
            f"- Converged: {'yes' if run.converged else 'no'}",
            f"- Stop reason: {run.stop_reason}",
            f"- Enforcement: {'ON' if run.enforce else 'OFF (ablation)'}",
            f"- Exfil-success-rate: {run.initial_success:.0%} → {run.final_success:.0%} "
            f"(delta {run.success_delta:+.0%})",
        ]
        if run.final_policy:
            lines.append(f"- Final policy version: {run.final_policy.version}")
        lines += ["", "## Iterations", ""]
        lines.append("| # | patched | open before | open after | max severity |")
        lines.append("|---|---------|-------------|------------|--------------|")
        for it in run.iterations:
            patched = "yes" if it.applied_patch else "no"
            lines.append(
                f"| {it.index} | {patched} | {len(it.open_before)} "
                f"| {len(it.open_after)} | {str(it.max_severity)} |"
            )
        report = "\n".join(lines) + "\n"
        if self.run_dir:
            (self.run_dir / "summary.md").write_text(report)
            (self.run_dir / "traces.json").write_text(
                json.dumps(self._traces, indent=2)
            )
            (self.run_dir / "report.html").write_text(self.render_html(run))
        return report

    # --- HTML dashboard ---------------------------------------------------
    def render_html(self, run: RunResult) -> str:
        return _render_html(self._traces, run)


def _badge(severity: str) -> str:
    color = _SEV_COLOR.get(severity, "#4b6584")
    return (
        f'<span class="badge" style="background:{color}">'
        f"{html.escape(severity)}</span>"
    )


def _op_text(op: dict) -> str:
    kind = op.get("op", "")
    path = op.get("path", "")
    value = op.get("value", "")
    return html.escape(f"{path} → {value}  ({kind})")


def _op_summary(op: dict) -> str:
    kind, path, value = op.get("op", ""), op.get("path", ""), op.get("value", "")
    if kind in ("tool_deny",):
        return f"tools.deny += {value}"
    if kind in ("allow_add", "tool_allow"):
        return f"{path} += {value}"
    return f"{path} = {value}"


def _op_config_yaml(ops: list[dict]) -> str:
    """Render the applied policy ops as the OpenShell config fragment that was
    set — the concrete change written to the (OpenShell-compatible) policy."""
    cfg: dict = {}
    for op in ops:
        section, _, key = op.get("path", "").partition(".")
        value = op.get("value")
        node = cfg.setdefault(section, {})
        if op.get("op") == "tool_deny":
            node.setdefault(key, [])
            if value not in node[key]:
                node[key].append(value)
        else:
            node[key] = value
    return yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False).strip()


def _refs_html(refs: list[dict]) -> str:
    if not refs:
        return ""
    links = "".join(
        f'<a href="{html.escape(r["url"])}" target="_blank" rel="noopener" '
        f'class="ref ref-{r["source"].split()[0].lower()}">'
        f'{html.escape(r["source"])} {html.escape(r["label"])}</a>'
        for r in refs
    )
    return f'<div class="refs">{links}</div>'


_HL_LABEL = re.compile(r"HiddenLayer flagged \[([^\]]+)\]")


def _policy_evolution(traces: list[dict]) -> str:
    """A compact timeline of how the OpenShell policy was hardened, derived from
    the applied remediations — each step shows the finding (and, when the live
    detector ran, the HiddenLayer signal) that triggered the policy change."""
    steps = []
    for t in traces:
        rec = t.get("remediation")
        if not (rec and rec.get("ops")):
            continue
        v_before = t.get("policy_version", 1)
        change = _op_summary(rec["ops"][0])
        addr = ", ".join(rec.get("addresses", [])) or "—"
        # find the addressed finding to show its category + HiddenLayer signal
        cat, signal = "", ""
        for f in t["findings"]:
            if f["id"] in rec.get("addresses", []):
                cat = f["category"]
                m = _HL_LABEL.search(f["evidence"])
                if m:
                    signal = m.group(1)
                break
        sig_html = (
            f'<span class="hl">HiddenLayer: {html.escape(signal)}</span>'
            if signal else ""
        )
        steps.append(
            f'<li><span class="ver">v{v_before}→v{v_before + 1}</span>'
            f'<code class="chg">{html.escape(change)}</code>'
            f'<span class="trig">{html.escape(addr)} · {html.escape(cat)}</span>'
            f"{sig_html}</li>"
        )
    if not steps:
        return ""
    return (
        '<div class="evolution"><h2>OpenShell policy evolution</h2>'
        '<div class="evo-sub">permissive → hardened, one control per round, '
        "each triggered by a finding</div>"
        f'<ol class="evo">{"".join(steps)}</ol></div>'
    )


def _bypass_analysis(traces: list[dict]) -> str:
    """Two-sided bypass report from the final state: which attacks bypass
    HiddenLayer (no / few signals) and which bypass OpenShell (no capability
    control), and which layer stops each."""
    if not traces:
        return ""
    final = traces[-1]["findings"]
    base = [f for f in final if not f["id"].startswith("REG-")]
    if not base:
        return ""

    # the OpenShell op that was applied to catch each finding, across all rounds
    fix = {}
    for t in traces:
        rec = t.get("remediation")
        if rec and rec.get("ops"):
            for aid in rec.get("addresses", []):
                fix[aid] = _op_summary(rec["ops"][0])

    hl_bypass, os_bypass = [], []
    for f in base:
        fid = html.escape(f["id"])
        cat = html.escape(f["category"])
        n_sig = len(f.get("hl_signals", []))
        if not f.get("hl_detected", False):          # bypassed HiddenLayer
            change = fix.get(f["id"], "—")
            hl_bypass.append(
                f'<li><span class="gapid">{fid}</span>'
                f'<span class="gapcat">{cat}</span>'
                f'<span class="sigcount">{n_sig} HiddenLayer signals</span>'
                f'<span class="gaparrow">→ stopped by OpenShell</span>'
                f'<code class="chg">{html.escape(change)}</code></li>'
            )
        if not f.get("openshell_blocked", False):    # bypassed OpenShell
            sigs = ", ".join(f.get("hl_signals", [])) or "detected"
            os_bypass.append(
                f'<li><span class="gapid">{fid}</span>'
                f'<span class="gapcat">{cat}</span>'
                f'<span class="gaparrow">→ stopped by HiddenLayer</span>'
                f'<span class="sig">signals: {html.escape(sigs)}</span></li>'
            )

    def block(title, sub, rows):
        if not rows:
            return ""
        return (f'<div class="bypass-col"><h3>{title}</h3>'
                f'<div class="evo-sub">{sub}</div>'
                f'<ul class="gaplist">{"".join(rows)}</ul></div>')

    return (
        '<div class="gaps"><h2>Bypass analysis — what each layer misses</h2>'
        '<div class="bypass-grid">'
        + block(f"Bypassed HiddenLayer ({len(hl_bypass)})",
                "no / few signals — OpenShell is the backstop", hl_bypass)
        + block(f"Bypassed OpenShell ({len(os_bypass)})",
                "no capability control — HiddenLayer detection catches them",
                os_bypass)
        + "</div></div>"
    )


def _iteration_card(trace: dict) -> str:
    i = trace["iteration"]
    open_ids = trace["open"]
    findings = trace["findings"]
    rec = trace.get("remediation")

    finding_rows = []
    for f in findings:
        cls = "resolved" if f["resolved"] else "open"
        hl_detected = f.get("hl_detected", False)
        os_blocked = f.get("openshell_blocked", False)
        n_sig = len(f.get("hl_signals", []))
        sig_title = ", ".join(f.get("hl_signals", [])) or "no signals"
        hl_cell = (
            f'<span class="layer ok" title="{html.escape(sig_title)}">{n_sig} signals</span>'
            if hl_detected
            else '<span class="layer gap" title="no signals">0 signals</span>'
        )
        os_cell = (
            '<span class="layer ok">blocked</span>' if os_blocked
            else '<span class="layer gap">open</span>'
        )
        if not f["resolved"]:
            outcome = '<span class="state landed">LANDED</span>'
        elif hl_detected and not os_blocked:
            outcome = '<span class="state hlonly">HiddenLayer</span>'
        elif os_blocked and not hl_detected:
            outcome = '<span class="state osonly">OpenShell</span>'
        else:
            outcome = '<span class="state">both</span>'
        finding_rows.append(
            f'<tr class="{cls}"><td>{html.escape(f["id"])}</td>'
            f'<td>{html.escape(f["category"])}</td>'
            f'<td>{_badge(f["severity"])}</td>'
            f'<td>{hl_cell}</td><td>{os_cell}</td>'
            f'<td>{outcome}</td></tr>'
        )
    findings_table = (
        '<table class="findings"><thead><tr><th>ID</th><th>category</th>'
        "<th>severity</th><th>HiddenLayer</th><th>OpenShell</th>"
        "<th>stopped&nbsp;by</th></tr></thead>"
        f'<tbody>{"".join(finding_rows)}</tbody></table>'
    )

    if rec and rec.get("ops"):
        source = rec["source"]
        src_cls = "src-nemotron" if source == "nemotron" else "src-heuristic"
        latency = (
            f' · {rec["latency_ms"]:.0f} ms' if rec.get("latency_ms") else ""
        )
        ops = "".join(f"<li><code>{_op_text(o)}</code></li>" for o in rec["ops"])
        addresses = ", ".join(rec.get("addresses", [])) or "—"
        # details: the OpenShell config that was applied + real docs for the
        # HiddenLayer finding being remediated.
        addr_ids = set(rec.get("addresses", []))
        addr_refs, seen = [], set()
        for f in findings:
            if f["id"] in addr_ids:
                for r in f.get("references", []):
                    if r["url"] not in seen:
                        seen.add(r["url"])
                        addr_refs.append(r)
        cfg_yaml = html.escape(_op_config_yaml(rec["ops"]))
        refs_block = _refs_html(addr_refs)
        details = f"""
            <details class="detail" open>
              <summary>OpenShell config applied &amp; references</summary>
              <div class="detail-h">Applied to the OpenShell policy:</div>
              <pre class="cfg">{cfg_yaml}</pre>
              {"<div class='detail-h'>Finding documentation ("
               + html.escape(addresses) + "):</div>" + refs_block if refs_block else ""}
            </details>"""
        remediation = f"""
          <div class="remediation">
            <div class="rem-head">
              <span class="arrow">↳</span> Remediation
              <span class="source {src_cls}">{html.escape(source)}{latency}</span>
            </div>
            <div class="root-cause">{html.escape(rec["root_cause"])}</div>
            <div class="addresses">addresses: <b>{html.escape(addresses)}</b></div>
            <ul class="ops">{ops}</ul>
            {details}
          </div>"""
    elif rec:
        remediation = (
            '<div class="remediation none">No applicable remediation — '
            f'{html.escape(rec.get("root_cause", ""))}</div>'
        )
    else:
        remediation = (
            '<div class="remediation converged">✓ No open findings — converged</div>'
            if not open_ids
            else '<div class="remediation none">Stalled — no progress</div>'
        )

    open_count = len(open_ids)
    dot = "converged-dot" if open_count == 0 else "open-dot"
    return f"""
    <section class="iter">
      <div class="iter-head">
        <span class="dot {dot}"></span>
        <h3>Iteration {i}</h3>
        <span class="open-count">{open_count} open finding{"s" if open_count != 1 else ""}</span>
      </div>
      {findings_table}
      {remediation}
    </section>"""


def _render_html(traces: list[dict], run: RunResult) -> str:
    cards = "".join(_iteration_card(t) for t in traces)
    evolution = _policy_evolution(traces)
    gaps = _bypass_analysis(traces)
    converged = run.converged
    status_txt = "CONVERGED" if converged else "STOPPED"
    status_cls = "ok" if converged else "warn"
    final_v = run.final_policy.version if run.final_policy else "—"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    enforce_badge = (
        '<span class="enf on">enforcement ON</span>' if run.enforce
        else '<span class="enf off">enforcement OFF · ablation</span>'
    )

    # exfil-success-rate curve per round (the headline metric)
    rates = [t.get("success_rate", 0.0) for t in traces]
    bars = "".join(
        f'<div class="bar" style="height:{r * 100:.0f}%" '
        f'title="round {idx}: {r:.0%} exfil success"></div>'
        for idx, r in enumerate(rates)
    )
    delta = run.success_delta

    return f"""<title>Crouching Dragon Hidden Tiger — Run Report</title>
<style>
  :root {{
    --bg:#ffffff; --fg:#1b1f24; --muted:#5b6570; --card:#f6f8fa;
    --line:#e2e6ea; --accent:#3457d5;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#0f1216; --fg:#e6edf3; --muted:#9aa5b1; --card:#171b21;
             --line:#272d35; --accent:#6f8bff; }}
  }}
  :root[data-theme="dark"] {{ --bg:#0f1216; --fg:#e6edf3; --muted:#9aa5b1;
    --card:#171b21; --line:#272d35; --accent:#6f8bff; }}
  :root[data-theme="light"] {{ --bg:#ffffff; --fg:#1b1f24; --muted:#5b6570;
    --card:#f6f8fa; --line:#e2e6ea; --accent:#3457d5; }}
  * {{ box-sizing:border-box; }}
  body, .wrap {{ color:var(--fg); }}
  .wrap {{ max-width:900px; margin:0 auto; padding:24px 18px 60px;
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  h1 .tag {{ font-size:12px; font-weight:600; color:var(--muted); letter-spacing:.04em;
    text-transform:uppercase; vertical-align:middle; margin-left:6px; }}
  .sub {{ color:var(--muted); font-size:13px; margin-bottom:20px; }}
  .status {{ display:inline-block; font-weight:700; letter-spacing:.04em;
    padding:3px 10px; border-radius:20px; font-size:12px; }}
  .status.ok {{ background:#12321f; color:#5fdd91; }}
  .status.warn {{ background:#3a2410; color:#f0a860; }}
  .enf {{ font-size:11px; font-weight:600; padding:1px 7px; border-radius:10px; }}
  .enf.on {{ background:#12321f; color:#5fdd91; }}
  .enf.off {{ background:#3a1418; color:#f0808f; }}
  .delta {{ color:#2fbd6b; }}
  .summary {{ display:flex; gap:22px; flex-wrap:wrap; align-items:flex-end;
    background:var(--card); border:1px solid var(--line); border-radius:12px;
    padding:16px 18px; margin-bottom:26px; }}
  .metric {{ display:flex; flex-direction:column; }}
  .metric b {{ font-size:20px; }}
  .metric span {{ color:var(--muted); font-size:12px; }}
  .trend {{ margin-left:auto; display:flex; align-items:flex-end; gap:4px;
    height:48px; }}
  .trend .bar {{ width:14px; background:var(--accent); border-radius:3px 3px 0 0;
    min-height:3px; opacity:.85; }}
  .evolution {{ border:1px solid var(--line); border-radius:12px; padding:14px 18px;
    margin-bottom:26px; background:var(--card); }}
  .evolution h2 {{ font-size:15px; margin:0 0 2px; }}
  .evo-sub {{ color:var(--muted); font-size:12px; margin-bottom:10px; }}
  ol.evo {{ list-style:none; margin:0; padding:0; }}
  ol.evo li {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap;
    padding:6px 0; border-bottom:1px solid var(--line); font-size:13px; }}
  ol.evo li:last-child {{ border-bottom:0; }}
  .evo .ver {{ font-variant-numeric:tabular-nums; color:var(--muted);
    min-width:64px; font-weight:600; }}
  .evo .chg {{ background:rgba(47,189,107,.12); color:#2fbd6b; padding:1px 7px;
    border-radius:5px; font-size:12px; }}
  .evo .trig {{ color:var(--muted); }}
  .gaps {{ border:1px solid #d1660f55; border-radius:12px; padding:14px 18px;
    margin-bottom:26px; background:rgba(209,102,15,.06); }}
  .gaps h2 {{ font-size:15px; margin:0 0 2px; }}
  ul.gaplist {{ list-style:none; margin:0; padding:0; }}
  ul.gaplist li {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap;
    padding:6px 0; border-bottom:1px solid var(--line); font-size:13px; }}
  ul.gaplist li:last-child {{ border-bottom:0; }}
  .gapid {{ font-weight:600; min-width:64px; }}
  .gapcat {{ color:var(--muted); }}
  .gaparrow {{ color:#d1660f; font-weight:600; }}
  .bypass-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
  @media (max-width:640px) {{ .bypass-grid {{ grid-template-columns:1fr; }} }}
  .bypass-col h3 {{ font-size:13px; margin:0 0 2px; }}
  .sigcount {{ font-size:11px; font-weight:600; padding:1px 7px; border-radius:9px;
    background:rgba(209,102,15,.15); color:#d1660f; }}
  .sig {{ font-size:11px; color:var(--muted); }}
  .layer {{ font-size:11px; font-weight:600; padding:1px 7px; border-radius:9px; }}
  .layer.ok {{ background:rgba(47,189,107,.15); color:#2fbd6b; }}
  .layer.gap {{ background:rgba(209,102,15,.15); color:#d1660f; }}
  .state.landed {{ color:#b3153b; }}
  .state.hlonly {{ color:#2fbd6b; }}
  .state.osonly {{ color:var(--accent); }}
  .evo .hl {{ margin-left:auto; font-size:11px; font-weight:600; padding:1px 8px;
    border-radius:10px; background:#3a1418; color:#f0808f; }}
  .iter {{ border:1px solid var(--line); border-radius:12px; padding:14px 16px;
    margin-bottom:16px; background:var(--card); }}
  .iter-head {{ display:flex; align-items:center; gap:10px; margin-bottom:10px; }}
  .iter-head h3 {{ margin:0; font-size:16px; }}
  .open-count {{ margin-left:auto; color:var(--muted); font-size:13px; }}
  .dot {{ width:10px; height:10px; border-radius:50%; display:inline-block; }}
  .open-dot {{ background:#d1660f; }}
  .converged-dot {{ background:#2fbd6b; }}
  table.findings {{ width:100%; border-collapse:collapse; font-size:13px;
    margin-bottom:10px; }}
  .findings th {{ text-align:left; color:var(--muted); font-weight:600;
    border-bottom:1px solid var(--line); padding:4px 8px; }}
  .findings td {{ padding:5px 8px; border-bottom:1px solid var(--line);
    vertical-align:top; }}
  .findings tr.resolved td {{ opacity:.5; }}
  .findings .state {{ font-weight:700; font-size:11px; }}
  .findings tr.open .state {{ color:#e0733a; }}
  .findings .ev {{ color:var(--muted); }}
  .badge {{ color:#fff; padding:1px 8px; border-radius:10px; font-size:11px;
    font-weight:600; text-transform:uppercase; }}
  .remediation {{ border-left:3px solid var(--accent); padding:8px 12px;
    background:rgba(52,87,213,.06); border-radius:0 8px 8px 0; }}
  .remediation.converged {{ border-color:#2fbd6b; background:rgba(47,189,107,.08);
    font-weight:600; }}
  .remediation.none {{ border-color:#b8860b; background:rgba(184,134,11,.08);
    color:var(--muted); }}
  .rem-head {{ font-weight:600; margin-bottom:4px; display:flex; gap:8px;
    align-items:center; }}
  .arrow {{ color:var(--accent); }}
  .source {{ font-size:11px; padding:1px 8px; border-radius:10px; font-weight:600; }}
  .src-nemotron {{ background:#1c3a5e; color:#8fc0ff; }}
  .src-heuristic {{ background:#2a2f36; color:#b7c0cc; }}
  .root-cause {{ margin:2px 0; }}
  .addresses {{ font-size:12px; color:var(--muted); margin-bottom:4px; }}
  ul.ops {{ margin:4px 0 0; padding-left:18px; }}
  ul.ops code {{ font-size:12px; }}
  .detail {{ margin-top:8px; }}
  .detail summary {{ cursor:pointer; font-size:12px; font-weight:600;
    color:var(--muted); }}
  .detail-h {{ font-size:11px; color:var(--muted); margin:8px 0 3px;
    text-transform:uppercase; letter-spacing:.03em; }}
  pre.cfg {{ margin:0; padding:8px 10px; background:rgba(128,128,128,.12);
    border-radius:6px; font-size:12px; overflow-x:auto;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .refs {{ display:flex; flex-wrap:wrap; gap:6px; }}
  .refs .ref {{ font-size:11px; font-weight:600; padding:2px 8px; border-radius:10px;
    text-decoration:none; border:1px solid var(--line); }}
  .ref-owasp {{ background:rgba(209,102,15,.12); color:#d1660f; }}
  .ref-mitre {{ background:rgba(52,87,213,.12); color:var(--accent); }}
  .ref-hiddenlayer {{ background:#3a1418; color:#f0808f; }}
  .ref-ape {{ background:rgba(111,139,255,.14); color:#6f8bff; }}
  .attribution {{ margin-top:26px; padding-top:14px; border-top:1px solid var(--line);
    color:var(--muted); font-size:11px; line-height:1.6; }}
  .attribution a {{ color:var(--muted); }}
  code {{ background:rgba(128,128,128,.15); padding:1px 5px; border-radius:5px; }}
</style>
<div class="wrap">
  <h1>Crouching Dragon Hidden Tiger <span class="tag">Run Report</span></h1>
  <div class="sub">Generated {generated}</div>
  <div class="summary">
    <div class="metric"><b><span class="status {status_cls}">{status_txt}</span></b>
      <span>{enforce_badge}</span></div>
    <div class="metric"><b>{run.initial_success:.0%} → {run.final_success:.0%}</b>
      <span>exfil-success-rate</span></div>
    <div class="metric"><b class="delta">{delta:+.0%}</b><span>Δ recursive-intel</span></div>
    <div class="metric"><b>{run.iteration_count}</b><span>rounds</span></div>
    <div class="metric"><b>v{final_v}</b><span>final policy</span></div>
    <div class="trend" title="exfil-success-rate per round">{bars}</div>
  </div>
  {gaps}
  {evolution}
  {cards}
  <div class="attribution">
    Attacks classified with the <a href="https://ape.hiddenlayer.com/"
    target="_blank" rel="noopener">HiddenLayer APE Taxonomy</a> (technique + objective,
    © HiddenLayer, CC BY-ND 4.0). Detection signals and OWASP / MITRE ATLAS
    mappings from the live HiddenLayer prompt analyzer. OpenShell controls map to
    OpenShell's documented sandboxing surfaces.
  </div>
</div>"""

"""Persists per-iteration traces and emits both a Markdown summary and a
self-contained HTML progress dashboard.

The dashboard is the "visual view" of the improvement loop: each iteration shows
the findings discovered, the analysis (root cause + which backend produced it),
the remediation applied, and how the open-finding count trends toward zero.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
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
                    "evidence": f.evidence,
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


def _iteration_card(trace: dict) -> str:
    i = trace["iteration"]
    open_ids = trace["open"]
    findings = trace["findings"]
    rec = trace.get("remediation")

    finding_rows = []
    for f in findings:
        state = "defended" if f["resolved"] else "OPEN"
        cls = "resolved" if f["resolved"] else "open"
        finding_rows.append(
            f'<tr class="{cls}"><td>{html.escape(f["id"])}</td>'
            f'<td>{html.escape(f["category"])}</td>'
            f'<td>{_badge(f["severity"])}</td>'
            f'<td class="state">{state}</td>'
            f'<td class="ev">{html.escape(f["evidence"])}</td></tr>'
        )
    findings_table = (
        '<table class="findings"><thead><tr><th>ID</th><th>category</th>'
        "<th>severity</th><th>state</th><th>evidence</th></tr></thead>"
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
        remediation = f"""
          <div class="remediation">
            <div class="rem-head">
              <span class="arrow">↳</span> Remediation
              <span class="source {src_cls}">{html.escape(source)}{latency}</span>
            </div>
            <div class="root-cause">{html.escape(rec["root_cause"])}</div>
            <div class="addresses">addresses: <b>{html.escape(addresses)}</b></div>
            <ul class="ops">{ops}</ul>
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
  {cards}
</div>"""

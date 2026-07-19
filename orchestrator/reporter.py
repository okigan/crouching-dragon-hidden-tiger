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
        self._generation: list[dict] = []
        self.run_dir = Path(run_dir) if run_dir else None
        if self.run_dir:
            self.run_dir.mkdir(parents=True, exist_ok=True)

    def set_generation_log(self, attempts: list[dict]) -> None:
        """Record the red team's full generation attempt log (every try + outcome,
        including the ones the content layer stopped) for the report."""
        self._generation = attempts or []

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
                    "payload": f.attack_vector,
                    "resolved": f.resolved,
                    "hl_detected": f.hl_detected,
                    "openshell_blocked": f.openshell_blocked,
                    "openshell_observed": f.openshell_observed,
                    "egress_host": f.egress_host,
                    "ape_technique": f.ape_technique,
                    "ape_objective": f.ape_objective,
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
            f"- Attack-success-rate: {run.initial_success:.0%} → {run.final_success:.0%} "
            f"(delta {run.success_delta:+.0%})",
        ]
        if run.llm_model:
            lines.append(f"- LLM: {run.llm_model}")
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
            attacks = _attacks_export(self._traces)
            (self.run_dir / "attacks.json").write_text(json.dumps(attacks, indent=2))
            (self.run_dir / "attacks.md").write_text(_attacks_markdown(attacks))
            if self._generation:
                (self.run_dir / "generation.json").write_text(
                    json.dumps(self._generation, indent=2))
        return report

    # --- HTML dashboard ---------------------------------------------------
    def render_html(self, run: RunResult) -> str:
        return _render_html(self._traces, run, self._generation)


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


def _attacks_export(traces: list[dict]) -> list[dict]:
    """Every attack prompt with its final two-layer outcome, for attacks.json —
    so the exact bypassing prompts are inspectable outside the HTML."""
    if not traces:
        return []
    out = []
    for f in traces[-1]["findings"]:
        hl = f.get("hl_detected", False)
        os_ = f.get("openshell_blocked", False)
        out.append({
            "id": f["id"],
            "category": f["category"],
            "severity": f["severity"],
            "prompt": f.get("payload", ""),
            "hl_signals": f.get("hl_signals", []),
            "bypassed_hiddenlayer": not hl,
            "bypassed_openshell": not os_,
            "stopped_by": ("HiddenLayer" if hl and not os_
                           else "OpenShell" if os_ and not hl
                           else "both" if hl and os_ else "none (LANDED)"),
            "references": [r["url"] for r in f.get("references", [])],
        })
    return out


def _attacks_markdown(attacks: list[dict]) -> str:
    lines = ["# Attack prompts and bypass outcomes", ""]
    for a in attacks:
        lines += [
            f"## {a['id']} — {a['category']} ({a['severity']})",
            f"- Bypassed HiddenLayer: **{a['bypassed_hiddenlayer']}** "
            f"(signals: {', '.join(a['hl_signals']) or 'none'})",
            f"- Bypassed OpenShell: **{a['bypassed_openshell']}**",
            f"- Stopped by: **{a['stopped_by']}**",
            "",
            "> " + a["prompt"].replace("\n", "\n> "),
            "",
        ]
    return "\n".join(lines)


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
        obs = (' <span class="obs" title="observed live inside the OpenShell '
               'sandbox">obs</span>' if f.get("openshell_observed") else "")
        # content-only objectives (hallucination, bias, system-prompt exposure)
        # have no OpenShell runtime control — HiddenLayer is the only layer that
        # can defend them, so OpenShell is honestly N/A rather than "bypassed".
        content_only = f.get("category") == "content_only"
        if content_only:
            os_cell = ('<span class="layer na" title="no OpenShell runtime '
                       'control for this content-layer objective">n/a</span>')
        else:
            os_cell = (
                f'<span class="layer ok">blocked{obs}</span>' if os_blocked
                else f'<span class="layer gap">open{obs}</span>'
            )
        if not f["resolved"] and content_only:
            outcome = ('<span class="state contentgap" title="content-layer '
                       'attack HiddenLayer did not flag; OpenShell cannot enforce '
                       'it">content-layer</span>')
        elif not f["resolved"]:
            outcome = '<span class="state landed">LANDED</span>'
        elif hl_detected and not os_blocked:
            outcome = '<span class="state hlonly">HiddenLayer</span>'
        elif os_blocked and not hl_detected:
            outcome = '<span class="state osonly">OpenShell</span>'
        else:
            outcome = '<span class="state">both</span>'
        tech, obj = f.get("ape_technique", ""), f.get("ape_objective", "")
        ape_tag = (f'<span class="apetag" title="APE technique {html.escape(tech)}'
                   f' × objective {html.escape(obj)}">{html.escape(tech)}'
                   f'{" · " + html.escape(obj) if obj else ""}</span>' if tech else "")
        cat_cell = f'{html.escape(f["category"])}{ape_tag}'
        finding_rows.append(
            f'<tr class="{cls}"><td>{html.escape(f["id"])}</td>'
            f'<td>{cat_cell}</td>'
            f'<td>{_badge(f["severity"])}</td>'
            f'<td>{hl_cell}</td><td>{os_cell}</td>'
            f'<td>{outcome}</td></tr>'
        )
        # the executed prompt for this attack, shown under its row
        prompt = f.get("payload", "")
        if prompt:
            finding_rows.append(
                f'<tr class="promptrow {cls}"><td></td>'
                f'<td colspan="5"><span class="attack-prompt">'
                f'{html.escape(prompt)}</span></td></tr>'
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


_GEN_OUTCOME = {
    "evaded": ("evaded → tested on OpenShell", "ok"),
    "caught": ("caught by HiddenLayer (content layer)", "hl"),
    "refused": ("model refused", "muted"),
    "duplicate": ("duplicate of an earlier try", "muted"),
}


def _generation_coverage(generation: list[dict]) -> str:
    """Panel showing the FULL red-team generation log — every try and its
    outcome, including the ones HiddenLayer stopped at screening (which never
    reach the corpus/iterations, so they'd otherwise be invisible)."""
    if not generation:
        return ""
    from collections import Counter
    tally = Counter(a.get("outcome", "") for a in generation)
    total = len(generation)
    chips = "".join(
        f'<span class="gcstat gc-{cls}">{tally.get(k, 0)} {html.escape(lbl)}</span>'
        for k, (lbl, cls) in _GEN_OUTCOME.items() if tally.get(k)
    )
    rows = []
    for a in generation:
        lbl, cls = _GEN_OUTCOME.get(a.get("outcome", ""),
                                    (a.get("outcome", "?"), "muted"))
        tech, obj = a.get("ape_technique", ""), a.get("ape_objective", "")
        aid = a.get("id") or "—"
        rows.append(
            f'<tr><td>{html.escape(aid)}</td>'
            f'<td>{html.escape(a.get("category", ""))}'
            f'<span class="apetag">{html.escape(tech)}'
            f'{" · " + html.escape(obj) if obj else ""}</span></td>'
            f'<td><span class="gco gco-{cls}">{html.escape(lbl)}</span></td>'
            f'<td><span class="attack-prompt">{html.escape(a.get("payload", ""))}'
            f'</span></td></tr>'
        )
    return (
        '<div class="gencov"><h2>Red-team generation — every try &amp; its outcome</h2>'
        f'<div class="evo-sub">The red team made <b>{total}</b> generation attempts '
        'across the selected categories. Attempts <b>caught by HiddenLayer</b> or '
        'refused never reach the corpus below — this is the full coverage, including '
        f'what the content layer already stopped.</div>'
        f'<div class="gcstats">{chips}</div>'
        '<table class="findings"><thead><tr><th>id</th><th>category</th>'
        '<th>outcome</th><th>prompt</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div>'
    )


def _render_html(traces: list[dict], run: RunResult,
                 generation: list[dict] | None = None) -> str:
    cards = "".join(_iteration_card(t) for t in traces)
    evolution = _policy_evolution(traces)
    gencov = _generation_coverage(generation or [])
    converged = run.converged
    status_txt = "CONVERGED" if converged else "STOPPED"
    status_cls = "ok" if converged else "warn"
    final_v = run.final_policy.version if run.final_policy else "—"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    llm_line = f" · LLM: {run.llm_model}" if run.llm_model else ""
    enforce_badge = (
        '<span class="enf on">enforcement ON</span>' if run.enforce
        else '<span class="enf off">enforcement OFF · ablation</span>'
    )

    # "% defended per round", stacked by which layer caught each attack (higher
    # is better). HiddenLayer (content) catches some; OpenShell (capability)
    # catches what HiddenLayer missed; the rest LANDED. The three sum to 100%.
    bars = []
    for idx, t in enumerate(traces):
        fs = t["findings"]
        n = len(fs) or 1
        hl = sum(1 for f in fs if f.get("hl_detected"))
        os_ = sum(1 for f in fs if f.get("openshell_blocked") and not f.get("hl_detected"))
        landed = sum(1 for f in fs if not f.get("resolved"))
        defended = round((hl + os_) / n * 100)
        bars.append(
            f'<div class="scol" title="round {idx}: {defended}% defended '
            f'({hl} HiddenLayer, {os_} OpenShell, {landed} landed of {len(fs)})">'
            f'<div class="seg landed" style="height:{landed / n * 100:.1f}%"></div>'
            f'<div class="seg os" style="height:{os_ / n * 100:.1f}%"></div>'
            f'<div class="seg hl" style="height:{hl / n * 100:.1f}%"></div>'
            f'<div class="scol-x">{idx}</div></div>'
        )
    bars = "".join(bars)
    # defense-in-depth split (final round): which layer stopped each attack
    final = traces[-1]["findings"] if traces else []
    base_final = [f for f in final if not f["id"].startswith("REG-")]
    os_stops = sum(1 for f in base_final
                   if f.get("openshell_blocked") and not f.get("hl_detected"))
    hl_stops = sum(1 for f in base_final if f.get("hl_detected"))
    initial_def = 1 - run.initial_success
    final_def = 1 - run.final_success

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
  .delta {{ color:#0f9d74; }}
  .summary {{ display:flex; gap:22px; flex-wrap:wrap; align-items:flex-end;
    background:var(--card); border:1px solid var(--line); border-radius:12px;
    padding:16px 18px; margin-bottom:26px; }}
  .metric {{ display:flex; flex-direction:column; }}
  .metric b {{ font-size:20px; }}
  .metric span {{ color:var(--muted); font-size:12px; }}
  .chart {{ margin-left:auto; display:flex; flex-direction:column; gap:6px; }}
  .trend {{ display:flex; align-items:flex-end; gap:5px; height:60px; }}
  .scol {{ position:relative; width:16px; height:100%; display:flex;
    flex-direction:column; justify-content:flex-end; border-radius:3px;
    overflow:hidden; background:rgba(128,128,128,.10); }}
  .seg {{ width:100%; }}
  .seg.hl {{ background:#0f9d74; }}
  .seg.os {{ background:#3b5bde; }}
  .seg.landed {{ background:#e0576b; }}
  .scol-x {{ position:absolute; bottom:-16px; left:0; right:0; text-align:center;
    font-size:9px; color:var(--muted); }}
  .legend {{ display:flex; align-items:center; gap:10px; margin-top:14px;
    font-size:11px; color:var(--muted); }}
  .legend .lg {{ display:inline-flex; align-items:center; gap:4px; }}
  .legend .sw {{ width:9px; height:9px; border-radius:2px; display:inline-block; }}
  .legend .sw.hl {{ background:#0f9d74; }}
  .legend .sw.os {{ background:#3b5bde; }}
  .legend .sw.landed {{ background:#e0576b; }}
  .legend .cap {{ margin-left:auto; font-weight:600; }}
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
  .evo .chg {{ background:rgba(47,189,107,.12); color:#0f9d74; padding:1px 7px;
    border-radius:5px; font-size:12px; }}
  .evo .trig {{ color:var(--muted); }}
  blockquote.prompt {{ margin:6px 0 0; padding:5px 10px; border-left:3px solid var(--line);
    color:var(--muted); font-size:12px; font-style:italic;
    background:rgba(128,128,128,.06); border-radius:0 6px 6px 0;
    overflow-wrap:anywhere; }}
  .layer {{ font-size:11px; font-weight:600; padding:1px 7px; border-radius:9px; }}
  .layer.ok {{ background:rgba(47,189,107,.15); color:#0f9d74; }}
  .layer.gap {{ background:rgba(209,102,15,.15); color:#d1660f; }}
  .obs {{ font-size:9px; font-weight:700; text-transform:uppercase; letter-spacing:.04em;
    padding:0 4px; border-radius:5px; background:var(--accent); color:#fff; vertical-align:middle; }}
  .state.landed {{ color:#b3153b; }}
  .state.contentgap {{ color:#8a6d3b; }}
  .layer.na {{ background:rgba(120,130,145,.14); color:var(--muted); }}
  .state.hlonly {{ color:#0f9d74; }}
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
  .converged-dot {{ background:#0f9d74; }}
  table.findings {{ width:100%; border-collapse:collapse; font-size:13px;
    margin-bottom:10px; }}
  .findings th {{ text-align:left; color:var(--muted); font-weight:600;
    border-bottom:1px solid var(--line); padding:4px 8px; }}
  .findings td {{ padding:5px 8px; border-bottom:1px solid var(--line);
    vertical-align:top; }}
  .findings tr.resolved td {{ opacity:.5; }}
  .findings tr.promptrow td {{ border-bottom:1px solid var(--line); padding-top:0;
    padding-bottom:8px; }}
  .attack-prompt {{ color:var(--muted); font-size:12px; font-style:italic;
    overflow-wrap:anywhere; }}
  .attack-prompt::before {{ content:"↳ prompt: "; font-style:normal; opacity:.7; }}
  .gencov {{ margin-bottom:26px; }}
  .gencov h2 {{ font-size:15px; margin:0 0 2px; }}
  .gcstats {{ display:flex; gap:8px; flex-wrap:wrap; margin:12px 0 14px; }}
  .gcstat {{ font-size:11px; font-weight:600; padding:3px 9px; border-radius:20px;
    background:rgba(120,130,145,.12); color:var(--muted); }}
  .gcstat.gc-ok {{ background:rgba(47,189,107,.15); color:#0f9d74; }}
  .gcstat.gc-hl {{ background:rgba(209,102,15,.15); color:#d1660f; }}
  .gco {{ font-size:11px; font-weight:600; }}
  .gco-ok {{ color:#0f9d74; }} .gco-hl {{ color:#d1660f; }} .gco-muted {{ color:var(--muted); }}
  .apetag {{ display:inline-block; margin-left:7px; font-size:10px; font-weight:600;
    color:var(--muted); background:rgba(120,130,145,.12); padding:1px 6px;
    border-radius:5px; font-variant-numeric:tabular-nums; letter-spacing:.02em; }}
  .findings .state {{ font-weight:700; font-size:11px; }}
  .findings tr.open .state {{ color:#e0733a; }}
  .findings .ev {{ color:var(--muted); }}
  .badge {{ color:#fff; padding:1px 8px; border-radius:10px; font-size:11px;
    font-weight:600; text-transform:uppercase; }}
  .remediation {{ border-left:3px solid var(--accent); padding:8px 12px;
    background:rgba(52,87,213,.06); border-radius:0 8px 8px 0; }}
  .remediation.converged {{ border-color:#0f9d74; background:rgba(47,189,107,.08);
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
  <div class="sub">Generated {generated}{llm_line}</div>
  <div class="summary">
    <div class="metric"><b><span class="status {status_cls}">{status_txt}</span></b>
      <span>{enforce_badge}</span></div>
    <div class="metric"><b>{initial_def:.0%} → {final_def:.0%}</b>
      <span>attacks defended</span></div>
    <div class="metric"><b>{hl_stops} / {os_stops}</b>
      <span>caught by HiddenLayer / OpenShell</span></div>
    <div class="metric"><b>{run.iteration_count}</b><span>rounds</span></div>
    <div class="metric"><b>v{final_v}</b><span>final policy</span></div>
    <div class="chart">
      <div class="trend">{bars}</div>
      <div class="legend">
        <span class="lg"><i class="sw hl"></i>HiddenLayer</span>
        <span class="lg"><i class="sw os"></i>OpenShell</span>
        <span class="lg"><i class="sw landed"></i>landed</span>
        <span class="cap">% defended per round ↑</span>
      </div>
    </div>
  </div>
  {gencov}
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

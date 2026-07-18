"""Persists per-iteration traces and emits a Markdown run summary."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Assessment, Policy, RunResult


class Reporter:
    def __init__(self, run_dir: str | Path | None = None) -> None:
        self._traces: list[dict] = []
        self.run_dir = Path(run_dir) if run_dir else None
        if self.run_dir:
            self.run_dir.mkdir(parents=True, exist_ok=True)

    def record_iteration(
        self, index: int, assessment: Assessment, policy: Policy
    ) -> None:
        trace = {
            "iteration": index,
            "policy_version": policy.version,
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
        }
        self._traces.append(trace)
        if self.run_dir:
            (self.run_dir / f"iteration-{index:03d}.json").write_text(
                json.dumps(trace, indent=2)
            )

    def summarize(self, run: RunResult) -> str:
        lines = [
            "# Security Validation Run",
            "",
            f"- Generated: {datetime.now(timezone.utc).isoformat()}",
            f"- Iterations: {run.iteration_count}",
            f"- Converged: {'yes' if run.converged else 'no'}",
            f"- Stop reason: {run.stop_reason}",
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
        return report

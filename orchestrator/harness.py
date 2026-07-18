"""Recursive-delta harness (redblue-arena Phase 6).

Runs the improvement loop twice from the same starting policy — enforcement ON
and OFF — and reports the exfil-success-rate delta of each. The ablation is the
control: with enforcement OFF, blue still learns and patches, but the guard
never takes effect, so the success rate stays flat. Only the enforced run drives
the rate to zero — that difference is the "recursive intelligence" signal.
"""

from __future__ import annotations

from pathlib import Path

from .config import Settings
from .loop import LoopConfig, SecurityOrchestrator
from .models import RunResult
from .policy_store import PolicyStore
from .reporter import Reporter


def _run_once(settings: Settings, policy: str, agent: str, max_iters: int,
              enforce: bool, out_dir: Path | None) -> RunResult:
    store = PolicyStore.load(policy)
    reporter = Reporter(run_dir=out_dir)
    orch = SecurityOrchestrator(
        sandbox=settings.build_sandbox(),
        assessor=settings.build_assessor(),
        llm=settings.build_llm(),
        store=store,
        reporter=reporter,
        config=LoopConfig(agent=agent, max_iters=max_iters, enforce=enforce),
    )
    result = orch.run()
    if out_dir is not None:
        reporter.summarize(result)
    return result


def run_ablation(settings: Settings, policy: str, *, agent: str = "target-agent",
                 max_iters: int = 10, out: str | None = None) -> str:
    base = Path(out) if out else None
    enforced = _run_once(settings, policy, agent, max_iters, True,
                         base / "enforced" if base else None)
    ablated = _run_once(settings, policy, agent, max_iters, False,
                        base / "ablated" if base else None)
    return _format(enforced, ablated, base)


def _format(enforced: RunResult, ablated: RunResult, base: Path | None) -> str:
    lines = [
        "# Recursive-Intelligence Ablation",
        "",
        "| enforcement | rounds | exfil-success start → end | delta | converged |",
        "|-------------|--------|---------------------------|-------|-----------|",
        f"| ON  | {enforced.iteration_count} | "
        f"{enforced.initial_success:.0%} → {enforced.final_success:.0%} | "
        f"{enforced.success_delta:+.0%} | {'yes' if enforced.converged else 'no'} |",
        f"| OFF | {ablated.iteration_count} | "
        f"{ablated.initial_success:.0%} → {ablated.final_success:.0%} | "
        f"{ablated.success_delta:+.0%} | {'yes' if ablated.converged else 'no'} |",
        "",
        f"**Recursive-intelligence delta = {enforced.success_delta - ablated.success_delta:+.0%}** "
        "(enforced improvement over the ablation control).",
    ]
    if base is not None:
        lines.append("")
        lines.append(f"Reports: {base/'enforced'/'report.html'} · "
                     f"{base/'ablated'/'report.html'}")
    return "\n".join(lines) + "\n"

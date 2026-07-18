"""CLI:
    python -m orchestrator run    [--policy ...] [--enforce/--no-enforce]
    python -m orchestrator ablate [--policy ...]   # enforcement on vs off
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Settings
from .harness import run_ablation
from .loop import LoopConfig, SecurityOrchestrator
from .policy_store import PolicyStore
from .reporter import Reporter


def _build(settings: Settings, policy: str, agent: str, max_iters: int,
           enforce: bool, out: str | None) -> tuple[SecurityOrchestrator, PolicyStore, Reporter]:
    store = PolicyStore.load(policy)
    reporter = Reporter(run_dir=out)
    orch = SecurityOrchestrator(
        sandbox=settings.build_sandbox(),
        assessor=settings.build_assessor(),
        llm=settings.build_llm(),
        store=store,
        reporter=reporter,
        config=LoopConfig(agent=agent, max_iters=max_iters, enforce=enforce),
    )
    return orch, store, reporter


def _run(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    enforce = args.enforce if args.enforce is not None else settings.enforce
    orch, store, reporter = _build(
        settings, args.policy, args.agent, args.max_iters, enforce, args.out
    )
    result = orch.run()
    print(reporter.summarize(result))
    print(f"backends: sandbox={settings.sandbox} assessor={settings.assessor} "
          f"llm={settings.llm} · enforce={enforce}")
    if args.out:
        print(f"visual report: {Path(args.out) / 'report.html'}")
    if args.save_policy:
        store.save(args.save_policy)
        print(f"hardened policy written to {args.save_policy}")
    return 0 if result.converged else 1


def _ablate(args: argparse.Namespace) -> int:
    """Recursive-Intelligence proof: run the loop with enforcement ON and OFF
    from the same starting policy and report the exfil-success-rate delta."""
    settings = Settings.from_env()
    report = run_ablation(
        settings, args.policy, agent=args.agent, max_iters=args.max_iters,
        out=args.out,
    )
    print(report)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="orchestrator")
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run the security improvement loop")
    run.add_argument("--policy", default="policies/permissive.yaml",
                     help="starting policy (default: permissive)")
    run.add_argument("--agent", default="target-agent")
    run.add_argument("--max-iters", type=int, default=10)
    run.add_argument("--out", default="runs/latest",
                     help="dir for traces + summary + report.html")
    run.add_argument("--save-policy", default=None, help="write hardened policy")
    enf = run.add_mutually_exclusive_group()
    enf.add_argument("--enforce", dest="enforce", action="store_true", default=None,
                     help="OpenShell enforces the policy (default)")
    enf.add_argument("--no-enforce", dest="enforce", action="store_false",
                     help="ablation: disable enforcement, attacks always land")
    run.set_defaults(func=_run)

    ab = sub.add_parser("ablate", help="run enforcement ON vs OFF and report delta")
    ab.add_argument("--policy", default="policies/permissive.yaml")
    ab.add_argument("--agent", default="target-agent")
    ab.add_argument("--max-iters", type=int, default=10)
    ab.add_argument("--out", default="runs/ablation",
                    help="dir for both run reports")
    ab.set_defaults(func=_ablate)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

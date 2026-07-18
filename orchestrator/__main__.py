"""CLI: `python -m orchestrator run --policy policies/baseline.yaml`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Settings
from .loop import LoopConfig, SecurityOrchestrator
from .policy_store import PolicyStore
from .reporter import Reporter


def _run(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    store = PolicyStore.load(args.policy)
    reporter = Reporter(run_dir=args.out)
    orch = SecurityOrchestrator(
        sandbox=settings.build_sandbox(),
        assessor=settings.build_assessor(),
        llm=settings.build_llm(),
        store=store,
        reporter=reporter,
        config=LoopConfig(agent=args.agent, max_iters=args.max_iters),
    )
    result = orch.run()
    print(reporter.summarize(result))
    if args.save_policy:
        store.save(args.save_policy)
        print(f"hardened policy written to {args.save_policy}")
    # Exit non-zero if we could not converge (useful as a CI gate).
    return 0 if result.converged else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="orchestrator")
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run the security improvement loop")
    run.add_argument("--policy", default="policies/baseline.yaml")
    run.add_argument("--agent", default="target-agent")
    run.add_argument("--max-iters", type=int, default=10)
    run.add_argument("--out", default=None, help="dir for traces + summary")
    run.add_argument("--save-policy", default=None, help="write hardened policy")
    run.set_defaults(func=_run)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""CLI:
    python -m orchestrator run    [--policy ...] [--enforce/--no-enforce]
    python -m orchestrator ablate [--policy ...]   # enforcement on vs off
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .backends import real
from .config import Settings
from .harness import run_ablation
from .loop import LoopConfig, SecurityOrchestrator
from .policy_store import PolicyStore
from .reporter import Reporter


def _run(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    enforce = args.enforce if args.enforce is not None else settings.enforce
    store = PolicyStore.load(args.policy)
    reporter = Reporter(run_dir=args.out)
    sandbox = settings.build_sandbox()
    assessor = settings.build_assessor()
    # Observed enforcement: if the sandbox can probe egress and the assessor can
    # use it, wire them so egress attacks are tested live instead of modeled.
    if hasattr(sandbox, "egress_probe") and hasattr(assessor, "set_prober"):
        assessor.set_prober(sandbox.egress_probe)

    # Dynamic red team: generate candidate attacks from APE techniques, screen
    # them against the detector, and add the evaders to the corpus.
    redteam = None
    if args.generate:
        from .backends.corpus import DEFAULT_CORPUS
        from .generator import generate_attacks, generate_coverage, taxonomy_specs
        gen = settings.build_generator()
        # Coverage filters (empty = all): restrict the pool to chosen APE tactics
        # and/or attack categories.
        tac = {t.strip() for t in args.tactics.split(",") if t.strip()}
        cat = {c.strip() for c in args.categories.split(",") if c.strip()}
        specs = taxonomy_specs(tactics=tac or None, categories=cat or None)
        n_cats = len({s.category for s in specs})
        scope = (f"full sweep of {len(specs)} specs" if args.full_taxonomy
                 else f"{n_cats} categories × {args.generate} tries")
        print(f"APE coverage → tactics: {', '.join(sorted(tac)) or 'all'} · "
              f"categories: {', '.join(sorted(cat)) or 'all'} ({scope})")
        # Feed the generator prompts already known to slip past the content
        # detector (the corpus's hl_detects=False cases) so new candidates build
        # on styles that evade HiddenLayer rather than starting from scratch.
        evasions = tuple(
            c.payload for c in DEFAULT_CORPUS if not c.hl_detects
        )[:4]
        # Give the red team `--generate` tries to breach EACH selected category
        # (or, with --full-taxonomy, sweep every spec once); capture the full
        # attempt log (incl. the tries HiddenLayer stopped).
        gen_log: list[dict] = []
        new = generate_coverage(
            gen, assessor.detect, args.generate, specs, evasions=evasions,
            attempts_out=gen_log, exhaustive=args.full_taxonomy,
        )
        assessor.add_tests(new)
        reporter.set_generation_log(gen_log)
        caught = sum(1 for a in gen_log if a["outcome"] == "caught")
        errors = sum(1 for a in gen_log if a["outcome"] == "error")
        print(f"probed {scope} ({len(gen_log)} attempts) → {len(new)} evaded "
              f"to OpenShell, {caught} caught by HiddenLayer, "
              f"{errors} endpoint error(s): "
              f"{', '.join(c.id for c in new) or 'none'}")
        if errors and not new:
            err = getattr(gen, "last_error", "") or "no model output"
            print(f"⚠ generation produced nothing — the LLM endpoint failed: {err}. "
                  "Switch the model in the web run bar (e.g. the self-hosted vLLM) "
                  "or check the endpoint quota/credentials.")

        # Adaptive per-round red team: regenerate from each round's survivors
        # (opportunistic escalation, seeded on what just evaded).
        if not args.no_adaptive:
            def redteam(evasions, budget, rnd,
                        _gen=gen, _det=assessor.detect, _specs=specs):
                return generate_attacks(
                    _gen, _det, budget, specs=_specs, evasions=evasions,
                    id_prefix=f"GEN-R{rnd}", seed=1234 + rnd,
                )

    orch = SecurityOrchestrator(
        sandbox=sandbox,
        assessor=assessor,
        llm=settings.build_llm(),
        store=store,
        reporter=reporter,
        config=LoopConfig(agent=args.agent, max_iters=args.max_iters, enforce=enforce),
        redteam=redteam,
    )
    result = orch.run()
    result.llm_backend = settings.llm
    result.llm_model = settings.nemotron_model if settings.llm == "nemotron" else settings.llm
    print(reporter.summarize(result))
    print(f"backends: sandbox={settings.sandbox} assessor={settings.assessor} "
          f"llm={settings.llm}({result.llm_model}) · enforce={enforce}")
    if args.out:
        print(f"visual report: {Path(args.out) / 'report.html'}")
        print(f"attack prompts: {Path(args.out) / 'attacks.json'} · "
              f"{Path(args.out) / 'attacks.md'}")
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


def _serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("web UI needs the 'web' extra: uv run --extra web security-orchestrator serve")
        return 1
    print(f"serving run reports at http://{args.host}:{args.port}")
    uvicorn.run("orchestrator.web:app", host=args.host, port=args.port)
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
    run.add_argument("--generate", type=int, default=0, metavar="K",
                     help="dynamic red team: give the model K tries to breach EACH "
                          "selected category (screen against the detector, add "
                          "evaders to the corpus); 0 = corpus only")
    run.add_argument("--no-adaptive", action="store_true",
                     help="disable per-round red-team escalation (with --generate, "
                          "the red team re-generates from each round's survivors)")
    run.add_argument("--full-taxonomy", action="store_true",
                     help="sweep EVERY technique×objective in the selected pool "
                          "exactly once (ignores --generate count; ~1034 attempts "
                          "for all of APE — instant with the mock, slow with an LLM)")
    run.add_argument("--tactics", default="",
                     help="comma-separated APE tactic IDs to restrict generation to "
                          "(e.g. HLT01,HLT03); empty = all tactics")
    run.add_argument("--categories", default="",
                     help="comma-separated attack categories to restrict generation "
                          "to (e.g. data_exfiltration,tool_abuse); empty = all")
    enf = run.add_mutually_exclusive_group()
    enf.add_argument("--enforce", dest="enforce", action="store_true", default=None,
                     help="OpenShell enforces the policy (default)")
    enf.add_argument("--no-enforce", dest="enforce", action="store_false",
                     help="ablation: disable enforcement, attacks always land")
    run.set_defaults(func=_run)

    sv = sub.add_parser("serve", help="light web UI to browse run reports")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8090)
    sv.set_defaults(func=_serve)

    ab = sub.add_parser("ablate", help="run enforcement ON vs OFF and report delta")
    ab.add_argument("--policy", default="policies/permissive.yaml")
    ab.add_argument("--agent", default="target-agent")
    ab.add_argument("--max-iters", type=int, default=10)
    ab.add_argument("--out", default="runs/ablation",
                    help="dir for both run reports")
    ab.set_defaults(func=_ablate)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except real.MissingCredentials as exc:
        # Real backends are the default; a missing endpoint/key is a setup issue,
        # not a stack trace. Point at .env (mocks are for the test suite only).
        print(f"error: {exc}\n\n"
              "The real backends are the default. Provide credentials in .env "
              "(copy .env.example), or set SANDBOX/ASSESSOR/LLM=mock for an "
              "offline run.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

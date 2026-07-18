import json

from orchestrator.__main__ import main
from orchestrator.backends.mock import MockAssessor, MockLLM, MockSandbox
from orchestrator.loop import SecurityOrchestrator
from orchestrator.policy_store import PolicyStore
from orchestrator.reporter import Reporter


def test_reporter_writes_traces_and_summary(tmp_path):
    store = PolicyStore.load("policies/baseline.yaml")
    reporter = Reporter(run_dir=tmp_path)
    orch = SecurityOrchestrator(
        MockSandbox(), MockAssessor(), MockLLM(), store, reporter
    )
    result = orch.run()
    summary = reporter.summarize(result)

    assert "Security Validation Run" in summary
    assert "Converged: yes" in summary
    assert (tmp_path / "summary.md").exists()
    traces = json.loads((tmp_path / "traces.json").read_text())
    assert len(traces) == result.iteration_count
    assert (tmp_path / "iteration-000.json").exists()


def test_cli_run_converges_returns_zero(tmp_path, capsys):
    out = tmp_path / "run"
    saved = tmp_path / "hardened.yaml"
    rc = main([
        "run", "--policy", "policies/baseline.yaml",
        "--out", str(out), "--save-policy", str(saved),
    ])
    captured = capsys.readouterr()
    assert rc == 0
    assert "Converged: yes" in captured.out
    assert saved.exists()
    # hardened policy denies egress by default
    assert "deny" in saved.read_text()

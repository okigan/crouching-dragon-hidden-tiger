"""Dynamic red-team generator: generate → screen → keep evaders."""

from orchestrator.generator import (
    DEFAULT_SPECS,
    MockGenerator,
    generate_attacks,
)


def test_mock_generator_produces_payloads_per_spec():
    gen = MockGenerator()
    for spec in DEFAULT_SPECS:
        assert len(gen.generate(spec)) > 20


def test_generate_keeps_evaders():
    # detector that flags nothing -> every candidate survives as an evader
    cases = generate_attacks(MockGenerator(), lambda p: False, 3)
    assert len(cases) == 3
    assert all(c.hl_detects is False for c in cases)      # marked as evasions
    assert all(c.requires_control for c in cases)          # mapped to a control
    assert all(c.ape_technique.startswith("HLT") for c in cases)  # APE-grounded
    assert [c.id for c in cases] == ["GEN-001", "GEN-002", "GEN-003"]


def test_generate_drops_detected_candidates():
    # detector that flags everything -> nothing survives (all caught at content layer)
    cases = generate_attacks(MockGenerator(), lambda p: True, 3)
    assert cases == []


def test_generated_evaders_land_then_openshell_catches_them():
    # end-to-end through the loop: generated evaders must force OpenShell hardening
    from orchestrator.backends.mock import MockAssessor, MockLLM, MockSandbox
    from orchestrator.loop import LoopConfig, SecurityOrchestrator
    from orchestrator.policy_store import PolicyStore
    from orchestrator.reporter import Reporter

    assessor = MockAssessor(corpus=[])          # start from an empty corpus
    assessor.add_tests(generate_attacks(MockGenerator(), assessor.detect, 3))
    assert assessor.corpus_size == 3

    orch = SecurityOrchestrator(
        MockSandbox(), assessor, MockLLM(),
        PolicyStore.load("policies/permissive.yaml"), Reporter(),
        LoopConfig(max_iters=10),
    )
    result = orch.run()
    assert result.converged is True
    assert result.success_rates[0] == 1.0   # all generated evaders land at first
    assert result.final_success == 0.0       # OpenShell hardened to catch them all

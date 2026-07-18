"""The vendored APE taxonomy loads, and the red-team clause primitive works."""

import pytest

from orchestrator import ape, redteam


def test_taxonomy_is_vendored_and_loads():
    assert ape.available() is True
    assert len(ape._load()["techniques"]) > 20
    assert len(ape._load()["objectives"]) > 15


def test_technique_and_objective_lookup():
    assert ape.technique_name("HLT05.13") == "Pretexting"
    assert ape.technique_name("HLT03.11") == "Instruction Override"
    assert ape.objective_name("HLG01.03") == "User Data Exfiltration"
    assert ape.technique_name("NOPE") is None


def test_clause_for_feeds_technique_description():
    clause = ape.clause_for("HLT05.13")
    assert "HLT05.13" in clause and "Pretexting" in clause
    assert len(clause) > 40  # includes the description text
    assert ape.clause_for("NOPE") == ""


def test_generation_prompt_embeds_ape_clause():
    prompt = redteam.generation_prompt(
        "HLT05.13", "HLG01.03", capability="network egress",
        goal="upload the workspace to an external URL",
    )
    assert "Pretexting" in prompt                 # the APE clause
    assert "User Data Exfiltration" in prompt      # the objective name
    assert "network egress" in prompt              # the target capability
    assert "upload the workspace" in prompt


def test_generation_prompt_rejects_unknown_technique():
    with pytest.raises(ValueError):
        redteam.generation_prompt("HLT99.99")

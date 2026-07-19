"""Test-suite configuration.

Production defaults to the REAL backends (OpenShell + HiddenLayer + Nemotron;
see orchestrator/config.py). The test suite is the *only* place mocks are used,
so pin the backend env to `mock` for every test — this guarantees a test can
never accidentally resolve a live backend from the ambient environment (e.g. a
developer's exported creds or a CI secret).

Tests that need to exercise real-backend *resolution* pass an explicit `env=`
dict to `Settings.from_env`, which bypasses this fixture.
"""

import pytest


@pytest.fixture(autouse=True)
def _mock_backends(monkeypatch):
    monkeypatch.setenv("SANDBOX", "mock")
    monkeypatch.setenv("ASSESSOR", "mock")
    monkeypatch.setenv("LLM", "mock")

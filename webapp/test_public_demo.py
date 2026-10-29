"""Offline tests for public mock mode and protected live Nebius access."""
import base64

import pytest
from fastapi.testclient import TestClient

from backend.live_events import record_event
from webapp.public import app, _attempts, _live_attempts, _attempts_lock


def credentials(username="demo", password="a-long-demo-password-123"):
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


@pytest.fixture(autouse=True)
def secure_test_env(monkeypatch):
    monkeypatch.setenv("SAFEHEAL_DEMO_PASSWORD", "a-long-demo-password-123")
    monkeypatch.setenv("SAFEHEAL_DEMO_USERNAME", "demo")
    monkeypatch.setenv("SAFEHEAL_MAX_ANALYSES_PER_HOUR", "8")
    monkeypatch.setenv("AI_MODE", "mock")
    with _attempts_lock:
        _attempts.clear()
        _live_attempts.clear()
    monkeypatch.delenv("SAFEHEAL_ALLOW_LIVE_DEMO", raising=False)
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("NEBIUS_MODEL", raising=False)


def test_anonymous_health_is_available():
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize("path", [
    "/",
    "/web/assets/app.js",
    "/web/assets/styles.css",
    "/web/demo-dockerfile",
    "/web/demo-analysis",
    "/web/live-events",
    "/api/attack-events",
])
def test_public_routes_open_without_password(path):
    with TestClient(app) as client:
        response = client.get(path)
    assert response.status_code == 200
    assert "www-authenticate" not in response.headers


@pytest.mark.parametrize("path", ["/web/unlock", "/api/live-events", "/api/live-events/stream", "/docs", "/openapi.json"])
def test_private_routes_still_require_password(path):
    with TestClient(app) as client:
        response = client.get(path)
    assert response.status_code == 401
    assert "Basic" in response.headers["www-authenticate"]


def test_bad_credentials_do_not_unlock_private_routes():
    with TestClient(app) as client:
        response = client.get("/web/unlock", headers=credentials(password="wrong-password"))
    assert response.status_code == 401


def test_authorized_users_can_unlock_private_route():
    with TestClient(app) as client:
        response = client.get("/web/unlock", headers=credentials())
    assert response.status_code == 200
    assert "Private SafeHeal Cloud access enabled" in response.text


def test_anonymous_public_probe_is_harmless():
    with TestClient(app) as client:
        response = client.get("/api/debug/demo")
    assert response.status_code == 404


def test_public_live_feed_does_not_expose_client_ip_or_path():
    record_event("SUSPICIOUS_HTTP_REQUEST", "192.0.2.45", "/api/debug/secret-path")
    with TestClient(app) as client:
        response = client.get("/web/live-events?after_id=0")
    assert response.status_code == 200
    assert response.json()["privacy"] == "anonymized"
    assert "192.0.2.45" not in response.text
    assert "secret-path" not in response.text
    assert any(event["source_ip"] == "REDACTED" for event in response.json()["events"])


def test_cannot_read_python_files_as_public_assets():
    with TestClient(app) as client:
        response = client.get("/web/assets/public.py", headers=credentials())
    assert response.status_code == 404


def test_mock_analysis_is_public_without_password():
    dockerfile = b'FROM python:3.9-slim\nRUN useradd -m appuser\nUSER appuser\nCMD ["python", "app.py"]\n'
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze",
            files={"dockerfile": ("Dockerfile", dockerfile)},
        )
    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert response.json()["ai"]["source"] == "mock"


def test_server_side_demo_is_mock_and_matches_existing_contract():
    with TestClient(app) as client:
        response = client.get("/web/demo-analysis")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["ai"]["source"] == "mock"
    assert len(data["findings"]) >= 3
    assert "proposed_patch" in data["tests"]


def test_demo_endpoint_never_calls_live_nebius(monkeypatch):
    monkeypatch.setenv("AI_MODE", "live")
    with TestClient(app) as client:
        response = client.get("/web/demo-analysis")
        authed = client.get("/web/demo-analysis", headers=credentials())
    assert response.status_code == 403
    assert authed.status_code == 403
    assert "live mode" in response.json()["detail"]


def test_demo_route_respects_analysis_rate_limit(monkeypatch):
    monkeypatch.setenv("SAFEHEAL_MAX_ANALYSES_PER_HOUR", "1")
    with TestClient(app) as client:
        first = client.get("/web/demo-analysis")
        second = client.get("/web/demo-analysis")
    assert first.status_code == 200
    assert second.status_code == 429


def test_real_nebius_analysis_requires_password_without_calling_nebius(monkeypatch):
    monkeypatch.setenv("AI_MODE", "live")
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze",
            files={"dockerfile": ("Dockerfile", b"FROM alpine\n")},
        )
    assert response.status_code == 401
    assert "Basic" in response.headers["www-authenticate"]


def test_public_mock_analysis_rate_limit(monkeypatch):
    monkeypatch.setenv("SAFEHEAL_MAX_ANALYSES_PER_HOUR", "1")
    with TestClient(app) as client:
        first = client.post(
            "/api/analyze",
            files={"dockerfile": ("Dockerfile", b"FROM alpine\nUSER 1000\n")},
        )
        second = client.post(
            "/api/analyze",
            files={"dockerfile": ("Dockerfile", b"FROM alpine\nUSER 1000\n")},
        )
    assert first.status_code == 200
    assert second.status_code == 429


def test_missing_password_fails_closed(monkeypatch):
    monkeypatch.delenv("SAFEHEAL_DEMO_PASSWORD")
    with pytest.raises(RuntimeError, match="SAFEHEAL_DEMO_PASSWORD"):
        with TestClient(app):
            pass


def test_team_nebius_demo_requires_auth():
    with TestClient(app) as client:
        response = client.post("/web/team-nebius-demo")
    assert response.status_code == 401


def test_team_nebius_demo_fails_closed_when_not_enabled():
    with TestClient(app) as client:
        response = client.post("/web/team-nebius-demo", headers=credentials())
    assert response.status_code == 503
    assert "disabled" in response.json()["detail"]


def test_team_nebius_demo_requires_configuration(monkeypatch):
    monkeypatch.setenv("SAFEHEAL_ALLOW_LIVE_DEMO", "true")
    with TestClient(app) as client:
        response = client.post("/web/team-nebius-demo", headers=credentials())
    assert response.status_code == 503
    assert "configuration" in response.json()["detail"]


def test_team_nebius_demo_rejects_cross_origin(monkeypatch):
    monkeypatch.setenv("SAFEHEAL_ALLOW_LIVE_DEMO", "true")
    monkeypatch.setenv("NEBIUS_API_KEY", "dummy-not-real")
    monkeypatch.setenv("NEBIUS_MODEL", "test-model")
    with TestClient(app) as client:
        response = client.post(
            "/web/team-nebius-demo",
            headers={**credentials(), "Origin": "https://evil.example"},
        )
    assert response.status_code == 403


def test_team_nebius_demo_injects_live_settings_without_mutating_public_mode(monkeypatch):
    monkeypatch.setenv("SAFEHEAL_ALLOW_LIVE_DEMO", "true")
    monkeypatch.setenv("NEBIUS_API_KEY", "dummy-not-real")
    monkeypatch.setenv("NEBIUS_MODEL", "test-model")
    modes = []

    def fake_analyze(dockerfile, logs, settings):
        modes.append(settings.mode)
        assert "EXPOSE 22" in dockerfile
        assert any(event["event_type"] == "PORT_SCAN" for event in logs)
        return {
            "status": "completed",
            "findings": [],
            "correlations": [],
            "patch": {
                "patched_dockerfile": "FROM python:3.9-slim\\nUSER appuser\\nEXPOSE 5000",
                "summary": "Test stub",
                "diff": "",
            },
            "ai": {
                "source": "nebius",
                "model": "test-model",
                "error": None,
                "patch_status": "proposed_not_validated",
            },
        }

    monkeypatch.setattr("webapp.public.analyze_evidence", fake_analyze)
    with TestClient(app) as client:
        live = client.post("/web/team-nebius-demo", headers=credentials())
        public = client.get("/web/demo-analysis")
    assert live.status_code == 200
    assert live.json()["ai"]["source"] == "nebius"
    assert live.json()["tests"]["proposed_patch"]["status"] == "static_review_only"
    assert live.json()["response"]["mode"] == "simulation"
    assert modes == ["live"]
    assert public.status_code == 200
    assert public.json()["ai"]["source"] == "mock"


def test_team_nebius_demo_uses_separate_rate_limit(monkeypatch):
    monkeypatch.setenv("SAFEHEAL_ALLOW_LIVE_DEMO", "true")
    monkeypatch.setenv("NEBIUS_API_KEY", "dummy-not-real")
    monkeypatch.setenv("NEBIUS_MODEL", "test-model")
    monkeypatch.setenv("SAFEHEAL_MAX_LIVE_ANALYSES_PER_HOUR", "1")
    monkeypatch.setattr("webapp.public.analyze_evidence", lambda *args: {
        "status": "ai_error", "findings": [], "correlations": [],
        "patch": {"patched_dockerfile": "", "summary": "", "diff": ""},
        "ai": {"source": "nebius", "error": {"code": "test_error", "message": "fake"}, "patch_status": "none"},
    })
    with TestClient(app) as client:
        first = client.post("/web/team-nebius-demo", headers=credentials())
        second = client.post("/web/team-nebius-demo", headers=credentials())
        public = client.get("/web/demo-analysis")
    assert first.status_code == 200
    assert second.status_code == 429
    assert public.status_code == 200

"""Offline tests for the password-protected Render demo entrypoint."""
import base64

import pytest
from fastapi.testclient import TestClient
from webapp.public import app, _attempts, _attempts_lock


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


def test_anonymous_health_is_available():
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize("path", ["/", "/web/assets/app.js", "/web/demo-dockerfile", "/web/live-events", "/api/attack-events"])
def test_demo_routes_require_password(path):
    with TestClient(app) as client:
        response = client.get(path)
    assert response.status_code == 401
    assert "Basic" in response.headers["www-authenticate"]


def test_invalid_credentials_are_rejected():
    with TestClient(app) as client:
        response = client.get("/", headers=credentials(password="wrong-password"))
    assert response.status_code == 401


def test_authorized_dashboard_assets_and_demo_are_accessible():
    with TestClient(app) as client:
        root = client.get("/", headers=credentials())
        js = client.get("/web/assets/app.js", headers=credentials())
        sample = client.get("/web/demo-dockerfile", headers=credentials())
        live = client.get("/web/live-events", headers=credentials())
        hidden = client.get("/web/assets/public.py", headers=credentials())
    assert root.status_code == 200
    assert "SafeHeal" in root.text
    assert js.status_code == 200
    assert sample.status_code == 200
    assert "FROM " in sample.text
    assert live.status_code == 200
    assert live.json()["mode"] == "live"
    assert hidden.status_code == 404


def test_analyze_post_requires_password():
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze",
            files={"dockerfile": ("Dockerfile", b"FROM python:3.9-slim\n")},
        )
    assert response.status_code == 401


def test_authorized_analysis_uses_offline_mock():
    dockerfile = b'FROM python:3.9-slim\nRUN useradd -m appuser\nUSER appuser\nCMD ["python", "app.py"]\n'
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze",
            files={"dockerfile": ("Dockerfile", dockerfile)},
            headers=credentials(),
        )
    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert response.json()["ai"]["source"] == "mock"


def test_analysis_rate_limit(monkeypatch):
    monkeypatch.setenv("SAFEHEAL_MAX_ANALYSES_PER_HOUR", "1")
    payload = {"dockerfile": ("Dockerfile", b"FROM alpine\nUSER 1000\n")}
    with TestClient(app) as client:
        first = client.post("/api/analyze", files=payload, headers=credentials())
        second = client.post("/api/analyze", files=payload, headers=credentials())
    assert first.status_code == 200
    assert second.status_code == 429


def test_missing_password_fails_closed(monkeypatch):
    monkeypatch.delenv("SAFEHEAL_DEMO_PASSWORD")
    with pytest.raises(RuntimeError, match="SAFEHEAL_DEMO_PASSWORD"):
        with TestClient(app):
            pass

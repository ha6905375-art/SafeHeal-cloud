
"""Tests for simulated attack monitoring."""

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_attack_monitor_success():
    response = client.get("/api/attack-events")

    assert response.status_code == 200

    data = response.json()

    assert data["mode"] == "simulation"
    assert data["total"] == len(data["events"])
    assert isinstance(data["events"], list)


def test_attack_monitor_event_fields():
    response = client.get("/api/attack-events")

    assert response.status_code == 200

    for event in response.json()["events"]:
        assert "timestamp" in event
        assert "source_ip" in event
        assert "event_type" in event
        assert "status" in event


def test_attack_monitor_extended_scenario():
    response = client.get(
        "/api/attack-events?scenario=extended"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["mode"] == "simulation"
    assert data["total"] == 16
    assert len(data["events"]) == 16


def test_attack_monitor_invalid_scenario():
    response = client.get(
        "/api/attack-events?scenario=invalid"
    )

    assert response.status_code == 422

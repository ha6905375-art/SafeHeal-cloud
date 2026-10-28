
"""Tests for live HTTP attack monitoring."""

from fastapi.testclient import TestClient

from backend.main import app
from backend.live_events import get_events_after


client = TestClient(app)


def latest_event_id():
    events = get_events_after()
    return events[-1]["id"] if events else 0


def test_suspicious_request_is_recorded():
    previous_id = latest_event_id()

    response = client.get("/api/debug")

    assert response.status_code == 404

    events = get_events_after(previous_id)

    assert len(events) == 1
    assert events[0]["event_type"] == "SUSPICIOUS_HTTP_REQUEST"
    assert events[0]["endpoint"] == "/api/debug"
    assert events[0]["severity"] == "high"
    assert events[0]["action_taken"] == "NONE"


def test_normal_request_is_not_flagged():
    previous_id = latest_event_id()

    response = client.get("/api/health")

    assert response.status_code == 200
    assert get_events_after(previous_id) == []


def test_live_events_api_returns_new_events():
    previous_id = latest_event_id()

    client.get("/api/debug")

    response = client.get(
        "/api/live-events",
        params={"after_id": previous_id},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["mode"] == "live"
    assert data["total"] == 1
    assert data["events"][0]["id"] > previous_id

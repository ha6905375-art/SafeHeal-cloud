
"""Tests for event/IP correlation validation."""

from ai.service import _ground_correlations


def test_rejects_wrong_event_ip_pair():
    logs = [
        {
            "event_type": "PORT_SCAN",
            "source_ip": "192.0.2.10",
        },
        {
            "event_type": "AUTH_ATTEMPT",
            "source_ip": "198.51.100.20",
        },
    ]

    correlations = [
        {
            "event_type": "PORT_SCAN",
            "source_ip": "198.51.100.20",
            "related_finding_ids": ["F-001"],
            "explanation": "Suspicious activity",
        }
    ]

    warnings = []

    result = _ground_correlations(
        correlations, logs, {"F-001"}, warnings
    )

    assert result[0]["event_type"] == "PORT_SCAN"
    assert result[0]["source_ip"] is None
    assert any("same log event" in w for w in warnings)


def test_accepts_correct_event_ip_pair():
    logs = [
        {
            "event_type": "PORT_SCAN",
            "source_ip": "192.0.2.10",
        }
    ]

    correlations = [
        {
            "event_type": "PORT_SCAN",
            "source_ip": "192.0.2.10",
            "related_finding_ids": ["F-001"],
            "explanation": "Confirmed correlation",
        }
    ]

    result = _ground_correlations(
        correlations, logs, {"F-001"}, []
    )

    assert result[0]["event_type"] == "PORT_SCAN"
    assert result[0]["source_ip"] == "192.0.2.10"

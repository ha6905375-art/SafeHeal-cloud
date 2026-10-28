
"""Thread-safe, bounded storage for live security events."""

from collections import deque
from datetime import datetime, timezone
from threading import Lock

MAX_EVENTS = 200

_events = deque(maxlen=MAX_EVENTS)
_lock = Lock()
_next_id = 0


def record_event(event_type, source_ip, endpoint, severity="medium"):
    """Record an observed event without executing defensive actions."""
    global _next_id

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "source_ip": source_ip,
        "endpoint": endpoint.split("?", 1)[0][:200],
        "severity": severity,
        "status": "FLAGGED",
        "action_taken": "NONE",
    }

    with _lock:
        _next_id += 1
        event["id"] = _next_id
        _events.append(event)

    return event.copy()


def get_events_after(last_id=0):
    """Return events added after the supplied event ID."""
    with _lock:
        return [
            event.copy()
            for event in _events
            if event["id"] > last_id
        ]

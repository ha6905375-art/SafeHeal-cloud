
"""Monitor suspicious HTTP requests reaching the Backend."""

from fastapi import Request
from backend.live_events import record_event


SUSPICIOUS_PATHS = (
    "/.env",
    "/.git/",
    "/wp-admin",
    "/api/debug",
    "/actuator/env",
)


def is_suspicious_path(path: str) -> bool:
    """Identify common probes for sensitive application paths."""
    path = path.lower()

    for pattern in SUSPICIOUS_PATHS:
        if pattern.endswith("/"):
            if path.startswith(pattern):
                return True
        elif path == pattern or path.startswith(pattern + "/"):
            return True

    return False


async def live_monitor_middleware(request: Request, call_next):
    """Observe incoming requests without blocking them."""

    path = request.url.path

    if is_suspicious_path(path):
        source_ip = (
            request.client.host
            if request.client
            else "unknown"
        )

        record_event(
            event_type="SUSPICIOUS_HTTP_REQUEST",
            source_ip=source_ip,
            endpoint=path,
            severity="high",
        )

    response = await call_next(request)
    return response

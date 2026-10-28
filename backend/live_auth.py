
"""Access protection for live security monitoring."""

import os
import secrets

from fastapi import HTTPException, Request


def require_live_access(request: Request):
    expected = os.getenv("LIVE_EVENTS_API_TOKEN", "").strip()

    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Live monitoring access is not configured.",
        )

    authorization = request.headers.get("Authorization", "")
    scheme, separator, provided = authorization.partition(" ")

    if (
        not separator
        or scheme.lower() != "bearer"
        or not provided
        or not secrets.compare_digest(provided, expected)
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized live monitoring access.",
            headers={"WWW-Authenticate": "Bearer"},
        )

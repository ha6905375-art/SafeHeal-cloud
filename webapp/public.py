"""Password-protected public showcase for SafeHeal Cloud.

The original webapp.run remains strictly localhost-only. Use this separate
entrypoint for HTTPS deployments behind a reverse proxy such as Render.

This is a hackathon demo, not a general-purpose production security service.
Access is restricted so anonymous visitors cannot use Nebius credits.
"""
from __future__ import annotations

import base64
import binascii
import os
import secrets
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from ai.config import load_dotenv
from backend.live_events import get_events_after
from backend.main import app as backend_app

load_dotenv()
ASSETS = Path(__file__).resolve().parent
REPO = ASSETS.parent
_attempts: deque[float] = deque()
_attempts_lock = Lock()
WINDOW_SECONDS = 3600


def _valid_basic_auth(header: str) -> bool:
    """Compare credentials without ever exposing them to page assets."""
    scheme, sep, encoded = header.partition(" ")
    if not sep or scheme.lower() != "basic":
        return False
    try:
        raw = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return False
    username, delim, password = raw.partition(":")
    if not delim:
        return False
    expected_password = os.getenv("SAFEHEAL_DEMO_PASSWORD", "")
    expected_user = os.getenv("SAFEHEAL_DEMO_USERNAME", "demo")
    return (
        secrets.compare_digest(username, expected_user)
        and secrets.compare_digest(password, expected_password)
    )


def _allow_analysis() -> bool:
    """Small in-memory safeguard; reset on server restart, not a billing cap."""
    try:
        limit = max(1, min(100, int(os.getenv("SAFEHEAL_MAX_ANALYSES_PER_HOUR", "8"))))
    except ValueError:
        limit = 8
    now = time.monotonic()
    with _attempts_lock:
        while _attempts and _attempts[0] <= now - WINDOW_SECONDS:
            _attempts.popleft()
        if len(_attempts) >= limit:
            return False
        _attempts.append(now)
        return True


@asynccontextmanager
async def lifespan(_: FastAPI):
    if len(os.getenv("SAFEHEAL_DEMO_PASSWORD", "")) < 12:
        raise RuntimeError(
            "SAFEHEAL_DEMO_PASSWORD must be set to at least 12 characters "
            "before exposing SafeHeal Cloud publicly."
        )
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def protect_public_demo(request: Request, call_next):
    if request.url.path == "/api/health" and request.method == "GET":
        return await call_next(request)

    if not _valid_basic_auth(request.headers.get("authorization", "")):
        return JSONResponse(
            status_code=401,
            content={"detail": "Demo authentication required"},
            headers={
                "WWW-Authenticate": 'Basic realm="SafeHeal Cloud Demo", charset="UTF-8"',
                "Cache-Control": "no-store",
            },
        )

    if request.method == "POST" and request.url.path == "/api/analyze":
        if not _allow_analysis():
            return JSONResponse(
                status_code=429,
                content={"detail": "Demo analysis limit reached. Try again later."},
                headers={"Cache-Control": "no-store"},
            )

    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(ASSETS / "index.html", media_type="text/html")


@app.get("/web/assets/{filename}", include_in_schema=False)
def safe_asset(filename: str):
    if filename not in {"app.js", "styles.css"}:
        raise HTTPException(status_code=404, detail="Asset not found")
    return FileResponse(ASSETS / filename)


@app.get("/web/demo-dockerfile", include_in_schema=False)
def demo_dockerfile():
    path = REPO / "security" / "vulnerable.Dockerfile"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Sample Dockerfile unavailable")
    return PlainTextResponse(path.read_text(encoding="utf-8"))


@app.get("/web/live-events", include_in_schema=False)
def demo_live_events(after_id: int = 0):
    if after_id < 0:
        raise HTTPException(status_code=422, detail="after_id must be nonnegative")
    events = get_events_after(after_id)
    return {"mode": "live", "total": len(events), "events": events}


# Preserve existing backend routes and middleware without rewriting them.
# All mounted endpoints are protected by the outer app's authentication.
app.mount("/", backend_app)

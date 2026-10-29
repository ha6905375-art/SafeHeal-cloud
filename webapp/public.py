"""Public, cost-safe SafeHeal Cloud showcase for the hackathon.

The original webapp.run remains strictly localhost-only. Use this separate
entrypoint for HTTPS deployments behind a reverse proxy such as Render.

Anyone can view the site and run *mock* analysis. Real Nebius analysis and
private event APIs require a password; public live telemetry is anonymized.
This is not production-grade authentication, logging, or billing enforcement.
"""
from __future__ import annotations

import base64
import binascii
import io
import json
import os
import secrets
import time
from dataclasses import replace
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from starlette.concurrency import run_in_threadpool
from ai.config import get_settings, load_dotenv
from ai.service import analyze_evidence
from backend.live_events import get_events_after
from backend.main import app as backend_app
from backend.simulation import simulate_response
from backend.validator import validate_dockerfile

load_dotenv()
ASSETS = Path(__file__).resolve().parent
REPO = ASSETS.parent
_attempts: deque[float] = deque()
_live_attempts: deque[float] = deque()
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
    """Small process-local limit, not a durable or distributed billing cap."""
    default_limit = 40 if get_settings().mode == "mock" else 8
    try:
        limit = max(1, min(100, int(os.getenv("SAFEHEAL_MAX_ANALYSES_PER_HOUR", str(default_limit)))))
    except ValueError:
        limit = default_limit
    now = time.monotonic()
    with _attempts_lock:
        while _attempts and _attempts[0] <= now - WINDOW_SECONDS:
            _attempts.popleft()
        if len(_attempts) >= limit:
            return False
        _attempts.append(now)
        return True


def _allow_live_analysis() -> bool:
    """Separate small rate limit for paid inference (per worker, not a budget cap)."""
    try:
        limit = max(1, min(5, int(os.getenv("SAFEHEAL_MAX_LIVE_ANALYSES_PER_HOUR", "2"))))
    except ValueError:
        limit = 2
    now = time.monotonic()
    with _attempts_lock:
        while _live_attempts and _live_attempts[0] <= now - WINDOW_SECONDS:
            _live_attempts.popleft()
        if len(_live_attempts) >= limit:
            return False
        _live_attempts.append(now)
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


# Explicit allowlist: never expose arbitrary backend routes anonymously.
PUBLIC_GET_PATHS = frozenset({
    "/",
    "/web/assets/app.js",
    "/web/assets/styles.css",
    "/web/demo-dockerfile",
    "/web/demo-analysis",  # Fixed server-side mock evidence, no risky upload.
    "/web/live-events",
    "/api/health",
    "/api/attack-events",  # Bundled synthetic scenarios, not observed traffic.
    "/api/debug/demo",     # Harmless test probe; intentionally returns 404.
})


def _is_public_request(request: Request) -> bool:
    if request.method == "GET" and request.url.path in PUBLIC_GET_PATHS:
        return True
    if request.method == "POST" and request.url.path == "/api/analyze":
        # Public analysis is safe in mock mode ONLY. Switching to live
        # immediately requires Basic Auth for the same endpoint.
        return get_settings().mode == "mock"
    return False


@app.middleware("http")
async def protect_public_demo(request: Request, call_next):
    if not _is_public_request(request) and not _valid_basic_auth(
        request.headers.get("authorization", "")
    ):
        return JSONResponse(
            status_code=401,
            content={"detail": "Private demo credentials required for this endpoint"},
            headers={
                "WWW-Authenticate": 'Basic realm="SafeHeal Cloud Private Demo", charset="UTF-8"',
                "Cache-Control": "no-store",
            },
        )

    analysis_request = (
        request.method == "POST" and request.url.path == "/api/analyze"
    ) or (
        request.method == "GET" and request.url.path == "/web/demo-analysis"
    )
    if analysis_request:
        if not _allow_analysis():
            return JSONResponse(
                status_code=429,
                content={"detail": "Demo analysis limit reached. Try again later."},
                headers={"Cache-Control": "no-store"},
            )

    if request.method == "POST" and request.url.path == "/web/team-nebius-demo":
        # Require a genuine same-origin browser request as well as Basic Auth.
        # A cross-site form must not trigger an inference using cached credentials.
        origin = request.headers.get("origin")
        if origin and origin != f"https://{request.headers.get('host', '')}":
            return JSONResponse(status_code=403, content={"detail": "Invalid request origin"})
        if os.getenv("SAFEHEAL_ALLOW_LIVE_DEMO", "").lower() not in {"1", "true"}:
            return JSONResponse(status_code=503, content={"detail": "Team Nebius demo is disabled"})
        settings = get_settings()
        if not settings.api_key or not settings.model:
            return JSONResponse(status_code=503, content={"detail": "Nebius server configuration is incomplete"})
        if not _allow_live_analysis():
            return JSONResponse(
                status_code=429,
                content={"detail": "Team live analysis quota reached. Try again later."},
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


@app.get("/web/demo-analysis", include_in_schema=False)
async def demo_analysis():
    """Analyze bundled synthetic evidence without uploading it through the CDN.

    This is intentionally unavailable in live mode: the endpoint can never
    spend Nebius credits, even for users with the private demo password.
    """
    if get_settings().mode != "mock":
        raise HTTPException(
            status_code=403,
            detail="Demo-only analysis is disabled in live mode",
        )

    from fastapi import UploadFile
    from backend.main import analyze

    dockerfile = (REPO / "security" / "vulnerable.Dockerfile").read_bytes()
    logs = (REPO / "security" / "attack_logs.json").read_bytes()

    return await analyze(
        dockerfile=UploadFile(
            filename="Dockerfile",
            file=io.BytesIO(dockerfile),
        ),
        attack_logs=UploadFile(
            filename="attack_logs.json",
            file=io.BytesIO(logs),
        ),
    )


@app.post("/web/team-nebius-demo", include_in_schema=False)
async def team_nebius_demo():
    """Team-only real Nebius inference on fixed synthetic evidence.

    There is intentionally no upload body here; the hosting edge may reject
    the insecure demonstration Dockerfile and attack strings. The ordinary
    public /web/demo-analysis endpoint remains mock-only.
    """
    dockerfile_text = (REPO / "security" / "vulnerable.Dockerfile").read_text(encoding="utf-8")
    logs = json.loads((REPO / "security" / "attack_logs.json").read_text(encoding="utf-8"))

    # Never change the process-wide AI_MODE; that would race with public
    # requests. Inject an immutable explicit live settings object instead.
    settings = replace(get_settings(), mode="live")
    result = await run_in_threadpool(analyze_evidence, dockerfile_text, logs, settings)

    original_review = validate_dockerfile(dockerfile_text)
    result["tests"] = {
        "status": "completed",
        "passed": original_review["passed"],
        "details": original_review["details"],
    }
    patch = result.get("patch", {}).get("patched_dockerfile", "")
    if isinstance(patch, str) and patch.strip():
        patch_review = validate_dockerfile(patch)
        result["tests"]["proposed_patch"] = {
            "status": "static_review_only",
            "passed": patch_review["passed"],
            "details": patch_review["details"],
        }
        if not patch_review["passed"] and result.get("ai", {}).get("patch_status") == "proposed_not_validated":
            result["ai"]["patch_status"] = "proposed_failed_static_review"
            result["ai"].setdefault("warnings", []).append(
                "Backend static review found issues in the proposed Dockerfile."
            )

    result["response"] = simulate_response(logs)
    return result


@app.get("/web/live-events", include_in_schema=False)
def demo_live_events(after_id: int = 0):
    """Public feed without client IP addresses or requested URL paths."""
    if after_id < 0:
        raise HTTPException(status_code=422, detail="after_id must be nonnegative")
    events = get_events_after(after_id)
    public_events = [
        {
            "id": event["id"],
            "timestamp": event["timestamp"],
            "event_type": event["event_type"],
            "source_ip": "REDACTED",
            "endpoint": "[redacted]",
            "severity": event["severity"],
            "status": event["status"],
            "action_taken": "NONE",
        }
        for event in events
    ]
    return {"mode": "live", "privacy": "anonymized", "total": len(public_events), "events": public_events}


@app.get("/web/unlock", include_in_schema=False)
def unlock_private_demo():
    """Optional team-only sign-in endpoint for real Nebius demonstrations.

    Visit this URL in a browser and enter demo credentials. The browser then
    remembers the same-origin Basic Auth credentials for private API calls.
    """
    return PlainTextResponse("Private SafeHeal Cloud access enabled. Return to the dashboard.")


# Preserve existing backend routes and middleware without rewriting them.
# All mounted endpoints are protected by the outer app's authentication.
app.mount("/", backend_app)

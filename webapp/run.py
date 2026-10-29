"""Local, same-origin SafeHeal website runner.

Start from the repo root:
    python -m uvicorn webapp.run:app --host 127.0.0.1 --port 8000

Only intended for a loopback hackathon demo. Do not expose this app publicly
without authentication and rate-limiting for all backend endpoints.
"""
from __future__ import annotations

import os
from ipaddress import ip_address
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from ai.config import load_dotenv
from backend.live_events import get_events_after
from backend.main import app

ASSETS = Path(__file__).resolve().parent
REPO = ASSETS.parent

# Do not put the live monitoring API token into browser JavaScript or HTML.
load_dotenv()


def _require_local_client(request: Request) -> None:
    """Prevent exposing this demo gateway to directly connected remote clients.

    Proxy deployments are NOT supported. Reverse proxies would change the peer
    IP and must not be used to bypass this demo-only boundary.
    """
    client = request.client.host if request.client else ""
    try:
        local = ip_address(client).is_loopback
    except ValueError:
        local = False
    if not local:
        raise HTTPException(status_code=403, detail="Local demo access only")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(ASSETS / "index.html", media_type="text/html")


@app.get("/web/demo-dockerfile", include_in_schema=False)
def demo_dockerfile(request: Request):
    _require_local_client(request)
    path = REPO / "security" / "vulnerable.Dockerfile"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Sample Dockerfile not available")
    return PlainTextResponse(path.read_text(encoding="utf-8"))


@app.get("/web/live-events", include_in_schema=False)
def local_live_gateway(request: Request, after_id: int = 0):
    """Local-only browser read of bounded in-process events, no token leakage.

    This runner is for localhost presentations; public deployments need a proper
    authenticated session layer and CSRF/rate-limit protection.
    """
    _require_local_client(request)
    if not (os.getenv("LIVE_EVENTS_API_TOKEN") or "").strip():
        raise HTTPException(status_code=503, detail="Set LIVE_EVENTS_API_TOKEN in local .env")
    if after_id < 0:
        raise HTTPException(status_code=422, detail="after_id must not be negative")
    events = get_events_after(after_id)
    return {"mode": "live", "total": len(events), "events": events}


# Avoid CORS entirely: both the website and backend run on the same origin.
# All backend API routes remain defined by backend.main; no AI secrets move
# into the browser. This route must be added after the explicit routes above.
app.mount("/web/assets", StaticFiles(directory=ASSETS), name="web-assets")

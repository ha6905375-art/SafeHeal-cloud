
"""Live security event API using Server-Sent Events."""

import asyncio
import json

from fastapi import APIRouter, Request, Query
from fastapi.responses import StreamingResponse

from backend.live_events import get_events_after


router = APIRouter(prefix="/api", tags=["Live Attack Monitoring"])


@router.get("/live-events")
def list_live_events(after_id: int = Query(default=0, ge=0)):
    """Return live security events currently held in memory."""
    events = get_events_after(after_id)

    return {
        "mode": "live",
        "total": len(events),
        "events": events,
    }


@router.get("/live-events/stream")
async def stream_live_events(request: Request):
    """Stream new security events to connected clients."""

    last_event_id = request.headers.get("last-event-id", "0")

    try:
        cursor = max(0, int(last_event_id))
    except ValueError:
        cursor = 0

    async def event_generator():
        nonlocal cursor

        heartbeat_count = 0

        while not await request.is_disconnected():
            events = get_events_after(cursor)

            for event in events:
                cursor = event["id"]

                data = json.dumps(event, ensure_ascii=False)

                yield (
                    f"id: {cursor}\n"
                    f"event: attack\n"
                    f"data: {data}\n\n"
                )

            heartbeat_count += 1

            if heartbeat_count >= 15:
                yield ": heartbeat\n\n"
                heartbeat_count = 0

            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

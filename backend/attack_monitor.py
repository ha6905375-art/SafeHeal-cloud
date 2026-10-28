
"""Read simulated attack scenarios without changing security files."""

import json
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api", tags=["Attack Monitor"])

SECURITY_DIR = Path(__file__).resolve().parent.parent / "security"

SCENARIOS = {
    "classic": SECURITY_DIR / "attack_logs.json",
    "extended": SECURITY_DIR / "attack _logs.json",
}


@router.get("/attack-events")
def get_attack_events(
    scenario: Literal["classic", "extended"] = "classic"
):
    logs_path = SCENARIOS[scenario]

    if not logs_path.is_file():
        raise HTTPException(
            status_code=503,
            detail="Demo attack logs are unavailable",
        )

    try:
        with logs_path.open("r", encoding="utf-8-sig") as file:
            events = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise HTTPException(
            status_code=503,
            detail="Unable to load demo attack logs",
        )

    if not isinstance(events, list):
        raise HTTPException(
            status_code=422,
            detail="Attack logs must be a JSON array",
        )

    return {
        "mode": "simulation",
        "total": len(events),
        "events": events,
    }

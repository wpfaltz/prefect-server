from __future__ import annotations
import secrets, time
from typing import Any

TICKETS: dict[str, dict[str, Any]] = {}

def create_ticket() -> str:
    tid = secrets.token_urlsafe(24)
    TICKETS[tid] = {"created_at": time.time(), "jwt": None}
    return tid

def set_ticket_jwt(ticket_id: str, token: str) -> None:
    if ticket_id not in TICKETS:
        raise KeyError("invalid ticket")
    TICKETS[ticket_id]["jwt"] = token

def get_ticket(ticket_id: str) -> dict[str, Any] | None:
    return TICKETS.get(ticket_id)
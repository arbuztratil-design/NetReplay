"""API route helpers."""
from __future__ import annotations

from fastapi import HTTPException, Request

from netreplay.core.storage import SessionStorage


def get_session(request: Request, session_id: str) -> SessionStorage:
    service = request.app.state.service
    session = service.open_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"session not found: {session_id}")
    return session

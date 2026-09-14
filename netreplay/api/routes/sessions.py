"""Session and timeline endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Query, Request

from netreplay.api.routes import get_session
from netreplay.api.schemas import EventOut, SessionOut
from netreplay.core.storage.database import SessionInfo
from netreplay.core.timeline.service import TimelineEvent, TimelineService

router = APIRouter(tags=["sessions"])


def _session_out(info: SessionInfo) -> SessionOut:
    return SessionOut(**{
        "session_id": info.session_id,
        "name": info.name,
        "interface": info.interface,
        "created_at": info.created_at,
        "status": info.status,
        "packet_count": info.packet_count,
        "flow_count": info.flow_count,
        "event_count": info.event_count,
        "first_ts": info.first_ts,
        "last_ts": info.last_ts,
        "path": info.path,
    })


def _event_out(ev: TimelineEvent) -> EventOut:
    return EventOut(timestamp=ev.timestamp, type=ev.type, flow_id=ev.flow_id, summary=ev.summary)


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(request: Request) -> list[SessionOut]:
    return [_session_out(info) for info in request.app.state.service.list_sessions()]


@router.get("/sessions/{session_id}", response_model=SessionOut)
def session_detail(request: Request, session_id: str) -> SessionOut:
    return _session_out(get_session(request, session_id).info())


@router.get("/sessions/{session_id}/timeline", response_model=list[EventOut])
def session_timeline(
    request: Request,
    session_id: str,
    start: float | None = None,
    end: float | None = None,
    types: str | None = Query(default=None, description="comma separated types"),
    flow_id: int | None = None,
    limit: int = Query(default=1000, ge=1, le=100_000),
    offset: int = Query(default=0, ge=0),
) -> list[EventOut]:
    session = get_session(request, session_id)
    type_list = [t.strip().upper() for t in (types or "").split(",") if t.strip()]
    events = TimelineService(session).events(
        start=start, end=end, types=type_list or None, limit=limit, flow_id=flow_id, offset=offset
    )
    return [_event_out(ev) for ev in events]
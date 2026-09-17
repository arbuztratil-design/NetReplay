"""Session and timeline endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Query, Request

from netreplay.api.routes import get_session
from netreplay.api.schemas import EventOut, SessionOut, SessionStatsOut
from netreplay.core.stats import compute_stats
from netreplay.core.storage.database import SessionInfo
from netreplay.core.timeline.service import TimelineEvent, TimelineService

router = APIRouter(tags=["sessions"])


def _session_out(info: SessionInfo) -> SessionOut:
    return SessionOut(
        session_id=info.session_id,
        name=info.name,
        interface=info.interface,
        created_at=info.created_at,
        status=info.status,
        packet_count=info.packet_count,
        flow_count=info.flow_count,
        event_count=info.event_count,
        first_ts=info.first_ts,
        last_ts=info.last_ts,
        path=info.path,
        dropped_packets=info.dropped_packets,
        integrity=info.integrity,
        integrity_hash=info.integrity_hash,
    )


def _event_out(ev: TimelineEvent) -> EventOut:
    return EventOut(timestamp=ev.timestamp, type=ev.type, flow_id=ev.flow_id, summary=ev.summary)


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(request: Request) -> list[SessionOut]:
    return [_session_out(info) for info in request.app.state.service.list_sessions()]


@router.get("/sessions/{session_id}", response_model=SessionOut)
def session_detail(request: Request, session_id: str) -> SessionOut:
    return _session_out(get_session(request, session_id).info())


@router.get("/sessions/{session_id}/stats", response_model=SessionStatsOut)
def session_stats(request: Request, session_id: str) -> SessionStatsOut:
    """Aggregate statistics for a session (#28): PPS, bytes, flows, resets."""
    stats = compute_stats(get_session(request, session_id))
    return SessionStatsOut(
        packet_count=stats.packet_count,
        byte_count=stats.byte_count,
        flow_count=stats.flow_count,
        event_count=stats.event_count,
        duration=stats.duration,
        packets_per_second=stats.packets_per_second,
        bytes_per_second=stats.bytes_per_second,
        average_packet_size=stats.average_packet_size,
        reset_count=stats.reset_count,
        retransmission_count=stats.retransmission_count,
    )


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

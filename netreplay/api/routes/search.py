"""Search and similarity endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from netreplay.api.routes import get_session
from netreplay.api.routes.flows import _flow_out, _packet_out
from netreplay.api.schemas import EventOut, SearchOut, SimilarSessionOut
from netreplay.core.search import search_session, similar_sessions
from netreplay.core.storage.database import EventRow

router = APIRouter(tags=["search"])


def _event_out(ev: EventRow) -> EventOut:
    return EventOut(
        timestamp=ev.ts, type=ev.event_type, flow_id=ev.flow_id, summary=ev.summary
    )


@router.get("/sessions/{session_id}/search", response_model=SearchOut)
def session_search(
    request: Request,
    session_id: str,
    q: str = Query(..., min_length=1, max_length=256, description="IP or domain to find"),
    limit: int = Query(default=100, ge=1, le=500),
) -> SearchOut:
    session = get_session(request, session_id)
    try:
        result = search_session(
            session,
            q,
            max_events=limit,
            max_flows=limit,
            max_packets=limit,
        )
    finally:
        session.close()
    return SearchOut(
        query=result.query,
        total=result.total,
        events=[_event_out(ev) for ev in result.events],
        flows=[_flow_out(row) for row in result.flows],
        packets=[_packet_out(pkt) for pkt in result.packets],
    )


@router.get("/sessions/{session_id}/similar", response_model=list[SimilarSessionOut])
def session_similar(
    request: Request,
    session_id: str,
    top: int = Query(default=5, ge=1, le=20),
) -> list[SimilarSessionOut]:
    path = request.app.state.service.get_session_path(session_id)
    if path is None:
        raise HTTPException(status_code=404, detail=f"session not found: {session_id}")
    found = similar_sessions(path, top=top)
    return [
        SimilarSessionOut(
            session_id=s.session_id,
            name=s.name,
            score=s.score,
            shared_domains=s.shared_domains,
            shared_ips=s.shared_ips,
            shared_ports=s.shared_ports,
        )
        for s in found
    ]

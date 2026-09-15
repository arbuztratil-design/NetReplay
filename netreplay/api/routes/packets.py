"""Packet endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from netreplay.api.routes import get_session
from netreplay.api.schemas import PacketOut

router = APIRouter(tags=["packets"])


def _packet_out(row, raw_bytes: bytes | None, raw: bool) -> PacketOut:
    return PacketOut(
        id=row.id,
        ts=row.ts,
        source=row.source,
        destination=row.destination,
        protocol=row.protocol,
        src_port=row.src_port,
        dst_port=row.dst_port,
        length=row.length,
        flow_id=row.flow_id,
        raw_hex=raw_bytes.hex() if raw and raw_bytes is not None else None,
    )


@router.get("/sessions/{session_id}/packets/{packet_id}", response_model=PacketOut)
def session_packet(
    request: Request,
    session_id: str,
    packet_id: int,
    raw: bool = Query(default=False),
) -> PacketOut:
    """Fetch a packet scoped to a session.

    Packet ids are unique per session (``(session_id, id)`` constraint), so
    the session path addresses the object unambiguously.
    """
    session = get_session(request, session_id)
    found = session.packet(packet_id)
    if found is None:
        raise HTTPException(
            status_code=404,
            detail=f"packet not found: {packet_id} (session {session_id})",
        )
    row, raw_bytes = found
    return _packet_out(row, raw_bytes, raw)


@router.get("/packets/{packet_id}", response_model=PacketOut, deprecated=True)
def packet_detail(
    request: Request,
    packet_id: int,
    raw: bool = Query(default=False),
) -> PacketOut:
    """Legacy cross-session lookup (deprecated).

    Prefer ``GET /sessions/{session_id}/packets/{packet_id}``: bare ids can
    collide between capture sessions, so this route scans every session.
    """
    for session_id in [i.session_id for i in request.app.state.service.list_sessions()]:
        found = get_session(request, session_id).packet(packet_id)
        if found is not None:
            row, raw_bytes = found
            return _packet_out(row, raw_bytes, raw)
    raise HTTPException(status_code=404, detail=f"packet not found: {packet_id}")
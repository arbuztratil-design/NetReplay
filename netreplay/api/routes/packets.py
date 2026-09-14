"""Packet endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from netreplay.api.routes import get_session
from netreplay.api.schemas import PacketOut

router = APIRouter(tags=["packets"])


@router.get("/packets/{packet_id}", response_model=PacketOut)
def packet_detail(
    request: Request,
    packet_id: int,
    raw: bool = Query(default=False),
) -> PacketOut:
    """Fetch a packet. Searches every session in the workspace.

    ``?raw=true`` additionally returns the raw bytes as hex.
    """
    found = None
    for session_id in [i.session_id for i in request.app.state.service.list_sessions()]:
        found = get_session(request, session_id).packet(packet_id)
        if found is not None:
            break
    if found is None:
        raise HTTPException(status_code=404, detail=f"packet not found: {packet_id}")
    row, raw_bytes = found
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
        raw_hex=raw_bytes.hex() if raw else None,
    )
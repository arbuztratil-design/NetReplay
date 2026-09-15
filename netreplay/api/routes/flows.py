"""Flow endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from netreplay.api.routes import get_session
from netreplay.api.schemas import FlowOut, PacketOut
from netreplay.core.storage.database import FlowRow, PacketRow

router = APIRouter(tags=["flows"])


def _flow_out(row: FlowRow, packets: list[PacketRow] | None = None) -> FlowOut:
    return FlowOut(
        id=row.id,
        source=row.source,
        destination=row.destination,
        protocol=row.protocol,
        src_port=row.src_port,
        dst_port=row.dst_port,
        start_ts=row.start_ts,
        end_ts=row.end_ts,
        packet_count=row.packet_count,
        bytes=row.bytes,
        state=row.state,
        packets=[_packet_out(p) for p in packets] if packets else [],
    )


def _packet_out(p: PacketRow) -> PacketOut:
    return PacketOut(
        id=p.id,
        ts=p.ts,
        source=p.source,
        destination=p.destination,
        protocol=p.protocol,
        src_port=p.src_port,
        dst_port=p.dst_port,
        length=p.length,
        flow_id=p.flow_id,
    )


def _render(flow_id: int, row: FlowRow, session, include_packets: bool, packets_limit: int) -> FlowOut:
    packets = None
    if include_packets:
        packets = session.packets_for_flow(flow_id, limit=packets_limit)
    return _flow_out(row, packets)


@router.get("/sessions/{session_id}/flows", response_model=list[FlowOut])
def session_flows(
    request: Request,
    session_id: str,
    sort: str = Query(default="start_ts", enum=["start_ts", "bytes", "packets"]),
) -> list[FlowOut]:
    session = get_session(request, session_id)
    return [_flow_out(row) for row in session.flows(sort=sort)]


@router.get("/sessions/{session_id}/flows/{flow_id}", response_model=FlowOut)
def session_flow(
    request: Request,
    session_id: str,
    flow_id: int,
    include_packets: bool = Query(default=False),
    packets_limit: int = Query(default=500, ge=1, le=10_000),
) -> FlowOut:
    """Fetch a flow scoped to a session.

    Flow ids are unique per session (``(session_id, id)`` constraint), so the
    session path addresses the object unambiguously.
    """
    session = get_session(request, session_id)
    row = session.flow(flow_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"flow not found: {flow_id} (session {session_id})",
        )
    return _render(flow_id, row, session, include_packets, packets_limit)


@router.get("/flows/{flow_id}", response_model=FlowOut, deprecated=True)
def flow_detail(
    request: Request,
    flow_id: int,
    include_packets: bool = Query(default=False),
    packets_limit: int = Query(default=500, ge=1, le=10_000),
) -> FlowOut:
    """Legacy cross-session lookup (deprecated).

    Prefer ``GET /sessions/{session_id}/flows/{flow_id}``: bare ids can
    collide between capture sessions, so this route scans every session.
    """
    for session_id in _session_ids(request):
        session = get_session(request, session_id)
        row = session.flow(flow_id)
        if row is None:
            continue
        return _render(flow_id, row, session, include_packets, packets_limit)
    raise HTTPException(status_code=404, detail=f"flow not found: {flow_id}")


def _session_ids(request: Request) -> list[str]:
    return [info.session_id for info in request.app.state.service.list_sessions()]
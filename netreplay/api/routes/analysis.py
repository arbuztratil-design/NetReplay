"""Analysis endpoints: display filters, packet layer tree, packet loss (#25, #24, #30)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from netreplay.api.routes import get_session

router = APIRouter(tags=["analysis"])


@router.get("/sessions/{session_id}/filter")
def filter_session(
    request: Request,
    session_id: str,
    expr: str = Query(..., description="display filter expression"),
    kind: str = Query(default="flows", pattern="^(flows|packets|events)$"),
    limit: int = Query(default=500, ge=1, le=100_000),
) -> dict:
    """Evaluate a display-filter expression server-side (#25)."""
    from netreplay.core.display_filter import FilterError, compile_filter

    session = get_session(request, session_id)
    try:
        flt = compile_filter(expr)
    except FilterError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if kind == "flows":
        rows = session.flows()[:limit]
    elif kind == "packets":
        page, _total = session.packets_page(limit=limit, offset=0)
        rows = page
    else:
        rows = session.events(limit=limit)

    selected = flt.select(rows)
    return {
        "expr": expr,
        "kind": kind,
        "count": len(selected),
        "ids": [
            getattr(row, "id", None) for row in selected
        ],
    }


@router.get("/sessions/{session_id}/packets/{packet_id}/layers")
def packet_layers(request: Request, session_id: str, packet_id: int) -> dict:
    """Protocol layer tree for one packet (#24), plus raw/hex (#23)."""
    from netreplay.core.packets.parser import parse_packet
    from netreplay.core.viewers.inspectors import layer_tree, raw_hex

    session = get_session(request, session_id)
    found = session.packet(packet_id)
    if found is None:
        raise HTTPException(status_code=404, detail=f"packet not found: {packet_id}")
    row, raw = found
    parsed = parse_packet(raw, ts=row.ts)
    tree = layer_tree(parsed)
    hexview = raw_hex(raw)

    def node_to_dict(node) -> dict:
        return {
            "name": node.name,
            "fields": {k: (str(v) if v is not None else None) for k, v in node.fields.items()},
            "children": [node_to_dict(child) for child in node.children],
        }

    return {
        "packet_id": packet_id,
        "layers": node_to_dict(tree),
        "size": hexview.size,
        "hex": [
            {"offset": r.offset, "hex": r.hex_bytes, "ascii": r.ascii}
            for r in hexview.rows
        ],
    }


@router.get("/sessions/{session_id}/loss")
def session_loss(request: Request, session_id: str) -> dict:
    """Packet-loss markers from stream gaps/retransmissions/overlaps (#30)."""
    from netreplay.core.loss import detect_loss

    report = detect_loss(get_session(request, session_id))
    return {
        "total": report.total,
        "gaps": report.gap_count,
        "retransmissions": report.retransmission_count,
        "overlaps": report.overlap_count,
        "duration": report.duration,
        "markers": [
            {
                "flow_id": m.flow_id,
                "start_ts": m.start_ts,
                "end_ts": m.end_ts,
                "severity": m.severity,
                "detail": m.detail,
            }
            for m in report.markers
        ],
    }

"""Forensics endpoints: compare, incidents, export, sanitize (#41-50)."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from netreplay.api.routes import get_session

router = APIRouter(tags=["forensics"])


@router.get("/sessions/{session_id}/compare/{other_id}")
def compare_sessions(request: Request, session_id: str, other_id: str) -> dict:
    """A/B comparison of two captures (#41-44)."""
    from netreplay.core.compare import compare_captures

    a = get_session(request, session_id)
    b = get_session(request, other_id)
    report = compare_captures(a, b)
    return {
        "identical": report.identical,
        "flows": {
            "added": len(report.flow_diff.added),
            "removed": len(report.flow_diff.removed),
            "changed": len(report.flow_diff.changed),
        },
        "timing": {
            "duration_before": report.timing_diff.duration_before,
            "duration_after": report.timing_diff.duration_after,
            "duration_delta": report.timing_diff.duration_delta,
        },
        "events": [
            {"type": d.event_type, "before": d.before, "after": d.after, "delta": d.delta}
            for d in report.event_diff.deltas
        ],
    }


@router.get("/sessions/{session_id}/incidents")
def session_incidents(
    request: Request,
    session_id: str,
    top: int = Query(default=5, ge=1, le=100),
) -> list[dict]:
    """Find behaviourally similar incidents in the workspace (#45-46)."""
    from netreplay.core.incidents import find_similar_incidents

    session = get_session(request, session_id)
    workspace = request.app.state.service.workspace
    try:
        matches = find_similar_incidents(session.path, workspace=workspace, top=top)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return [
        {"session_id": m.session_id, "name": m.name, "score": m.score}
        for m in matches
    ]


@router.get("/sessions/{session_id}/export", response_class=PlainTextResponse)
def export_session_text(
    request: Request,
    session_id: str,
    format: str = Query(default="json", pattern="^(json|ndjson|csv)$"),
    kind: str = Query(default="packets", pattern="^(packets|flows)$"),
) -> PlainTextResponse:
    """Export a session inline as JSON/NDJSON/CSV (#48)."""
    from netreplay.core.export import session_to_dict

    session = get_session(request, session_id)
    if format == "json":
        return PlainTextResponse(
            json.dumps(session_to_dict(session), indent=2, ensure_ascii=False),
            media_type="application/json",
        )
    if format == "ndjson":
        buffer = io.StringIO()
        for row in session.packets():
            buffer.write(json.dumps({
                "id": row.id, "ts": row.ts, "source": row.source,
                "destination": row.destination, "protocol": row.protocol,
                "src_port": row.src_port, "dst_port": row.dst_port,
                "length": row.length, "flow_id": row.flow_id,
            }))
            buffer.write("\n")
        return PlainTextResponse(buffer.getvalue(), media_type="application/x-ndjson")

    buffer = io.StringIO()
    if kind == "flows":
        fieldnames = ["id", "source", "destination", "protocol", "src_port",
                      "dst_port", "start_ts", "end_ts", "packet_count", "bytes", "state"]
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        for flow in session.flows():
            writer.writerow({
                "id": flow.id, "source": flow.source, "destination": flow.destination,
                "protocol": flow.protocol, "src_port": flow.src_port,
                "dst_port": flow.dst_port, "start_ts": flow.start_ts, "end_ts": flow.end_ts,
                "packet_count": flow.packet_count, "bytes": flow.bytes, "state": flow.state,
            })
    else:
        fieldnames = ["id", "ts", "source", "destination", "protocol",
                      "src_port", "dst_port", "length", "flow_id"]
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        for row in session.packets():
            writer.writerow({
                "id": row.id, "ts": row.ts, "source": row.source,
                "destination": row.destination, "protocol": row.protocol,
                "src_port": row.src_port, "dst_port": row.dst_port,
                "length": row.length, "flow_id": row.flow_id,
            })
    return PlainTextResponse(buffer.getvalue(), media_type="text/csv")


@router.post("/sessions/{session_id}/sanitize")
def sanitize_capture(request: Request, session_id: str) -> dict:
    """Create a redacted copy of a capture in the workspace (#47)."""
    from netreplay.core.sanitize import sanitize_session

    session = get_session(request, session_id)
    workspace = Path(request.app.state.service.workspace)
    output = workspace / f"sanitized-{session_id}.nrp"
    report = sanitize_session(session.path, output)
    return {
        "output": str(output),
        "flows": report.flows,
        "packets": report.packets,
        "events": report.events,
        "redacted": report.mapping_summary(),
    }


@router.post("/regression/run")
def run_regression_cases(request: Request, payload: dict) -> dict:
    """Run regression checks from an inline case list (#50)."""
    from netreplay.core.regression import (
        Expectations,
        RegressionCase,
        run_regression,
    )

    raw_cases = payload.get("cases") or []
    workspace = Path(request.app.state.service.workspace)
    cases = [
        RegressionCase(
            name=item.get("name") or item.get("session", "case"),
            session_path=workspace / item["session"],
            expect=Expectations.from_dict(item.get("expect", {})),
        )
        for item in raw_cases
    ]
    report = run_regression(cases)
    return {
        "passed": report.passed,
        "failed": report.failed,
        "ok": report.ok,
        "results": [
            {
                "name": r.name,
                "passed": r.passed,
                "error": r.error,
                "checks": [
                    {"name": c.name, "passed": c.passed, "detail": c.detail}
                    for c in r.checks
                ],
            }
            for r in report.results
        ],
    }

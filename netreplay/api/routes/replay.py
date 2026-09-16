"""Replay-out control endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from netreplay.api.schemas import ReplayStartIn, ReplayStatusOut
from netreplay.core.capture.base import CaptureError
from netreplay.core.replay.mutation import (
    MutationPipeline,
    PadToLength,
    ReplacePattern,
    TruncatePayload,
)
from netreplay.core.replay.remap import RemapConfig
from netreplay.core.replay.selection import ReplaySelection
from netreplay.core.replay.timing import ReplayMode
from netreplay.core.service import ReplayOutController

router = APIRouter(tags=["replay"])


def _build_pipeline(items: list[dict]) -> MutationPipeline | None:
    if not items:
        return None
    pipeline = MutationPipeline()
    for item in items:
        kind = item.get("type")
        if kind == "truncate":
            pipeline.add(TruncatePayload(int(item["max_length"])))
        elif kind == "replace":
            pipeline.add(ReplacePattern(str(item["old"]).encode(), str(item["new"]).encode()))
        elif kind == "pad":
            pipeline.add(PadToLength(int(item["length"])))
        else:
            raise ValueError(f"unknown mutation: {kind!r}")
    return pipeline


def _build_remap(body: ReplayStartIn) -> RemapConfig | None:
    if not (body.mac_map or body.ip_map or body.port_map):
        return None
    return RemapConfig.build(
        mac_map=body.mac_map or None,
        ip_map=body.ip_map or None,
        port_map={int(k): int(v) for k, v in body.port_map.items()} or None,
    )


def _status_out(controller: ReplayOutController | None) -> ReplayStatusOut:
    if controller is None:
        return ReplayStatusOut(running=False)
    status = controller.status()
    return ReplayStatusOut(
        running=controller.running,
        session_id=controller.session_id,
        interface=controller.interface,
        dry_run=controller.dry_run,
        packets=status.packets,
        bytes=status.bytes,
        duration=status.duration,
        stopped=status.stopped,
        error=status.error,
        skipped=status.skipped,
        failed=status.failed,
        timing_drift=status.timing_drift,
        mode=status.mode,
    )


@router.post("/replay-out/stop", response_model=ReplayStatusOut)
def replay_stop(request: Request) -> ReplayStatusOut:
    service = request.app.state.service
    service.stop_replay()
    return _status_out(service.replay)


@router.post("/replay-out/{session_id}", response_model=ReplayStatusOut)
def replay_start(request: Request, session_id: str, body: ReplayStartIn) -> ReplayStatusOut:
    service = request.app.state.service
    try:
        selection = ReplaySelection.from_values(
            packet_ids=body.packet_ids,
            flow_ids=body.flow_ids,
            start_ts=body.start_ts,
            end_ts=body.end_ts,
        )
        controller = service.start_replay(
            session_id=session_id,
            interface=body.interface,
            speed=body.speed,
            max_gap=body.max_gap,
            dry_run=body.dry_run,
            offset=body.offset,
            limit=body.limit,
            mode=ReplayMode(body.mode),
            selection=selection,
            validate=body.validate_frames,
            remap=_build_remap(body),
            pipeline=_build_pipeline(body.mutations),
        )
    except CaptureError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _status_out(controller)


@router.get("/replay-out/status", response_model=ReplayStatusOut)
def replay_status(request: Request) -> ReplayStatusOut:
    return _status_out(request.app.state.service.replay)

"""Replay-out control endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from netreplay.api.schemas import ReplayStartIn, ReplayStatusOut
from netreplay.core.capture.base import CaptureError
from netreplay.core.service import ReplayOutController

router = APIRouter(tags=["replay"])


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
        controller = service.start_replay(
            session_id=session_id,
            interface=body.interface,
            speed=body.speed,
            max_gap=body.max_gap,
            dry_run=body.dry_run,
            offset=body.offset,
            limit=body.limit,
        )
    except CaptureError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _status_out(controller)


@router.get("/replay-out/status", response_model=ReplayStatusOut)
def replay_status(request: Request) -> ReplayStatusOut:
    return _status_out(request.app.state.service.replay)

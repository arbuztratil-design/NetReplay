"""Live L2 bridge control endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from netreplay.api.schemas import BridgeStartIn, BridgeStatusOut
from netreplay.core.capture.base import CaptureError
from netreplay.core.service import BridgeController

router = APIRouter(tags=["bridge"])


def _status_out(controller: BridgeController | None) -> BridgeStatusOut:
    if controller is None:
        return BridgeStatusOut(running=False)
    status = controller.status
    return BridgeStatusOut(
        running=controller.running,
        left_interface=controller.left_interface,
        right_interface=controller.right_interface,
        left_forwarded=status.left_forwarded,
        right_forwarded=status.right_forwarded,
        left_bytes=status.left_bytes,
        right_bytes=status.right_bytes,
        errors=status.errors,
        stopped=status.stopped,
        error=status.error,
        duration=status.duration,
    )


@router.post("/bridge/start", response_model=BridgeStatusOut)
def bridge_start(request: Request, body: BridgeStartIn) -> BridgeStatusOut:
    service = request.app.state.service
    try:
        controller = service.start_bridge(
            left_interface=body.left_interface,
            right_interface=body.right_interface,
        )
    except CaptureError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _status_out(controller)


@router.post("/bridge/stop", response_model=BridgeStatusOut)
def bridge_stop(request: Request) -> BridgeStatusOut:
    service = request.app.state.service
    status = service.stop_bridge()
    return BridgeStatusOut(
        running=False,
        left_forwarded=status.left_forwarded,
        right_forwarded=status.right_forwarded,
        left_bytes=status.left_bytes,
        right_bytes=status.right_bytes,
        errors=status.errors,
        stopped=status.stopped,
        error=status.error,
        duration=status.duration,
    )


@router.get("/bridge/status", response_model=BridgeStatusOut)
def bridge_status(request: Request) -> BridgeStatusOut:
    return _status_out(request.app.state.service.bridge)

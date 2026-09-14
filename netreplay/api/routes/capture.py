"""Capture control endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from netreplay.api.schemas import (
    CaptureStartIn,
    CaptureStatusOut,
    InterfaceOut,
    LiveEvent,
)
from netreplay.core.capture.base import CaptureError
from netreplay.core.service import CaptureController

router = APIRouter(tags=["capture"])


def _status_out(controller: CaptureController | None) -> CaptureStatusOut:
    if controller is None:
        return CaptureStatusOut(running=False)
    status = controller.status()
    return CaptureStatusOut(**{
        "running": status.running,
        "interface": status.interface,
        "output": status.output,
        "session_id": status.session_id,
        "packets": status.packets,
        "flows": status.flows,
        "started_at": status.started_at,
        "error": status.error,
    })


def _make_pusher(request: Request):
    """Build a callback that feeds capture events onto the WS broadcast loop."""
    loop = request.app.state.loop
    queue = request.app.state.event_queue

    def on_event(event) -> None:
        payload = LiveEvent(
            timestamp=event.timestamp,
            flow_id=event.flow_id,
            protocol=event.type,
            summary=event.summary,
        ).model_dump()
        loop.call_soon_threadsafe(queue.put_nowait, payload)

    return on_event


@router.post("/capture/start", response_model=CaptureStatusOut)
def capture_start(request: Request, body: CaptureStartIn) -> CaptureStatusOut:
    service = request.app.state.service
    try:
        controller = service.start_capture(
            interface=body.interface,
            output=body.output,
            on_event=_make_pusher(request),
        )
    except CaptureError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _status_out(controller)


@router.post("/capture/stop", response_model=CaptureStatusOut)
def capture_stop(request: Request) -> CaptureStatusOut:
    service = request.app.state.service
    status = service.stop_capture()
    return CaptureStatusOut(**{
        "running": status.running,
        "interface": status.interface,
        "output": status.output,
        "session_id": status.session_id,
        "packets": status.packets,
        "flows": status.flows,
        "started_at": status.started_at,
        "error": status.error,
    })


@router.get("/capture/status", response_model=CaptureStatusOut)
def capture_status(request: Request) -> CaptureStatusOut:
    return _status_out(request.app.state.service.capture)


@router.get("/interfaces", response_model=list[InterfaceOut])
def list_interfaces() -> list[InterfaceOut]:
    from netreplay.core.capture.scapy_backend import list_interfaces as list_ifaces

    return [InterfaceOut(name=i.name, description=i.description) for i in list_ifaces()]
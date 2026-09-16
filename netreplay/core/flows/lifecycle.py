"""Flow lifecycle events (#29).

Maps the coarse TCP states produced by :class:`TcpStateMachine` onto the four
analyst-facing lifecycle phases OPEN / ACTIVE / HALF-CLOSED / CLOSED and turns
state transitions into timeline events, so a flow's life is visible on the
timeline alongside DNS/TLS/HTTP events.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from netreplay.core.flows.models import Flow


class FlowPhase(str, Enum):
    OPEN = "open"
    ACTIVE = "active"
    HALF_CLOSED = "half-closed"
    CLOSED = "closed"


# TCP state -> lifecycle phase. ``None`` means "no phase change yet".
_STATE_PHASE: dict[str, FlowPhase | None] = {
    "NONE": None,
    "SYN": FlowPhase.OPEN,
    "SYN/ACK": FlowPhase.OPEN,
    "ACK": FlowPhase.OPEN,
    "ESTABLISHED": FlowPhase.ACTIVE,
    "FIN": FlowPhase.HALF_CLOSED,
    "CLOSED": FlowPhase.CLOSED,
    "RST": FlowPhase.CLOSED,
}

_EVENT_TYPE: dict[FlowPhase, str] = {
    FlowPhase.OPEN: "FLOW_OPEN",
    FlowPhase.ACTIVE: "FLOW_ACTIVE",
    FlowPhase.HALF_CLOSED: "FLOW_HALF_CLOSED",
    FlowPhase.CLOSED: "FLOW_CLOSED",
}


@dataclass(slots=True)
class LifecycleEvent:
    ts: float
    flow_id: int
    phase: FlowPhase
    event_type: str
    summary: str


def phase_for_state(state: str) -> FlowPhase | None:
    """Lifecycle phase for a TCP state string (``None`` for NONE/unknown)."""
    return _STATE_PHASE.get((state or "NONE").upper())


def flow_phase(flow: Flow) -> FlowPhase | None:
    """Current lifecycle phase of a flow from its final state."""
    return phase_for_state(flow.state)


def _endpoint(host: str, port: int | None) -> str:
    return f"{host}:{port}" if port is not None else host


def lifecycle_transitions(
    flow: Flow, previous_state: str, new_state: str, ts: float
) -> list[LifecycleEvent]:
    """Events emitted when a flow moves from *previous_state* to *new_state*.

    A transition that stays within the same phase (e.g. SYN -> ACK) emits
    nothing; only phase changes become timeline events.
    """
    if previous_state == new_state:
        return []
    previous_phase = phase_for_state(previous_state)
    new_phase = phase_for_state(new_state)
    if new_phase is None or new_phase == previous_phase:
        return []
    src = _endpoint(flow.source, flow.src_port)
    dst = _endpoint(flow.destination, flow.dst_port)
    return [
        LifecycleEvent(
            ts=ts,
            flow_id=flow.id or 0,
            phase=new_phase,
            event_type=_EVENT_TYPE[new_phase],
            summary=f"{flow.protocol} {src} -> {dst} {new_phase.value}",
        )
    ]


def flow_lifecycle_events(
    flow: Flow, transitions: list[tuple[float, str, str]]
) -> list[LifecycleEvent]:
    """Build lifecycle events for a flow from ``(ts, prev_state, new_state)``."""
    events: list[LifecycleEvent] = []
    for ts, previous, new in transitions:
        events.extend(lifecycle_transitions(flow, previous, new, ts))
    return events

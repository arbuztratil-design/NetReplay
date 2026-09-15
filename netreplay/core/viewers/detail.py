"""P1 #21: packet detail viewer — full inspection of a single packet.

Takes a session's event graphs / packet rows and projects a self-contained,
human-reviewable detail card for one packet: raw summary, kind, the flow +
flow params it participates in, its parent/child events (the events it gave
rise to), and protocol metadata. Pure projection — no writes to the session.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from netreplay.core.events.models import EventGraph, NetworkEvent


@dataclass(slots=True)
class PacketDetailView:
    """Everything a reviewer wants about a single packet, in one object."""

    packet_id: int
    session_id: str
    kind_value: str
    summary: str
    ts: float
    flow_id: str | None = None
    flow_params: dict[str, Any] = field(default_factory=dict)
    upstream: list[NetworkEvent] = field(default_factory=list)
    downstream: list[NetworkEvent] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    has_error: bool = False


def packet_detail(
    graph: EventGraph,
    packet_id: int,
    session_id: str | None = None,
) -> PacketDetailView | None:
    """Project the detail card for ``packet_id`` from the event graph.

    Returns ``None`` when no event in the graph references that packet.
    """
    events = graph.for_packet(packet_id, session_id=session_id)
    if not events:
        return None

    first = events[0]
    flow_id = first.flow_id
    upstream: list[NetworkEvent] = []
    downstream: list[NetworkEvent] = []
    err = False
    for ev in events:
        if ev.kind.value == "error":
            err = True
        if ev.parent_id is not None:
            parent = graph.get(ev.parent_id)
            if parent is not None:
                upstream.append(parent)
        downstream.extend(graph.children(ev.id))

    flow_params: dict[str, Any] = {}
    if flow_id is not None:
        flow_params = graph.flow_params(flow_id)

    meta = dict(first.params)
    meta["session_id"] = first.session_id

    return PacketDetailView(
        packet_id=packet_id,
        session_id=first.session_id,
        kind_value=first.kind.value,
        summary=first.summary,
        ts=first.ts,
        flow_id=flow_id,
        flow_params=flow_params,
        upstream=_dedupe(upstream),
        downstream=_dedupe(downstream),
        metadata=meta,
        has_error=err,
    )


def _dedupe(events: list[NetworkEvent]) -> list[NetworkEvent]:
    seen: set[str] = set()
    out: list[NetworkEvent] = []
    for ev in events:
        if ev.id not in seen:
            seen.add(ev.id)
            out.append(ev)
    return out

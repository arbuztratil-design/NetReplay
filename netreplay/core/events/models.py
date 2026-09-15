"""Event graph domain (#19-20): one graph where every DNS/TLS/HTTP/error
event is a node linked to the flow and packet that produced it.

Design: nodes are immutable events; edges express derivation (a TLS event
derived from a packet). The same graph feeds the Timeline projection (#20)
and the replay engine, so there is a single source of truth.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventKind(str, Enum):
    """Protocol-agnostic event kinds composing the event graph."""

    DNS = "dns"
    TLS = "tls"
    HTTP = "http"
    ERROR = "error"


def _now_ms() -> float:
    return time.time() * 1000.0


@dataclass(slots=True)
class NetworkEvent:
    """A node in the event graph.

    ``flow_id``/``packet_id`` are the references (edges) back to the session's
    own flow/packet tables, keeping the graph co-located with its data.
    """

    ts: float
    kind: EventKind
    summary: str
    session_id: str = ""
    flow_id: str | None = None
    packet_id: int | None = None
    params: dict[str, Any] = field(default_factory=dict)
    parent_id: str | None = None
    id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")


@dataclass(slots=True)
class EventGraph:
    """Directed a-cyclic graph of NetworkEvent nodes (edges = parent_id)."""

    session_id: str
    events: list[NetworkEvent] = field(default_factory=list)
    by_id: dict[str, NetworkEvent] = field(default_factory=dict)

    def add(self, event: NetworkEvent) -> NetworkEvent:
        if event.parent_id is not None and event.parent_id not in self.by_id:
            raise KeyError(f"unknown parent event {event.parent_id!r}")
        self.events.append(event)
        self.by_id[event.id] = event
        return event

    def children(self, event_id: str) -> list[NetworkEvent]:
        parent = self.by_id[event_id]
        return [e for e in self.events if e.parent_id == parent.id]

    def roots(self) -> list[NetworkEvent]:
        return [e for e in self.events if e.parent_id is None]

    def timeline(self) -> list[NetworkEvent]:
        """#20: the timeline is just this graph ordered by timestamp."""
        return sorted(self.events, key=lambda e: (e.ts, e.id))


    def for_packet(self, packet_id: int, session_id: str | None = None) -> list[NetworkEvent]:
        """Portrait of one packet: every event whose packet_id matches (#21)."""
        if session_id is None:
            return [e for e in self.events if e.packet_id == packet_id]
        return [e for e in self.events
                if e.packet_id == packet_id and e.session_id == session_id]

    def ancestors(self, event_id: str) -> list[NetworkEvent]:
        """Parent chain (oldest first): the events that produced this one."""
        chain: list[NetworkEvent] = []
        cur = self.by_id.get(event_id)
        seen: set[str] = set()
        while cur is not None and cur.parent_id is not None:
            if cur.parent_id in seen:
                break
            seen.add(cur.parent_id)
            parent = self.by_id.get(cur.parent_id)
            if parent is None:
                break
            chain.append(parent)
            cur = parent
        chain.reverse()
        return chain

    def descendants(self, event_id: str) -> list[NetworkEvent]:
        """Recursive children, depth-first, ts-ordered (#20 projection base)."""
        out: list[NetworkEvent] = []
        stack = list(reversed(self.children(event_id)))
        seen: set[str] = set()
        while stack:
            ev = stack.pop()
            if ev.id in seen:
                continue
            seen.add(ev.id)
            out.append(ev)
            stack.extend(reversed(self.children(ev.id)))
        out.sort(key=lambda e: e.ts)
        return out

    def for_flow(self, flow_id: str) -> list[NetworkEvent]:
        return [e for e in self.events if e.flow_id == flow_id]

    def get(self, event_id: str) -> NetworkEvent | None:
        return self.by_id.get(event_id)

    def flow_params(self, flow_id: str) -> dict:
        """Merge all events' params of one flow into one dict (detail #21)."""
        merged: dict = {}
        for e in self.events:
            if e.flow_id == flow_id:
                merged.update(e.params or {})
        return merged

    def kinds(self) -> dict[EventKind, int]:
        counts: dict[EventKind, int] = {}
        for e in self.events:
            counts[e.kind] = counts.get(e.kind, 0) + 1
        return counts

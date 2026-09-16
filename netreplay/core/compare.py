"""Capture A/B comparison (#41-44).

Compares two stored sessions along three independent axes:

* **flow diff (#42)** — which flows appeared, disappeared or changed size;
* **timing diff (#43)** — duration / latency / pacing changes;
* **protocol-event diff (#44)** — how DNS/TLS/HTTP event counts moved.

:func:`compare_captures` combines all three into one report (#41).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from netreplay.core.storage import SessionStorage
from netreplay.core.storage.database import EventRow, FlowRow


def _endpoint_key(flow: FlowRow) -> tuple:
    """Direction-independent identity for matching flows across captures."""
    a = (flow.source or "", flow.src_port or 0)
    b = (flow.destination or "", flow.dst_port or 0)
    if a > b:
        a, b = b, a
    return (flow.protocol or "", a[0], int(a[1]), b[0], int(b[1]))


@dataclass(slots=True)
class FlowDelta:
    key: tuple
    status: str  # "added" | "removed" | "changed" | "unchanged"
    packets_before: int = 0
    packets_after: int = 0
    bytes_before: int = 0
    bytes_after: int = 0
    state_before: str = ""
    state_after: str = ""

    @property
    def packet_delta(self) -> int:
        return self.packets_after - self.packets_before

    @property
    def byte_delta(self) -> int:
        return self.bytes_after - self.bytes_before


@dataclass(slots=True)
class FlowDiff:
    deltas: list[FlowDelta] = field(default_factory=list)

    def by_status(self, status: str) -> list[FlowDelta]:
        return [d for d in self.deltas if d.status == status]

    @property
    def added(self) -> list[FlowDelta]:
        return self.by_status("added")

    @property
    def removed(self) -> list[FlowDelta]:
        return self.by_status("removed")

    @property
    def changed(self) -> list[FlowDelta]:
        return self.by_status("changed")


def compare_flows(a: SessionStorage, b: SessionStorage) -> FlowDiff:
    """Flow-level diff between two captures (#42)."""
    before = {_endpoint_key(f): f for f in a.flows()}
    after = {_endpoint_key(f): f for f in b.flows()}
    deltas: list[FlowDelta] = []
    for key in sorted(set(before) | set(after), key=repr):
        fb = before.get(key)
        fa = after.get(key)
        if fb is None and fa is not None:
            deltas.append(FlowDelta(
                key=key, status="added", packets_after=fa.packet_count,
                bytes_after=fa.bytes, state_after=fa.state,
            ))
        elif fa is None and fb is not None:
            deltas.append(FlowDelta(
                key=key, status="removed", packets_before=fb.packet_count,
                bytes_before=fb.bytes, state_before=fb.state,
            ))
        elif fa is not None and fb is not None:
            changed = (
                fa.packet_count != fb.packet_count
                or fa.bytes != fb.bytes
                or fa.state != fb.state
            )
            deltas.append(FlowDelta(
                key=key,
                status="changed" if changed else "unchanged",
                packets_before=fb.packet_count, packets_after=fa.packet_count,
                bytes_before=fb.bytes, bytes_after=fa.bytes,
                state_before=fb.state, state_after=fa.state,
            ))
    return FlowDiff(deltas=deltas)


@dataclass(slots=True)
class TimingDelta:
    key: tuple
    duration_before: float
    duration_after: float

    @property
    def duration_delta(self) -> float:
        return self.duration_after - self.duration_before


@dataclass(slots=True)
class TimingDiff:
    duration_before: float
    duration_after: float
    per_flow: list[TimingDelta] = field(default_factory=list)

    @property
    def duration_delta(self) -> float:
        return self.duration_after - self.duration_before


def _session_duration(session: SessionStorage) -> float:
    first, last = session.bounds()
    if first is None or last is None:
        return 0.0
    return max(0.0, last - first)


def compare_timing(a: SessionStorage, b: SessionStorage) -> TimingDiff:
    """Timing/latency diff between two captures (#43)."""
    before = {_endpoint_key(f): f for f in a.flows()}
    after = {_endpoint_key(f): f for f in b.flows()}
    per_flow: list[TimingDelta] = []
    for key in sorted(set(before) & set(after), key=repr):
        fb = before[key]
        fa = after[key]
        per_flow.append(TimingDelta(
            key=key,
            duration_before=max(0.0, fb.end_ts - fb.start_ts),
            duration_after=max(0.0, fa.end_ts - fa.start_ts),
        ))
    return TimingDiff(
        duration_before=_session_duration(a),
        duration_after=_session_duration(b),
        per_flow=per_flow,
    )


def _event_counts(session: SessionStorage) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in session.events(limit=1_000_000):
        counts[row.event_type] = counts.get(row.event_type, 0) + 1
    return counts


@dataclass(slots=True)
class EventTypeDelta:
    event_type: str
    before: int
    after: int

    @property
    def delta(self) -> int:
        return self.after - self.before


@dataclass(slots=True)
class EventDiff:
    deltas: list[EventTypeDelta] = field(default_factory=list)

    def get(self, event_type: str) -> EventTypeDelta | None:
        for delta in self.deltas:
            if delta.event_type == event_type:
                return delta
        return None


def compare_events(a: SessionStorage, b: SessionStorage) -> EventDiff:
    """Protocol-event diff (DNS/TLS/HTTP/...) between two captures (#44)."""
    before = _event_counts(a)
    after = _event_counts(b)
    deltas = [
        EventTypeDelta(event_type=etype, before=before.get(etype, 0), after=after.get(etype, 0))
        for etype in sorted(set(before) | set(after))
    ]
    return EventDiff(deltas=deltas)


@dataclass(slots=True)
class CaptureComparison:
    flow_diff: FlowDiff
    timing_diff: TimingDiff
    event_diff: EventDiff

    @property
    def identical(self) -> bool:
        flows_same = not (self.flow_diff.added or self.flow_diff.removed or self.flow_diff.changed)
        events_same = all(d.delta == 0 for d in self.event_diff.deltas)
        return flows_same and events_same


def compare_captures(a: SessionStorage, b: SessionStorage) -> CaptureComparison:
    """Full A/B comparison of two captures (#41)."""
    return CaptureComparison(
        flow_diff=compare_flows(a, b),
        timing_diff=compare_timing(a, b),
        event_diff=compare_events(a, b),
    )

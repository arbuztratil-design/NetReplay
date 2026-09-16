"""Packet-loss visualization (#30).

Structural TCP findings (gaps, retransmissions, overlaps) are already stored
as timeline events by the reassembly layer. This module turns them into
explicit :class:`LossMarker` spans so the GUI can draw gaps directly on the
timeline and analysts get a headline loss figure.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from netreplay.core.storage import SessionStorage

_GAP_TYPES = ("STREAM_GAP", "STREAM_RETRANSMISSION", "STREAM_OVERLAP")

_SEVERITY = {
    "STREAM_GAP": "gap",
    "STREAM_RETRANSMISSION": "retransmission",
    "STREAM_OVERLAP": "overlap",
}


@dataclass(slots=True)
class LossMarker:
    """A missing/duplicated region on the timeline for one flow."""

    flow_id: int | None
    start_ts: float
    end_ts: float
    severity: str
    detail: str

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)


@dataclass(slots=True)
class LossReport:
    markers: list[LossMarker] = field(default_factory=list)
    duration: float = 0.0

    @property
    def total(self) -> int:
        return len(self.markers)

    @property
    def gap_count(self) -> int:
        return sum(1 for m in self.markers if m.severity == "gap")

    @property
    def retransmission_count(self) -> int:
        return sum(1 for m in self.markers if m.severity == "retransmission")

    @property
    def overlap_count(self) -> int:
        return sum(1 for m in self.markers if m.severity == "overlap")

    @property
    def has_loss(self) -> bool:
        return bool(self.markers)


def _to_markers(rows) -> list[LossMarker]:
    """Pair consecutive findings on the same flow into spans.

    Each finding starts a span that runs until the next finding on that flow
    (or the finding's own timestamp when it is the last one), which is exactly
    what the timeline needs to shade a lost region.
    """
    by_flow: dict[int | None, list] = {}
    for row in rows:
        by_flow.setdefault(row.flow_id, []).append(row)

    markers: list[LossMarker] = []
    for flow_id, events in by_flow.items():
        events = sorted(events, key=lambda r: (r.ts, r.id))
        for index, event in enumerate(events):
            end_ts = (
                events[index + 1].ts if index + 1 < len(events) else event.ts
            )
            markers.append(
                LossMarker(
                    flow_id=flow_id,
                    start_ts=event.ts,
                    end_ts=end_ts,
                    severity=_SEVERITY.get(event.event_type, "gap"),
                    detail=event.summary,
                )
            )
    markers.sort(key=lambda m: (m.start_ts, m.flow_id or 0))
    return markers


def detect_loss(session: SessionStorage) -> LossReport:
    """Scan a session for stream gaps/retransmissions/overlaps (#30)."""
    rows = session.events(types=list(_GAP_TYPES), limit=1_000_000)
    first_ts, last_ts = session.bounds()
    if first_ts is None or last_ts is None:
        if rows:
            timestamps = [row.ts for row in rows]
            first_ts, last_ts = min(timestamps), max(timestamps)
        else:
            first_ts = last_ts = None
    duration = (
        max(0.0, last_ts - first_ts)
        if first_ts is not None and last_ts is not None
        else 0.0
    )
    return LossReport(markers=_to_markers(rows), duration=duration)

"""Replay selection (#34): replay only part of a capture.

A :class:`ReplaySelection` narrows the frame stream by explicit packet ids,
by flow ids and/or by a capture time range. All dimensions are optional and
combine with AND, so ``ReplaySelection(flow_ids={3}, start_ts=100)`` replays
only flow 3 after t=100.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from netreplay.core.storage.database import PacketRow


@dataclass(frozen=True, slots=True)
class ReplaySelection:
    packet_ids: frozenset[int] | None = None
    flow_ids: frozenset[int] | None = None
    start_ts: float | None = None
    end_ts: float | None = None

    @classmethod
    def from_values(
        cls,
        packet_ids: list[int] | None = None,
        flow_ids: list[int] | None = None,
        start_ts: float | None = None,
        end_ts: float | None = None,
    ) -> "ReplaySelection":
        if start_ts is not None and end_ts is not None and end_ts < start_ts:
            raise ValueError("end_ts must not be before start_ts")
        return cls(
            packet_ids=frozenset(packet_ids) if packet_ids else None,
            flow_ids=frozenset(flow_ids) if flow_ids else None,
            start_ts=start_ts,
            end_ts=end_ts,
        )

    @property
    def is_unrestricted(self) -> bool:
        return (
            self.packet_ids is None
            and self.flow_ids is None
            and self.start_ts is None
            and self.end_ts is None
        )

    def matches(self, row: PacketRow) -> bool:
        if self.packet_ids is not None and row.id not in self.packet_ids:
            return False
        if self.flow_ids is not None and row.flow_id not in self.flow_ids:
            return False
        if self.start_ts is not None and row.ts < self.start_ts:
            return False
        if self.end_ts is not None and row.ts > self.end_ts:
            return False
        return True

    def select(self, rows: list[PacketRow]) -> list[PacketRow]:
        return [row for row in rows if self.matches(row)]

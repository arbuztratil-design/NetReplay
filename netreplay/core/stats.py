"""Aggregate session statistics (#28).

Read-only rollups computed from the stored flows/events: packet and byte
counts, flow/event totals, duration, per-second rates, average packet size,
TCP resets and stream retransmissions. Cheap enough to call on every status
poll because it only reads metadata rows.
"""
from __future__ import annotations

from dataclasses import dataclass

from netreplay.core.storage import SessionStorage

_RETRANSMISSION_TYPES = ("STREAM_RETRANSMISSION", "STREAM_OVERLAP")


@dataclass(slots=True)
class SessionStats:
    packet_count: int
    byte_count: int
    flow_count: int
    event_count: int
    duration: float
    packets_per_second: float
    bytes_per_second: float
    average_packet_size: float
    reset_count: int
    retransmission_count: int

    @property
    def has_traffic(self) -> bool:
        return self.packet_count > 0


def compute_stats(session: SessionStorage) -> SessionStats:
    """Aggregate statistics for one stored session."""
    info = session.info()
    flows = session.flows()
    byte_count = sum(flow.bytes for flow in flows)
    flow_packets = sum(flow.packet_count for flow in flows)
    packet_count = session.packet_count()
    if packet_count == 0:
        packet_count = flow_packets
    reset_count = sum(1 for flow in flows if flow.state == "RST")

    first_ts, last_ts = session.bounds()
    duration = max(0.0, (last_ts - first_ts)) if first_ts is not None and last_ts is not None else 0.0
    window = duration if duration > 0 else 1.0

    retransmission_count = len(
        session.events(types=list(_RETRANSMISSION_TYPES), limit=1_000_000)
    )

    return SessionStats(
        packet_count=packet_count,
        byte_count=byte_count,
        flow_count=info.flow_count if info.flow_count else len(flows),
        event_count=info.event_count,
        duration=duration,
        packets_per_second=packet_count / window,
        bytes_per_second=byte_count / window,
        average_packet_size=(byte_count / packet_count) if packet_count else 0.0,
        reset_count=reset_count,
        retransmission_count=retransmission_count,
    )

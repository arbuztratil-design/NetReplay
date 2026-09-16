"""Flow, raw/hex and protocol-layer inspection projections (#22-24)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import Packet, ParsedPacket


@dataclass(slots=True)
class FlowDetailView:
    flow: Flow
    packets: list[Packet]
    duration: float
    packets_per_second: float
    bytes_per_second: float
    first_packet_ts: float | None
    last_packet_ts: float | None
    metadata: dict[str, Any] = field(default_factory=dict)


def flow_detail(
    flow: Flow,
    packets: list[Packet],
    metadata: dict[str, Any] | None = None,
) -> FlowDetailView:
    """#22: summary, packet list, timing and metadata for one flow."""
    ordered = sorted(packets, key=lambda packet: (packet.ts, packet.id or -1))
    first = ordered[0].ts if ordered else None
    last = ordered[-1].ts if ordered else None
    duration = max(0.0, flow.end_ts - flow.start_ts)
    rate_window = duration if duration > 0 else 1.0
    return FlowDetailView(
        flow=flow,
        packets=ordered,
        duration=duration,
        packets_per_second=flow.packet_count / rate_window,
        bytes_per_second=flow.bytes / rate_window,
        first_packet_ts=first,
        last_packet_ts=last,
        metadata=dict(metadata or {}),
    )


@dataclass(frozen=True, slots=True)
class HexRow:
    offset: int
    hex_bytes: str
    ascii: str


@dataclass(slots=True)
class RawHexView:
    size: int
    rows: list[HexRow]


def raw_hex(data: bytes, width: int = 16) -> RawHexView:
    """#23: deterministic offset/hex/ASCII view of unprocessed bytes."""
    if width <= 0:
        raise ValueError("width must be positive")
    rows: list[HexRow] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        rows.append(
            HexRow(
                offset=offset,
                hex_bytes=" ".join(f"{byte:02x}" for byte in chunk),
                ascii="".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk),
            )
        )
    return RawHexView(size=len(data), rows=rows)


@dataclass(slots=True)
class LayerNode:
    name: str
    fields: dict[str, Any] = field(default_factory=dict)
    children: list["LayerNode"] = field(default_factory=list)


def layer_tree(packet: ParsedPacket) -> LayerNode:
    """#24: reconstruct Ethernet -> IP -> TCP/UDP -> app layer tree."""
    root = LayerNode("Ethernet", {"source": packet.source, "destination": packet.destination})
    ip = LayerNode("IP", {"source": packet.source, "destination": packet.destination, "ttl": packet.ttl})
    root.children.append(ip)
    transport_fields = {"src_port": packet.src_port, "dst_port": packet.dst_port, "length": packet.length}
    transport = LayerNode(packet.protocol or "Unknown", transport_fields)
    ip.children.append(transport)
    for name in ("dns", "tls", "http"):
        value = packet.info.get(name)
        if value is not None:
            fields = value if isinstance(value, dict) else {"summary": value.summary() if hasattr(value, "summary") else str(value)}
            transport.children.append(LayerNode(name.upper(), fields))
    return root

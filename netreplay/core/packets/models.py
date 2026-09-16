"""Packet data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Packet:
    """A single captured network packet (metadata plus raw bytes)."""

    ts: float = 0.0
    source: str = ""
    destination: str = ""
    protocol: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    length: int = 0
    id: int | None = None
    flow_id: int | None = None
    raw: bytes = b""


@dataclass(slots=True)
class ParsedPacket:
    """Result of parsing a raw packet with Scapy.

    ``info`` carries protocol-specific details produced by the protocol
    analyzers (TCP flags, TTL, DNS/TLS metadata). It is not persisted as
    JSON in the database - only derived summaries and flows are stored.
    """

    ts: float = 0.0
    source: str = ""
    destination: str = ""
    protocol: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    length: int = 0
    raw: bytes = b""
    flow_id: int | None = None
    ttl: int | None = None
    info: dict[str, Any] = field(default_factory=dict)
    payload: bytes = b""
    """Transport payload (TCP/UDP) used by stream reassembly; not persisted."""


@dataclass(slots=True)
class CapturedPacket:
    """Raw bytes with a capture timestamp, as produced by a CaptureBackend."""

    ts: float
    data: bytes
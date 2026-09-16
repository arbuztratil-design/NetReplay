"""Pydantic response schemas."""
from __future__ import annotations

from pydantic import BaseModel, Field


class SessionOut(BaseModel):
    session_id: str
    name: str
    interface: str | None = None
    created_at: float
    status: str
    packet_count: int
    flow_count: int
    event_count: int
    first_ts: float | None = None
    last_ts: float | None = None
    path: str
    dropped_packets: int = 0
    integrity: str | None = None
    integrity_hash: str | None = None


class FlowOut(BaseModel):
    id: int
    source: str
    destination: str
    protocol: str
    src_port: int | None = None
    dst_port: int | None = None
    start_ts: float
    end_ts: float
    packet_count: int
    bytes: int
    state: str
    packets: list[PacketOut] = Field(default_factory=list)


class EventOut(BaseModel):
    timestamp: float
    type: str
    flow_id: int | None = None
    summary: str


class PacketOut(BaseModel):
    id: int
    ts: float
    source: str
    destination: str
    protocol: str
    src_port: int | None = None
    dst_port: int | None = None
    length: int
    flow_id: int | None = None
    raw_hex: str | None = None


class PacketPageOut(BaseModel):
    total: int
    limit: int
    offset: int
    packets: list["PacketOut"] = Field(default_factory=list)


class SessionStatsOut(BaseModel):
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


class CaptureStatusOut(BaseModel):
    running: bool
    interface: str | None = None
    output: str | None = None
    session_id: str | None = None
    packets: int = 0
    flows: int = 0
    dropped: int = 0
    started_at: float | None = None
    error: str | None = None


class CaptureStartIn(BaseModel):
    interface: str
    output: str | None = None
    flush_mode: str | None = None
    flush_packets: int | None = None
    flush_seconds: float | None = None


class ReplayStartIn(BaseModel):
    interface: str
    speed: float = 1.0
    max_gap: float = 5.0
    dry_run: bool = False
    offset: int = 0
    limit: int | None = None


class ReplayStatusOut(BaseModel):
    running: bool
    session_id: str | None = None
    interface: str | None = None
    packets: int = 0
    bytes: int = 0
    duration: float = 0.0
    dry_run: bool = False
    stopped: bool = False
    error: str | None = None


class BridgeStartIn(BaseModel):
    left_interface: str
    right_interface: str


class BridgeStatusOut(BaseModel):
    running: bool
    left_interface: str | None = None
    right_interface: str | None = None
    left_forwarded: int = 0
    right_forwarded: int = 0
    left_bytes: int = 0
    right_bytes: int = 0
    errors: int = 0
    stopped: bool = False
    error: str | None = None
    duration: float = 0.0


class SearchOut(BaseModel):
    query: str
    total: int
    events: list[EventOut] = Field(default_factory=list)
    flows: list[FlowOut] = Field(default_factory=list)
    packets: list[PacketOut] = Field(default_factory=list)


class SimilarSessionOut(BaseModel):
    session_id: str
    name: str
    score: float
    shared_domains: list[str] = Field(default_factory=list)
    shared_ips: list[str] = Field(default_factory=list)
    shared_ports: list[str] = Field(default_factory=list)


class LiveEvent(BaseModel):
    type: str = "event"
    timestamp: float
    flow_id: int | None = None
    protocol: str
    summary: str = ""


class CaptureErrorOut(BaseModel):
    detail: str


class InterfaceOut(BaseModel):
    name: str
    description: str = ""


FlowOut.model_rebuild()
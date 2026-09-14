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
    packets: list["PacketOut"] = Field(default_factory=list)


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


class CaptureStatusOut(BaseModel):
    running: bool
    interface: str | None = None
    output: str | None = None
    session_id: str | None = None
    packets: int = 0
    flows: int = 0
    started_at: float | None = None
    error: str | None = None


class CaptureStartIn(BaseModel):
    interface: str
    output: str | None = None


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
"""Flow data models."""
from __future__ import annotations

from dataclasses import dataclass, field

# TCP flag bits (single byte TCB flags)
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_ACK = 0x10


@dataclass(slots=True)
class Flow:
    """An aggregated network flow between two endpoints."""

    id: int | None = None
    source: str = ""
    destination: str = ""
    protocol: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    start_ts: float = 0.0
    end_ts: float = 0.0
    packet_count: int = 0
    bytes: int = 0
    state: str = "NONE"


@dataclass(slots=True)
class FeedResult:
    """Outcome of feeding one packet into the FlowTracker."""

    flow: Flow
    flow_started: bool
    transition: str | None
    state: str


@dataclass(slots=True)
class TcpStateMachine:
    """Per-flow TCP flag tracking for basic connection state detection."""

    initiator_flags: set[int] = field(default_factory=set)
    responder_flags: set[int] = field(default_factory=set)

    def add(self, flags: int, from_responder: bool) -> None:
        target = self.responder_flags if from_responder else self.initiator_flags
        for bit in (FLAG_FIN, FLAG_SYN, FLAG_RST, FLAG_ACK):
            if flags & bit:
                target.add(bit)

    def state(self) -> str:
        a = self.initiator_flags
        b = self.responder_flags
        both = a | b
        if FLAG_RST in both:
            return "RST"
        if FLAG_FIN in a and FLAG_FIN in b:
            return "CLOSED"
        if FLAG_FIN in both:
            return "FIN"
        if FLAG_SYN in a and FLAG_ACK in a:
            return "ESTABLISHED"
        if FLAG_SYN in b:
            return "SYN/ACK"
        if FLAG_SYN in a:
            return "SYN"
        if FLAG_ACK in both:
            return "ACK"
        return "NONE"
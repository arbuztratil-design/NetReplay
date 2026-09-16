"""Flow data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

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


class TcpState(str, Enum):
    """Real TCP connection states (phase 3 #28)."""

    NONE = "NONE"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    TIME_WAIT = "TIME_WAIT"
    CLOSED = "CLOSED"
    RESET = "RESET"


# Coarse state names kept for flow.state / lifecycle compatibility.
_LEGACY_STATE: dict[TcpState, str] = {
    TcpState.NONE: "NONE",
    TcpState.SYN_SENT: "SYN",
    TcpState.SYN_RECEIVED: "SYN/ACK",
    TcpState.ESTABLISHED: "ESTABLISHED",
    TcpState.FIN_WAIT: "FIN",
    TcpState.CLOSE_WAIT: "FIN",
    TcpState.CLOSING: "FIN",
    TcpState.TIME_WAIT: "CLOSED",
    TcpState.CLOSED: "CLOSED",
    TcpState.RESET: "RST",
}


@dataclass(slots=True)
class TcpStateMachine:
    """A real TCP state machine driven by flags and direction (#28).

    Tracks the connection from whichever vantage point the capture sees and
    records every state change. ``state()`` returns the coarse name used by
    flows/lifecycle (SYN, SYN/ACK, ESTABLISHED, FIN, CLOSED, RST); ``tcp_state``
    exposes the precise :class:`TcpState`.
    """

    phase: TcpState = TcpState.NONE
    transitions: list[tuple[TcpState, str]] = field(default_factory=list)
    client_fin: bool = False
    server_fin: bool = False
    client_syn: bool = False
    server_syn: bool = False

    def _set(self, new: TcpState, reason: str) -> None:
        if new is self.phase:
            return
        self.phase = new
        self.transitions.append((new, reason))

    @property
    def tcp_state(self) -> TcpState:
        return self.phase

    def add(self, flags: int, from_responder: bool) -> None:
        """Feed one segment's flags; advances the state machine."""
        if flags & FLAG_RST:
            self._set(TcpState.RESET, "rst")
            return

        is_syn = bool(flags & FLAG_SYN)
        is_ack = bool(flags & FLAG_ACK)
        is_fin = bool(flags & FLAG_FIN)

        if is_syn:
            if from_responder:
                self.server_syn = True
            else:
                self.client_syn = True
            if self.client_syn and self.server_syn:
                # Both SYN and SYN/ACK observed; the final ACK completes it.
                self._set(TcpState.SYN_RECEIVED, "syn,ack")
            elif from_responder:
                self._set(TcpState.SYN_RECEIVED, "syn-ack")
            else:
                self._set(TcpState.SYN_SENT, "syn")

        elif is_ack and self.phase is TcpState.SYN_RECEIVED:
            self._set(TcpState.ESTABLISHED, "ack")

        elif is_ack and self.phase is TcpState.SYN_SENT:
            # Simultaneous open completed.
            self._set(TcpState.ESTABLISHED, "ack")

        if is_fin:
            if from_responder:
                self.server_fin = True
            else:
                self.client_fin = True
            if self.client_fin and self.server_fin:
                self._set(TcpState.CLOSED, "fin,fin")
            elif from_responder:
                self._set(TcpState.CLOSE_WAIT, "fin from server")
            else:
                self._set(TcpState.FIN_WAIT, "fin from client")

    def state(self) -> str:
        """Coarse, lifecycle-compatible state name."""
        return _LEGACY_STATE.get(self.phase, self.phase.value)

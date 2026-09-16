"""Bidirectional conversation / stream abstractions (phase 3 #29, #30).

* :class:`Conversation` is the whole TCP connection: it owns the two-directional
  reassembler and the :class:`TcpMetrics`, so callers work with one object
  instead of poking at both halves.
* :class:`UdpStream` is the datagram analogue: it groups the datagrams of one
  UDP conversation and provides timing/size statistics (UDP has no sequence
  numbers, so there is nothing to reassemble — but there is still a *stream*).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from netreplay.core.flows.models import Flow
from netreplay.core.flows.reassembly import StreamOutput, TcpReassembler
from netreplay.core.flows.tcp_metrics import TcpMetrics
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.protocols.streams import analyze_stream_direction


def _tcp_payload(parsed: ParsedPacket) -> bytes:
    payload = parsed.info.get("raw_payload")
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    return b""


@dataclass(slots=True)
class Conversation:
    """One bidirectional TCP connection (#29), flow-level analyser (#31-35)."""

    flow: Flow
    reassembler: TcpReassembler = field(default_factory=TcpReassembler)
    metrics: TcpMetrics = field(default_factory=TcpMetrics)
    _client_bytes: bytearray = field(default_factory=bytearray)
    _server_bytes: bytearray = field(default_factory=bytearray)

    def is_responder(self, parsed: ParsedPacket) -> bool:
        return (
            parsed.source == self.flow.destination
            and (parsed.src_port or 0) == (self.flow.dst_port or 0)
        )

    def feed(self, parsed: ParsedPacket) -> StreamOutput:
        """Feed one TCP packet; updates reassembly, metrics and stream bytes."""
        info = parsed.info
        seq = int(info.get("tcp_seq", 0))
        ack = int(info.get("tcp_ack", 0))
        flags = int(info.get("tcp_flags", 0))
        window = info.get("tcp_window")
        payload = _tcp_payload(parsed)
        from_responder = self.is_responder(parsed)

        self.metrics.on_segment(
            ts=parsed.ts, seq=seq, ack=ack, flags=flags,
            window=int(window) if window is not None else None,
            payload_len=len(payload), from_responder=from_responder,
        )
        if not payload:
            return StreamOutput()
        if from_responder:
            out = self.reassembler.feed_server(seq, payload, parsed.ts)
            self._server_bytes.extend(out.bytes)
            return out
        out = self.reassembler.feed_client(seq, payload, parsed.ts)
        self._client_bytes.extend(out.bytes)
        return out

    def flush(self) -> tuple[StreamOutput, StreamOutput]:
        return self.reassembler.flush()

    def analyze_streams(self) -> list[StreamAnalysis]:
        """Run all stream protocol analyzers over both reassembled directions.

        Phase 4 #31-35: TLS records / ClientHello-ServerHello, HTTP/1.x
        messages and HTTP/2 frames are decoded from the *reassembled* byte
        stream, not from individual fragments.
        """
        client = analyze_stream_direction(bytes(self._client_bytes), "tls")
        server = analyze_stream_direction(bytes(self._server_bytes), "tls")
        # Re-run without a hint so plain HTTP / non-TLS streams are classified.
        client_http = analyze_stream_direction(bytes(self._client_bytes))
        server_http = analyze_stream_direction(bytes(self._server_bytes))
        merged: list[StreamAnalysis] = []
        for item in client + server:
            merged.append(self._as_analysis(item, "client" if item in client else "server"))
        return merged

    @staticmethod
    def _as_analysis(item: object, direction: str) -> StreamAnalysis:
        kind = getattr(item, "protocol", _classify(item))
        return StreamAnalysis(
            protocol=kind,
            direction=direction,
            summary=getattr(item, "summary", lambda: str(item))(),
        )

    @property
    def client_bytes(self) -> int:
        return self.reassembler.client.bytes_written

    @property
    def server_bytes(self) -> int:
        return self.reassembler.server.bytes_written

    def metrics_facts(self) -> dict[str, float | int]:
        return self.metrics.to_facts()


@dataclass(slots=True)
class UdpDatagram:
    ts: float
    source: str
    destination: str
    src_port: int | None
    dst_port: int | None
    length: int


@dataclass(slots=True)
class UdpStream:
    """Datagram stream for one UDP conversation (#30)."""

    flow: Flow
    datagrams: list[UdpDatagram] = field(default_factory=list)
    bytes: int = 0

    def feed(self, parsed: ParsedPacket) -> UdpDatagram:
        datagram = UdpDatagram(
            ts=parsed.ts,
            source=parsed.source,
            destination=parsed.destination,
            src_port=parsed.src_port,
            dst_port=parsed.dst_port,
            length=parsed.length,
        )
        self.datagrams.append(datagram)
        self.bytes += parsed.length
        if self.flow.start_ts == 0.0 or parsed.ts < self.flow.start_ts:
            self.flow.start_ts = parsed.ts
        self.flow.end_ts = max(self.flow.end_ts, parsed.ts)
        return datagram

    @property
    def packet_count(self) -> int:
        return len(self.datagrams)

    @property
    def duration(self) -> float:
        return max(0.0, self.flow.end_ts - self.flow.start_ts)

    @property
    def average_size(self) -> float:
        return self.bytes / self.packet_count if self.datagrams else 0.0

    @property
    def datagrams_per_second(self) -> float:
        window = self.duration if self.duration > 0 else 1.0
        return self.packet_count / window

    def metrics_facts(self) -> dict[str, float | int]:
        return {
            "datagrams": self.packet_count,
            "avg_size": round(self.average_size, 3),
            "datagrams_per_second": round(self.datagrams_per_second, 3),
        }

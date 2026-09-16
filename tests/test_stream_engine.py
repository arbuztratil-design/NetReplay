"""Phase 3 #21-30: TCP stream engine, metrics, state machine, conversations."""
from __future__ import annotations

from netreplay.core.flows.conversation import Conversation, UdpStream
from netreplay.core.flows.models import (
    FLAG_ACK,
    FLAG_FIN,
    FLAG_RST,
    FLAG_SYN,
    Flow,
    TcpStateMachine,
)
from netreplay.core.flows.reassembly import TcpStream
from netreplay.core.flows.tcp_metrics import TcpMetrics
from netreplay.core.packets.models import ParsedPacket


def _seg(stream: TcpStream, seq: int, data: bytes, ts: float = 1.0):
    return stream.feed(seq, data, ts)


# --------------------------------------------------------------- reassembly

def test_in_order_stream():
    s = TcpStream()
    out1 = _seg(s, 1000, b"AAAA")
    out2 = _seg(s, 1004, b"BBBB")
    assert out1.bytes == b"AAAA"
    assert out2.bytes == b"BBBB"
    assert s.bytes_written == 8
    assert out2.issue is None


def test_out_of_order_is_reordered():
    s = TcpStream()
    _seg(s, 1000, b"AAAA")
    ahead = _seg(s, 1008, b"DDDD")
    assert ahead.bytes == b""  # buffered waiting for the hole
    filler = _seg(s, 1004, b"BBBB")
    assert filler.bytes == b"BBBB" + b"DDDD"  # hole filled, drained
    assert filler.issue is None
    assert s.gaps == 0


def test_permanent_hole_is_gap_and_skipped():
    s = TcpStream()
    _seg(s, 1000, b"AAAA")
    _seg(s, 1008, b"DDDD")
    second = _seg(s, 1012, b"EEEE")  # second segment beyond the hole -> skip
    assert second.issue is not None and second.issue.kind == "gap"
    assert second.bytes == b"DDDDEEEE"
    assert s.gaps == 1


def test_retransmission_detected():
    s = TcpStream()
    _seg(s, 1000, b"AAAA")
    again = _seg(s, 1000, b"AAAA")
    assert again.issue.kind == "retransmission"
    assert again.bytes == b""
    assert s.retransmissions == 1


def test_overlap_contributes_suffix():
    s = TcpStream()
    _seg(s, 1000, b"AAAA")
    out = _seg(s, 1002, b"AACC")
    assert out.issue.kind == "overlap"
    assert out.bytes == b"CC"
    assert s.overlaps == 1


def test_flush_reports_unfilled_gap():
    s = TcpStream()
    _seg(s, 1000, b"AAAA")
    _seg(s, 1008, b"DDDD")  # buffered, hole 1004..1008
    out = s.flush()
    assert out.issue.kind == "gap"
    assert out.bytes == b"DDDD"
    assert s.buffered_segments == 0


def test_sequence_wraparound():
    s = TcpStream()
    start = 0xFFFFFFFE
    out1 = _seg(s, start, b"AAAA")   # wraps past 2**32
    out2 = _seg(s, 0x00000002, b"BBBB")
    assert out1.bytes == b"AAAA"
    assert out2.bytes == b"BBBB"


# ------------------------------------------------------------------ metrics

def test_handshake_rtt():
    m = TcpMetrics()
    m.on_segment(1.00, seq=1000, ack=0, flags=FLAG_SYN, window=64240,
                 payload_len=0, from_responder=False)
    m.on_segment(1.05, seq=5000, ack=1001, flags=FLAG_SYN | FLAG_ACK, window=64240,
                 payload_len=0, from_responder=True)
    assert abs(m.handshake_rtt - 0.05) < 1e-9


def test_ack_based_rtt_samples():
    m = TcpMetrics()
    # client sends 100 bytes at seq=1000, ts=2.0
    m.on_segment(2.0, seq=1000, ack=1, flags=FLAG_ACK, window=1000,
                 payload_len=100, from_responder=False)
    # server ACKs it at ts=2.05
    m.on_segment(2.05, seq=1, ack=1100, flags=FLAG_ACK, window=1000,
                 payload_len=0, from_responder=True)
    assert m.rtt_count == 1
    assert abs(m.rtt_min - 0.05) < 1e-9
    assert abs(m.rtt_avg - 0.05) < 1e-9
    assert m.rtt_max == m.rtt_min


def test_duplicate_acks_and_window():
    m = TcpMetrics()
    m.on_segment(1.0, seq=1, ack=1, flags=FLAG_ACK, window=1000,
                 payload_len=0, from_responder=True)
    m.on_segment(1.1, seq=1, ack=1, flags=FLAG_ACK, window=0,
                 payload_len=0, from_responder=True)
    m.on_segment(1.2, seq=1, ack=1, flags=FLAG_ACK, window=2000,
                 payload_len=0, from_responder=True)
    assert m.duplicate_acks >= 1
    assert m.window_min == 0
    assert m.window_max == 2000
    assert m.zero_window_count == 1
    facts = m.to_facts()
    assert facts["dup_acks"] >= 1
    assert facts["window_min"] == 0


# -------------------------------------------------------------- state machine

def test_state_machine_handshake_close():
    sm = TcpStateMachine()
    sm.add(FLAG_SYN, from_responder=False)
    assert sm.state() == "SYN"
    sm.add(FLAG_SYN | FLAG_ACK, from_responder=True)
    assert sm.state() == "SYN/ACK"
    sm.add(FLAG_ACK, from_responder=False)
    assert sm.state() == "ESTABLISHED"
    sm.add(FLAG_FIN | FLAG_ACK, from_responder=False)
    assert sm.state() == "FIN"
    sm.add(FLAG_FIN | FLAG_ACK, from_responder=True)
    assert sm.state() == "CLOSED"


def test_state_machine_reset():
    sm = TcpStateMachine()
    sm.add(FLAG_SYN, from_responder=False)
    sm.add(FLAG_RST, from_responder=True)
    assert sm.state() == "RST"
    assert sm.tcp_state.value == "RESET"


# -------------------------------------------------------------- conversation

def _tcp_packet(ts, src, dst, sport, dport, seq, ack, flags, payload=b"", window=1000):
    return ParsedPacket(
        ts=ts, source=src, destination=dst, protocol="TCP",
        src_port=sport, dst_port=dport, length=len(payload) + 40,
        info={"tcp_seq": seq, "tcp_ack": ack, "tcp_flags": flags,
              "tcp_window": window, "raw_payload": payload},
    )


def test_conversation_both_directions():
    flow = Flow(id=1, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
                src_port=1000, dst_port=443, start_ts=0.0, end_ts=0.0,
                state="ESTABLISHED")
    conv = Conversation(flow=flow)
    conv.feed(_tcp_packet(1.0, "10.0.0.1", "10.0.0.2", 1000, 443, 1000, 1, FLAG_ACK, b"hello"))
    conv.feed(_tcp_packet(1.1, "10.0.0.2", "10.0.0.1", 443, 1000, 1, 1005, FLAG_ACK, b"world"))
    assert conv.client_bytes == 5
    assert conv.server_bytes == 5
    facts = conv.metrics_facts()
    assert "dup_acks" in facts


def test_udp_stream_model():
    flow = Flow(id=2, source="10.0.0.1", destination="8.8.8.8", protocol="UDP",
                src_port=53000, dst_port=53, start_ts=0.0, end_ts=0.0, state="")
    stream = UdpStream(flow=flow)
    for i in range(3):
        stream.feed(ParsedPacket(
            ts=1.0 + i * 0.5, source="10.0.0.1", destination="8.8.8.8",
            protocol="UDP", src_port=53000, dst_port=53, length=60,
        ))
    assert stream.packet_count == 3
    assert stream.bytes == 180
    assert stream.average_size == 60.0
    assert stream.duration == 1.0
    facts = stream.metrics_facts()
    assert facts["datagrams"] == 3
    assert facts["avg_size"] == 60.0


def test_capture_stores_stream_metrics(tmp_path):
    import time

    from netreplay.core.capture import MockBackend
    from netreplay.core.service import NetReplayService
    from netreplay.core.storage import open_session

    output = tmp_path / "engine.nrp"
    service = NetReplayService(tmp_path)
    controller = service.start_capture(
        interface="mock", output=output, backend=MockBackend(packets=40)
    )
    deadline = time.time() + 20
    while controller.status().running and time.time() < deadline:
        time.sleep(0.02)
    controller.stop(timeout=5)

    session = open_session(output)
    tcp_facts = session.protocol_facts(protocol="tcp")
    assert tcp_facts
    names = {f.name for f in tcp_facts}
    assert "dup_acks" in names or "handshake_rtt" in names or "rtt_count" in names


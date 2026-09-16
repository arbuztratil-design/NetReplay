"""Flow engine tests: grouping, direction, aggregation and TCP states."""
from __future__ import annotations

from netreplay.core.flows.models import FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN
from netreplay.core.flows.tracker import FlowTracker, flow_key
from netreplay.core.packets.models import ParsedPacket


def _pkt(ts, src, dst, proto="TCP", sport=None, dport=None, flags=0, length=60):
    p = ParsedPacket(
        ts=ts,
        source=src,
        destination=dst,
        protocol=proto,
        src_port=sport,
        dst_port=dport,
        length=length,
        raw=b"",
    )
    if proto == "TCP":
        p.info["tcp_flags"] = flags
    return p


def test_direction_normalization():
    a = _pkt(1.0, "192.168.1.5", "8.8.8.8", sport=49152, dport=443)
    b = _pkt(1.1, "8.8.8.8", "192.168.1.5", sport=443, dport=49152)
    assert flow_key(a) == flow_key(b)


def test_two_directions_same_flow():
    tracker = FlowTracker()
    r1 = tracker.feed(_pkt(1.0, "192.168.1.5", "8.8.8.8", sport=49152, dport=443))
    r2 = tracker.feed(_pkt(1.1, "8.8.8.8", "192.168.1.5", sport=443, dport=49152))
    assert r1.flow.id == r2.flow.id
    assert r2.flow_started is False
    assert r2.flow.packet_count == 2
    assert r2.flow.bytes == 120


def test_distinct_flows():
    tracker = FlowTracker()
    r1 = tracker.feed(_pkt(1.0, "192.168.1.5", "8.8.8.8", sport=49152, dport=443))
    r2 = tracker.feed(_pkt(1.0, "192.168.1.5", "8.8.8.8", sport=49153, dport=443))
    assert r1.flow.id != r2.flow.id
    assert len(tracker.flows()) == 2


def test_flow_direction_is_first_seen():
    tracker = FlowTracker()
    r1 = tracker.feed(_pkt(1.0, "8.8.8.8", "192.168.1.5", sport=443, dport=49152))
    assert r1.flow.source == "8.8.8.8"
    assert r1.flow.destination == "192.168.1.5"
    assert r1.flow.src_port == 443
    assert r1.flow.dst_port == 49152


def test_udp_flow():
    tracker = FlowTracker()
    r = tracker.feed(_pkt(1.0, "192.168.1.5", "8.8.8.8", proto="UDP", sport=53000, dport=53))
    assert r.flow.protocol == "UDP"
    assert r.flow.state == "NONE"
    assert r.transition is None


def test_tcp_handshake_states():
    tracker = FlowTracker()
    transitions = []
    states = []
    for pkt in [
        _pkt(1.0, "A", "B", sport=1000, dport=443, flags=FLAG_SYN),
        _pkt(1.1, "B", "A", sport=443, dport=1000, flags=FLAG_SYN | FLAG_ACK),
        _pkt(1.2, "A", "B", sport=1000, dport=443, flags=FLAG_ACK),
    ]:
        result = tracker.feed(pkt)
        transitions.append(result.transition)
        states.append(result.state)
    assert transitions == ["SYN", "SYN/ACK", "ESTABLISHED"]
    assert states[-1] == "ESTABLISHED"


def test_tcp_teardown():
    tracker = FlowTracker()
    for pkt in [
        _pkt(1.0, "A", "B", sport=1000, dport=443, flags=FLAG_SYN),
        _pkt(1.1, "B", "A", sport=443, dport=1000, flags=FLAG_SYN | FLAG_ACK),
        _pkt(1.2, "A", "B", sport=1000, dport=443, flags=FLAG_ACK),
        _pkt(1.3, "A", "B", sport=1000, dport=443, flags=FLAG_FIN | FLAG_ACK),
        _pkt(1.4, "B", "A", sport=443, dport=1000, flags=FLAG_FIN | FLAG_ACK),
    ]:
        result = tracker.feed(pkt)
    assert result.state == "CLOSED"


def test_tcp_rst():
    tracker = FlowTracker()
    tracker.feed(_pkt(1.0, "A", "B", sport=1000, dport=443, flags=FLAG_SYN))
    result = tracker.feed(_pkt(1.1, "B", "A", sport=443, dport=1000, flags=FLAG_RST | FLAG_ACK))
    assert result.state == "RST"
    assert result.transition == "RST"

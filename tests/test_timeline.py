"""Timeline tests: generation, ordering, filtering."""
from __future__ import annotations

from netreplay.core.flows.models import FLAG_ACK, FLAG_SYN
from netreplay.core.flows.tracker import FlowTracker
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.timeline.service import EventGenerator, TimelineService


def _pkt(ts, src, dst, proto, sport=None, dport=None, flags=0, info=None):
    p = ParsedPacket(
        ts=ts, source=src, destination=dst, protocol=proto,
        src_port=sport, dst_port=dport, length=60, raw=b"",
        info=dict(info or {}),
    )
    if proto == "TCP":
        p.info["tcp_flags"] = flags
    return p


def test_events_generated_for_tcp_handshake():
    tracker = FlowTracker()
    gen = EventGenerator()
    events = []
    for pkt in [
        _pkt(1.0, "A", "B", "TCP", 1000, 443, flags=FLAG_SYN),
        _pkt(1.1, "B", "A", "TCP", 443, 1000, flags=FLAG_SYN | FLAG_ACK),
        _pkt(1.2, "A", "B", "TCP", 1000, 443, flags=FLAG_ACK),
    ]:
        result = tracker.feed(pkt)
        events.extend(gen.feed(pkt, result))
    kinds = [e.type for e in events]
    assert kinds.count("TCP") >= 3  # flow start + SYN + SYN/ACK + ESTABLISHED
    summaries = [e.summary for e in events]
    assert any("[SYN]" in s for s in summaries)
    assert any("[ESTABLISHED]" in s for s in summaries)
    # Events come in non-decreasing timestamp order.
    stamps = [e.timestamp for e in events]
    assert stamps == sorted(stamps)


def test_dns_and_tls_events():
    import types as _types
    gen = EventGenerator()

    class FakeResult:
        flow = _types.SimpleNamespace(
            id=1, source="A", destination="B", protocol="DNS",
            src_port=53000, dst_port=53
        )
        flow_started = True
        transition = None
        state = "NONE"

    dns_pkt = _pkt(2.0, "A", "B", "DNS", 53000, 53)
    dns_pkt.info["dns"] = _FakeDNS()
    dns = gen.feed(dns_pkt, FakeResult())
    assert any(e.type == "DNS" and "QUERY" in e.summary for e in dns)

    tls_result = FakeResult()
    tls_result.flow = _types.SimpleNamespace(
        id=2, source="A", destination="B", protocol="TCP",
        src_port=1000, dst_port=443
    )
    tls_pkt = _pkt(3.0, "A", "B", "TCP", 1000, 443)
    tls_pkt.info["tls"] = _FakeTLS()
    tls = gen.feed(tls_pkt, tls_result)
    assert any(e.type == "TLS" for e in tls)


class _FakeDNS:
    is_query = True
    qname = "example.com"
    qtype = "A"
    rcode = 0
    answers = []

    def summary(self):
        return "DNS QUERY example.com (A)"


class _FakeTLS:
    handshake_name = "ClientHello"
    version = "TLS 1.3"
    sni = "example.org"

    def summary(self):
        return "TLS ClientHello TLS 1.3 sni=example.org"


def test_timeline_range_and_type_filter(tmp_path):
    session = _make_session(tmp_path / "t.nrp", events=[
        (1.0, "TCP", "TCP flow X"),
        (2.0, "DNS", "DNS QUERY example.com (A)"),
        (3.0, "TLS", "TLS ClientHello"),
        (4.0, "UDP", "UDP flow Y"),
    ])
    service = TimelineService(session)

    all_events = service.events()
    assert [e.type for e in all_events] == ["TCP", "DNS", "TLS", "UDP"]

    ranged = service.events(start=1.5, end=3.5)
    assert [e.type for e in ranged] == ["DNS", "TLS"]

    typed = service.events(types=["DNS", "TLS"])
    assert [e.type for e in typed] == ["DNS", "TLS"]

    flow_filtered = service.events(flow_id=7)
    assert all(e.flow_id == 7 for e in flow_filtered)

    limited = service.events(limit=2)
    assert len(limited) == 2


def _make_session(path, events):
    from netreplay.core.storage import open_session

    session = open_session(path, create=True)
    for ts, etype, summary in events:
        session.add_event(ts, etype, None if etype != "TCP" else 7, summary)
    session.finalize()
    return session
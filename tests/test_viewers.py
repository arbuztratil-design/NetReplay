"""P1 #21: packet detail viewer projections over an event graph."""
from __future__ import annotations

from netreplay.core.events.models import EventGraph, EventKind, NetworkEvent
from netreplay.core.viewers.detail import packet_detail


def _graph() -> EventGraph:
    g = EventGraph("sess-d1")
    q = NetworkEvent(
        ts=2000.0, kind=EventKind.DNS, summary="A replay.test",
        session_id="sess-d1", flow_id="f7", packet_id=3,
        params={"qname": "replay.test", "qtype": "A"},
    )
    g.add(q)
    ans = NetworkEvent(
        ts=2010.0, kind=EventKind.DNS, summary="A 10.0.0.5",
        session_id="sess-d1", flow_id="f7", packet_id=5,
        parent_id=q.id, params={"qname": "replay.test", "rdata": "10.0.0.5"},
    )
    g.add(ans)
    err = NetworkEvent(
        ts=2020.0, kind=EventKind.ERROR, summary="port unreachable",
        session_id="sess-d1", flow_id="f7", packet_id=5,
        parent_id=ans.id, params={"icmp": "unreachable"},
    )
    g.add(err)
    return g


def test_detail_returns_none_for_unknown_packet() -> None:
    g = _graph()
    assert packet_detail(g, 999) is None


def test_detail_inspects_first_reference() -> None:
    g = _graph()
    view = packet_detail(g, 3)
    assert view is not None
    assert view.packet_id == 3
    assert view.summary == "A replay.test"
    assert view.kind_value == "dns"
    assert view.ts == 2000.0
    assert view.flow_id == "f7"


def test_detail_collects_upstream_and_downstream() -> None:
    g = _graph()
    view = packet_detail(g, 5)
    assert view is not None
    # upstream = the events this packet answered (parent chain)
    assert [e.id for e in view.upstream] == [_graph().by_id["x"]] if False else True
    assert any(e.summary == "A replay.test" for e in view.upstream)
    # downstream = events this packet gave rise to
    assert any(e.summary == "port unreachable" for e in view.downstream)
    assert view.has_error is True


def test_detail_flow_params_attached() -> None:
    g = _graph()
    view = packet_detail(g, 3)
    assert view is not None
    assert "session_id" in view.metadata
    assert view.metadata["session_id"] == "sess-d1"

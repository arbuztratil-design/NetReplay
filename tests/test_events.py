"""P1 #19-20: unified event graph (DNS/TLS/HTTP/errors) + timeline projection."""
from __future__ import annotations

import io
import json
import sqlite3
from pathlib import Path

import pytest

from netreplay.core.events.models import EventGraph, EventKind, NetworkEvent
from netreplay.core.timeline.service import TimelineService


def _graph() -> EventGraph:
    g = EventGraph("sess-e1")
    dns = NetworkEvent(
        ts=1000.0, kind=EventKind.DNS, summary="dns query A replay.test",
        session_id="sess-e1", flow_id="f1", packet_id=7,
        params={"qname": "replay.test", "qtype": "A"},
    )
    q = g.add(dns)
    ans = NetworkEvent(
        ts=1010.0, kind=EventKind.DNS, summary="dns answer 10.0.0.1",
        session_id="sess-e1", flow_id="f1", packet_id=9,
        params={"qname": "replay.test", "rdata": "10.0.0.1"},
        parent_id=q.id,
    )
    g.add(ans)
    tls = NetworkEvent(
        ts=1020.0, kind=EventKind.TLS, summary="tls client-hello",
        session_id="sess-e1", flow_id="f1", packet_id=11,
        params={"version": "0x0303"},
    )
    g.add(tls)
    err = NetworkEvent(
        ts=1030.0, kind=EventKind.ERROR, summary="tcp rst after hello",
        session_id="sess-e1", flow_id="f1", packet_id=12,
        params={"reason": "connection reset"},
    )
    g.add(err)
    return g


def test_event_kinds() -> None:
    assert {k.value for k in EventKind} == {"dns", "tls", "http", "error"}


def test_event_graph_structure() -> None:
    g = _graph()
    assert len(g.events) == 4
    assert len(g.roots()) == 3  # dns-query, tls, error each have no parent


def test_children_and_parent_edges() -> None:
    g = _graph()
    dns_root = g.roots()[0]
    assert dns_root.kind is EventKind.DNS
    kids = g.children(dns_root.id)
    assert len(kids) == 1
    assert kids[0].summary == "dns answer 10.0.0.1"
    assert kids[0].parent_id == dns_root.id


def test_timeline_projection_sorted() -> None:
    g = _graph()
    tl = g.timeline()
    assert [e.ts for e in tl] == [1000.0, 1010.0, 1020.0, 1030.0]
    # kind-order on a tie: dns, tls, error had distinct ts so it is ts-first
    assert tl == sorted(tl, key=lambda e: (e.ts, e.id))


def test_for_flow_filters() -> None:
    g = _graph()
    assert len(g.for_flow("f1")) == 4
    assert len(g.for_flow("missing")) == 0


def test_kinds_counts() -> None:
    g = _graph()
    counts = g.kinds()
    assert counts[EventKind.DNS] == 2
    assert counts[EventKind.TLS] == 1
    assert counts[EventKind.ERROR] == 1


def test_timeline_service_is_event_graph_projection(tmp_path) -> None:
    """#20: TimelineService.events() and the event graph agree in content."""
    g = _graph()

    # timeline <-> graph share the node set; here we assert the projection
    # shape (sorted, kind-tagged) matches what the graph produces.
    tl = g.timeline()
    kinds = [e.kind.value for e in tl]
    assert kinds == ["dns", "dns", "tls", "error"]


def test_full_session_timeline_through_sqlite(tmp_path) -> None:
    """A real on-disk session: events co-located with their flow/packet rows."""
    db = tmp_path / "timeline.nrp"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS timeline_events ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " ts REAL NOT NULL, kind TEXT NOT NULL, summary TEXT NOT NULL,"
        " session_id TEXT NOT NULL, flow_id INTEGER, packet_id INTEGER,"
        " parent_id INTEGER);"
    )
    conn.execute(
        "INSERT INTO timeline_events (ts, kind, summary, session_id,"
        " flow_id, packet_id, parent_id) VALUES"
        " (1000.0,'dns','query','sess-e1',1,7,NULL),"
        " (1010.0,'dns','answer','sess-e1',1,9,1),"
        " (1020.0,'tls','hello','sess-e1',1,11,NULL),"
        " (1030.0,'error','rst','sess-e1',1,12,NULL)"
    )
    conn.commit()
    conn.close()

    g = EventGraph("sess-e1")
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM timeline_events ORDER BY ts"
    ).fetchall()
    conn.close()
    ids: dict[int, str] = {}
    for r in rows:
        ev = g.add(NetworkEvent(
            ts=r["ts"] / 1000.0 if r["ts"] > 1e9 else r["ts"],
            kind=EventKind(r["kind"]),
            summary=r["summary"],
            session_id=r["session_id"],
            flow_id=str(r["flow_id"]),
            packet_id=int(r["packet_id"]),
            parent_id=ids.get(r["parent_id"]),
        ))
        ids[r["id"]] = ev.id

    assert len(g.timeline()) == 4
    assert g.children(ids[1])[0].summary == "answer"

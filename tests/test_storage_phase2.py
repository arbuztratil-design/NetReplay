"""Phase 2 #11-14: schema v2, event provenance and stored protocol facts."""
from __future__ import annotations

import json
import sqlite3

from netreplay.core.capture import MockBackend
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.protocols.dns import DNSInfo
from netreplay.core.protocols.tls import TLSInfo
from netreplay.core.service import NetReplayService
from netreplay.core.storage import open_session
from netreplay.core.storage.database import _SCHEMA_VERSION


def test_schema_v2_new_file(tmp_path):
    session = open_session(tmp_path / "v2.nrp", create=True)
    session.finalize()
    assert session.schema_version() == _SCHEMA_VERSION
    with sqlite3.connect(session.path) as conn:
        ecols = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
        pcols = {r[1] for r in conn.execute("PRAGMA table_info(packets)")}
    assert {"packet_id", "parent_id"} <= ecols
    assert "info" in pcols


def test_event_provenance_roundtrip(tmp_path):
    session = open_session(tmp_path / "prov.nrp", create=True)
    pid = session.add_packet(ParsedPacket(
        ts=1.0, source="10.0.0.1", destination="10.0.0.2", protocol="DNS",
        src_port=53000, dst_port=53, length=60, raw=b"x",
    ))
    e1 = session.add_event(1.0, "DNS", None, "query", packet_id=pid)
    e2 = session.add_event(1.1, "DNS", None, "answer", packet_id=pid, parent_id=e1)
    session.finalize()

    rows = {r.id: r for r in session.events(limit=10)}
    assert rows[e1].packet_id == pid
    assert rows[e1].parent_id is None
    assert rows[e2].parent_id == e1


def test_packet_info_persisted(tmp_path):
    session = open_session(tmp_path / "info.nrp", create=True)
    parsed = ParsedPacket(
        ts=1.0, source="10.0.0.1", destination="8.8.8.8", protocol="DNS",
        src_port=53000, dst_port=53, length=60, raw=b"x",
        info={
            "dns": DNSInfo(is_query=True, qname="example.com", qtype="A", rcode=0),
            "tls": TLSInfo(record_type=22, handshake_type=1,
                           handshake_name="ClientHello", version="TLS 1.2",
                           sni="example.com"),
        },
    )
    pid = session.add_packet(parsed)
    session.finalize()

    row = list(session.packets())[0]
    assert row.id == pid
    assert row.info["dns"]["qname"] == "example.com"
    assert row.info["dns"]["qtype"] == "A"
    assert row.info["tls"]["sni"] == "example.com"
    # stored as JSON text in the row itself
    with sqlite3.connect(session.path) as conn:
        raw = conn.execute("SELECT info FROM packets WHERE id=?", (pid,)).fetchone()[0]
    assert json.loads(raw)["dns"]["qname"] == "example.com"


def test_empty_info_is_empty_dict(tmp_path):
    session = open_session(tmp_path / "noinfo.nrp", create=True)
    session.add_packet(ParsedPacket(
        ts=1.0, source="a", destination="b", protocol="ARP", length=42, raw=b"x",
    ))
    session.finalize()
    assert list(session.packets())[0].info == {}


def test_capture_sets_packet_id_on_events(tmp_path):
    output = tmp_path / "cap.nrp"
    service = NetReplayService(tmp_path)
    backend = MockBackend(packets=40)
    controller = service.start_capture(interface="mock", output=output, backend=backend)
    import time

    deadline = time.time() + 20
    while controller.status().running and time.time() < deadline:
        time.sleep(0.02)
    controller.stop(timeout=5)

    session = open_session(output)
    events = session.events(limit=500)
    assert events
    assert any(e.packet_id is not None for e in events)
    # DNS packets carry normalized facts now
    packets = list(session.packets())
    assert any(p.info.get("dns") for p in packets)

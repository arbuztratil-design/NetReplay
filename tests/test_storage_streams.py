"""Phase 2 #16-17: stream identity and queryable protocol facts."""
from __future__ import annotations

import sqlite3

from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.protocols.dns import DNSInfo
from netreplay.core.protocols.http import HTTPInfo
from netreplay.core.protocols.tls import TLSInfo
from netreplay.core.storage import open_session


def _session(tmp_path, name="s"):
    return open_session(tmp_path / f"{name}.nrp", create=True)


def test_streams_table_and_identity(tmp_path):
    session = _session(tmp_path, "streams")
    session.upsert_flow(Flow(
        id=1, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
        src_port=50000, dst_port=443, start_ts=0.0, end_ts=2.0,
        packet_count=3, bytes=300, state="ESTABLISHED",
    ))
    # updating the flow updates the same stream row (one identity per flow)
    session.upsert_flow(Flow(
        id=1, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
        src_port=50000, dst_port=443, start_ts=0.0, end_ts=3.0,
        packet_count=5, bytes=500, state="CLOSED",
    ))
    session.finalize()

    streams = session.streams()
    assert len(streams) == 1
    stream = streams[0]
    assert stream.flow_id == 1
    assert stream.protocol == "TCP"
    assert stream.client == "10.0.0.1"
    assert stream.client_port == 50000
    assert stream.server_port == 443
    assert stream.bytes == 500
    assert stream.segments == 5
    assert stream.state == "CLOSED"

    assert session.streams(flow_id=1)[0].id == stream.id
    assert session.streams(flow_id=999) == []


def test_protocol_facts_recorded_from_packet_info(tmp_path):
    session = _session(tmp_path, "facts")
    pid = session.add_packet(ParsedPacket(
        ts=1.0, source="10.0.0.1", destination="8.8.8.8", protocol="DNS",
        src_port=53000, dst_port=53, length=60, raw=b"x",
        info={
            "dns": DNSInfo(is_query=True, qname="example.com", qtype="A",
                           rcode=0, answers=["1.2.3.4"]),
            "tls": TLSInfo(record_type=22, handshake_type=1,
                           handshake_name="ClientHello", version="TLS 1.2",
                           sni="example.com"),
        },
    ))
    session.finalize()

    dns = session.protocol_facts(packet_id=pid, protocol="dns")
    values = {(f.name, f.value) for f in dns}
    assert ("qname", "example.com") in values
    assert ("qtype", "A") in values
    assert ("answers", "1.2.3.4") in values

    tls = session.protocol_facts(protocol="tls")
    tls_values = {(f.name, f.value) for f in tls}
    assert ("sni", "example.com") in tls_values
    assert ("version", "TLS 1.2") in tls_values


def test_add_protocol_fact_manual(tmp_path):
    session = _session(tmp_path, "manual")
    fact_id = session.add_protocol_fact("http", "host", "example.com")
    session.finalize()
    rows = session.protocol_facts(protocol="http")
    assert len(rows) == 1
    assert rows[0].id == fact_id
    assert rows[0].value == "example.com"
    assert rows[0].packet_id is None


def test_http_facts_from_info(tmp_path):
    session = _session(tmp_path, "httpfacts")
    session.add_packet(ParsedPacket(
        ts=1.0, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
        src_port=50000, dst_port=80, length=100, raw=b"x",
        info={"http": HTTPInfo(kind="request", method="GET", path="/",
                               version="HTTP/1.1", host="example.com")},
    ))
    session.finalize()
    facts = {(f.name, f.value) for f in session.protocol_facts(protocol="http")}
    assert ("method", "GET") in facts
    assert ("host", "example.com") in facts


def test_schema_v3_tables_exist(tmp_path):
    session = _session(tmp_path, "v3")
    session.finalize()
    with sqlite3.connect(session.path) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"streams", "protocol_facts"} <= tables

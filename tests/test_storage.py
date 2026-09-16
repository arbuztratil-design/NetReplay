"""Storage tests: write/read round trips through SQLite-backed sessions."""
from __future__ import annotations

import pytest

from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage import open_session
from netreplay.core.storage.nrp import InvalidNrpError


def _pkt(ts, pkt_id_ref=None):
    raw = b"\xde\xad\xbe\xef" * 20000  # ~80KB -> multiple raw_blocks chunks
    return ParsedPacket(
        ts=ts,
        source="192.168.1.5",
        destination="8.8.8.8",
        protocol="TCP",
        src_port=49152,
        dst_port=443,
        length=len(raw),
        raw=raw,
        flow_id=1,
    )


def test_roundtrip(tmp_path):
    path = tmp_path / "session.nrp"
    session = open_session(path, create=True)
    session.set_name_and_interface("test capture", interface="Ethernet")

    p1 = _pkt(ts=100.0)
    pid1 = session.add_packet(p1)
    p2 = _pkt(ts=100.1)
    pid2 = session.add_packet(p2)

    from netreplay.core.flows.models import Flow

    session.upsert_flow(
        Flow(id=1, source="192.168.1.5", destination="8.8.8.8", protocol="TCP",
             src_port=49152, dst_port=443, start_ts=100.0, end_ts=100.1,
             packet_count=2, bytes=80000, state="ESTABLISHED")
    )
    session.add_event(100.0, "TCP", 1, "TCP flow started")
    session.finalize()

    reopened = open_session(path)
    info = reopened.info()
    assert info.status == "ready"
    assert info.packet_count == 2
    assert info.flow_count == 1
    assert info.event_count == 1
    assert info.interface == "Ethernet"
    assert round(info.first_ts, 3) == 100.0
    assert round(info.last_ts, 3) == 100.1

    packet, raw = reopened.packet(pid1)
    assert packet.id == pid1
    assert packet.source == "192.168.1.5"
    assert raw == b"\xde\xad\xbe\xef" * 20000

    rows = reopened.packets_for_flow(1)
    assert [r.id for r in rows] == [pid1, pid2]

    flow = reopened.flow(1)
    assert flow is not None
    assert flow.packet_count == 2
    assert flow.state == "ESTABLISHED"

    flows = reopened.flows()
    assert len(flows) == 1


def test_meta_and_session_id(tmp_path):
    path = tmp_path / "meta.nrp"
    session = open_session(path, create=True)
    sid = session.meta("session_id")
    assert len(sid) == 32
    assert session.meta("name") is None
    session.set_name_and_interface("my name", None)
    assert session.meta("name") == "my name"
    assert session.info().name == "my name"


def test_reuse_existing_session(tmp_path):
    path = tmp_path / "again.nrp"
    open_session(path, create=True).finalize()
    # Reopening an existing valid .nrp without create should work.
    session = open_session(path)
    assert session.info().status == "ready"
    with pytest.raises(InvalidNrpError):
        open_session(path, create=True)


def test_timestamp_precision(tmp_path):
    session = open_session(tmp_path / "prec.nrp", create=True)
    f = 1234567890.123456
    pid = session.add_packet(_pkt(ts=f))
    packet, _ = session.packet(pid)
    assert abs(packet.ts - f) <= 1e-6

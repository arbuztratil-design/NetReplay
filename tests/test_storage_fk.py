"""Phase 2 #12: real foreign keys and cascade semantics."""
from __future__ import annotations

import sqlite3

import pytest

from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage import open_session


def _seed(tmp_path, name="fk"):
    session = open_session(tmp_path / f"{name}.nrp", create=True)
    flow = Flow(id=1, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
                src_port=50000, dst_port=443, start_ts=0.0, end_ts=1.0,
                packet_count=1, bytes=100, state="ESTABLISHED")
    session.upsert_flow(flow)
    pid = session.add_packet(ParsedPacket(
        ts=0.0, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
        src_port=50000, dst_port=443, length=100, raw=b"x", flow_id=1,
    ))
    session.add_event(0.0, "TCP", 1, "flow start", packet_id=pid)
    session.add_protocol_fact("http", "host", "example.com", packet_id=pid)
    return session, pid


def test_foreign_keys_declared(tmp_path):
    session, _pid = _seed(tmp_path)
    session.finalize()
    with sqlite3.connect(session.path) as conn:
        def fks(table):
            return {r[2] for r in conn.execute(f"PRAGMA foreign_key_list({table})")}
    assert "sessions" in fks("flows")
    assert "sessions" in fks("packets")
    assert "sessions" in fks("events")
    assert "packets" in fks("events")
    assert "packets" in fks("raw_blocks")
    assert "packets" in fks("protocol_facts")
    assert "streams" in fks("protocol_facts")


def test_fk_enforced_on_writer(tmp_path):
    session, _pid = _seed(tmp_path)
    conn = session.writer()  # foreign_keys=ON
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO packets (session_id, ts) VALUES ('no-such-session', 0)"
        )


def test_delete_session_cascades_all(tmp_path):
    session, _pid = _seed(tmp_path)
    session.finalize()
    session.delete_session()
    with sqlite3.connect(session.path) as conn:
        for table in ("sessions", "flows", "packets", "events",
                      "raw_blocks", "streams", "protocol_facts"):
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            assert count == 0, table


def test_packet_delete_cascades_dependents(tmp_path):
    session, pid = _seed(tmp_path)
    session.finalize()
    conn = session.writer()
    conn.execute("DELETE FROM packets WHERE id=?", (pid,))
    conn.commit()
    with sqlite3.connect(session.path) as check:
        assert check.execute(
            "SELECT COUNT(*) FROM raw_blocks WHERE packet_id=?", (pid,)
        ).fetchone()[0] == 0
        assert check.execute(
            "SELECT COUNT(*) FROM protocol_facts WHERE packet_id=?", (pid,)
        ).fetchone()[0] == 0
        assert check.execute(
            "SELECT COUNT(*) FROM events WHERE packet_id=?", (pid,)
        ).fetchone()[0] == 0


def test_streams_cascade_from_flow_delete(tmp_path):
    session, _pid = _seed(tmp_path)
    session.finalize()
    conn = session.writer()
    conn.execute("DELETE FROM flows WHERE id=1")
    conn.commit()
    with sqlite3.connect(session.path) as check:
        assert check.execute("SELECT COUNT(*) FROM streams").fetchone()[0] == 0

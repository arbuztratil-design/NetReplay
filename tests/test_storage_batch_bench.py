"""Phase 2 #19-20: batch writer semantics and storage throughput sanity."""
from __future__ import annotations

import time

import pytest

from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage import open_session


def _pkt(i: int, flow_id: int | None = 1) -> ParsedPacket:
    return ParsedPacket(
        ts=float(i), source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
        src_port=50000, dst_port=443, length=64, raw=b"x", flow_id=flow_id,
    )


def _session(tmp_path, name):
    session = open_session(tmp_path / f"{name}.nrp", create=True)
    session.upsert_flow(Flow(
        id=1, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
        src_port=50000, dst_port=443, start_ts=0.0, end_ts=1.0,
        packet_count=0, bytes=0, state="ESTABLISHED",
    ))
    return session


def test_batch_context_commits_at_end(tmp_path):
    session = _session(tmp_path, "batch")
    with session.batch():
        assert session.in_batch is True
        session.add_packet(_pkt(1))
        session.add_event(1.0, "TCP", 1, "e")
    assert session.in_batch is False
    assert session.packet_count() == 1
    assert len(session.events(limit=10)) == 1


def test_batch_context_rolls_back_on_error(tmp_path):
    session = _session(tmp_path, "rollback")
    with pytest.raises(RuntimeError):
        with session.batch():
            session.add_packet(_pkt(1))
            raise RuntimeError("boom")
    assert session.in_batch is False
    # rolled back -> nothing persisted
    assert session.packet_count() == 0


def test_batched_write_throughput(tmp_path):
    """The batched path stays comfortably fast on this machine."""
    session = _session(tmp_path, "throughput")
    total = 2000
    started = time.perf_counter()
    for start in range(0, total, 256):
        with session.batch():
            for i in range(start, min(start + 256, total)):
                session.add_packet(_pkt(i))
    elapsed = time.perf_counter() - started
    session.finalize()
    assert session.packet_count() == total
    # Very loose bound: catches a regression to commit-per-packet, not CPU speed.
    assert elapsed < 15.0
    rate = total / elapsed
    assert rate > 100  # packets/s


def test_wal_and_tuning_pragmas(tmp_path):
    session = _session(tmp_path, "pragmas")
    conn = session.writer()
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA synchronous").fetchone()[0] in (1, 2)  # NORMAL/FULL

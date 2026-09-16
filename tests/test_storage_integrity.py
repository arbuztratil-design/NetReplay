"""Phase 2 #18: capture-integrity metadata (drops, malformed, gaps)."""
from __future__ import annotations

from netreplay.core.storage import open_session


def test_integrity_clean_session(tmp_path):
    session = open_session(tmp_path / "clean.nrp", create=True)
    session.finalize()
    report = session.integrity_report()
    assert report.dropped == 0
    assert report.malformed == 0
    assert report.gaps == 0
    assert report.is_complete is True
    assert report.status == "complete"
    assert report.integrity_hash


def test_integrity_records_malformed(tmp_path):
    session = open_session(tmp_path / "mal.nrp", create=True)
    session.finalize(malformed=3)
    report = session.integrity_report()
    assert report.malformed == 3
    assert report.is_complete is False
    assert report.status == "degraded"
    assert session.info().malformed_packets == 3


def test_integrity_records_drops(tmp_path):
    session = open_session(tmp_path / "drop.nrp", create=True)
    session.finalize(dropped=7)
    assert session.info().dropped_packets == 7
    assert session.integrity_report().status == "degraded"


def test_integrity_counts_gaps(tmp_path):
    session = open_session(tmp_path / "gaps.nrp", create=True)
    session.add_event(1.0, "STREAM_GAP", 1, "gap at seq=100")
    session.add_event(2.0, "STREAM_GAP", 1, "gap at seq=500")
    session.add_event(3.0, "TCP", 1, "ack")
    session.finalize()
    report = session.integrity_report()
    assert report.gaps == 2
    assert session.info().gaps == 2

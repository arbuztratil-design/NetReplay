"""Phase 1 #4-5: strict session lifecycle and immediate session_id."""
from __future__ import annotations

import sqlite3
import time

from netreplay.core.capture import MockBackend
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.service import NetReplayService
from netreplay.core.storage import open_session
from netreplay.core.storage.database import SessionStatus


def test_lifecycle_created_capturing_ready(tmp_path):
    session = open_session(tmp_path / "life.nrp", create=True)
    assert session.status() == SessionStatus.CREATED.value
    assert session.info().status == "created"

    session.add_packet(ParsedPacket(
        ts=1.0, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
        src_port=1, dst_port=2, length=10, raw=b"x", flow_id=None,
    ))
    assert session.status() == SessionStatus.CAPTURING.value

    session.finalize()
    assert session.status() == SessionStatus.READY.value
    assert session.info().status == "ready"


def test_lifecycle_failed_and_archived(tmp_path):
    session = open_session(tmp_path / "term.nrp", create=True)
    session.set_status(SessionStatus.FAILED)
    assert session.status() == "failed"
    session.archive()
    assert session.status() == "archived"


def test_finalize_can_mark_failed(tmp_path):
    session = open_session(tmp_path / "fail.nrp", create=True)
    session.finalize(status=SessionStatus.FAILED)
    assert session.status() == "failed"


def test_legacy_complete_normalized_to_ready(tmp_path):
    path = tmp_path / "legacy.nrp"
    session = open_session(path, create=True)
    session.finalize()
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE sessions SET status='complete'")
        conn.commit()
    assert open_session(path).status() == "ready"


def test_session_id_available_immediately_after_start(tmp_path):
    service = NetReplayService(tmp_path)
    backend = MockBackend(packets=40)
    controller = service.start_capture(
        interface="mock", output=tmp_path / "imm.nrp", backend=backend
    )
    # No polling: the id must already be known the moment start() returned.
    assert controller.session_id is not None
    assert controller.status().session_id == controller.session_id

    deadline = time.time() + 20
    while controller.status().running and time.time() < deadline:
        time.sleep(0.02)
    controller.stop(timeout=5)

    info = open_session(tmp_path / "imm.nrp").info()
    assert info.session_id == controller.session_id
    assert info.status == "ready"

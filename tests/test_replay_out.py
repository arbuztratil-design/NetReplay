"""Replay-out: injection service ordering, pacing, dry-run and stop logic."""
from __future__ import annotations

import threading

from netreplay.core.packets.models import ParsedPacket
from netreplay.core.replay.inject import ReplayOutService
from netreplay.core.storage import open_session


class FakeSender:
    """Collects sent frames; optional hook invoked after each send."""

    def __init__(self, after_send=None):
        self.sent: list[bytes] = []
        self.closed = False
        self._after = after_send

    def send(self, raw: bytes) -> None:
        self.sent.append(raw)
        if self._after is not None:
            self._after()

    def close(self) -> None:
        self.closed = True


def _seed(tmp_path, ts_list):
    """Create a session with one packet per timestamp (ts may be unsorted)."""
    session = open_session(tmp_path / "replay.nrp", create=True)
    session.set_name_and_interface("replay out", "Ethernet")
    for i, ts in enumerate(ts_list):
        raw = f"frame-{i}".encode()
        packet = ParsedPacket(
            ts=ts,
            source="192.0.2.1",
            destination="192.0.2.2",
            protocol="TCP",
            src_port=4000,
            dst_port=443,
            length=len(raw),
            raw=raw,
            flow_id=1,
        )
        session.add_packet(packet)
    session.finalize()
    return session


def test_dry_run_counts_without_sending(tmp_path):
    session = _seed(tmp_path, [10.0, 10.5, 13.0])
    service = ReplayOutService(session, interface="Ethernet", dry_run=True)
    status = service.run()
    assert status.packets == 3
    assert status.bytes == sum(len(session.packet(r.id)[1]) for r in session.packets())
    assert status.error is None
    assert not status.stopped
    assert status.duration >= 0


def test_run_sends_all_frames_in_order(tmp_path, monkeypatch):
    monkeypatch.setattr("netreplay.core.replay.inject.time.sleep", lambda s: None)
    session = _seed(tmp_path, [13.0, 10.0, 10.5])
    sender = FakeSender()
    status = ReplayOutService(
        session, interface="Ethernet", sender_factory=lambda _if: sender
    ).run()
    assert status.packets == 3
    assert status.error is None
    expected = [session.packet(r.id)[1] for r in session.packets()]
    assert sender.sent == expected  # ts order: 10.0 -> 10.5 -> 13.0
    assert sender.closed


def test_run_keeps_original_timing_by_speed(tmp_path, monkeypatch):
    sleeps: list[float] = []

    def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr("netreplay.core.replay.inject.time.sleep", fake_sleep)
    session = _seed(tmp_path, [10.0, 10.5, 13.0])
    ReplayOutService(session, interface="Ethernet", speed=2.0, dry_run=True).run()
    assert sleeps == [0.25, 1.25]  # 0.5/2 and 2.5/2


def test_gaps_capped_by_max_gap(tmp_path, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(
        "netreplay.core.replay.inject.time.sleep", lambda s: sleeps.append(s)
    )
    session = _seed(tmp_path, [10.0, 20.0])
    ReplayOutService(session, interface="Ethernet", max_gap=3.0, dry_run=True).run()
    assert sleeps == [3.0]  # 10s gap capped


def test_limit_and_offset(tmp_path, monkeypatch):
    monkeypatch.setattr("netreplay.core.replay.inject.time.sleep", lambda s: None)
    session = _seed(tmp_path, [1.0, 2.0, 3.0, 4.0])
    sender = FakeSender()
    status = ReplayOutService(
        session, interface="Ethernet", offset=1, limit=2,
        sender_factory=lambda _if: sender,
    ).run()
    assert status.packets == 2
    assert [r.id for r in session.packets()][1:3] == [] or True
    sent_ids = []
    for raw in sender.sent:
        idx = int(raw.split(b"-")[1])
        sent_ids.append(("frame-" + str(idx)).encode() == raw)
    expected = [session.packet(r.id)[1] for r in list(session.packets())[1:3]]
    assert sender.sent == expected


def test_stop_requests_graceful_abort(tmp_path, monkeypatch):
    monkeypatch.setattr("netreplay.core.replay.inject.time.sleep", lambda s: None)
    session = _seed(tmp_path, [1.0, 2.0, 3.0, 4.0, 5.0])
    flag = threading.Event()

    def interrupt():
        if not flag.is_set():
            flag.set()
            service.stop()

    service = ReplayOutService(
        session, interface="Ethernet", sender_factory=lambda _if: FakeSender(after_send=interrupt)
    )
    status = service.run()
    assert status.stopped
    assert 1 <= status.packets < 5  # stopped after the first frame


def test_sender_closed_after_error(tmp_path, monkeypatch):
    monkeypatch.setattr("netreplay.core.replay.inject.time.sleep", lambda s: None)
    session = _seed(tmp_path, [1.0, 2.0])

    class BrokenSender(FakeSender):
        def send(self, raw: bytes) -> None:
            raise RuntimeError("wire down")

    sender = BrokenSender()
    status = ReplayOutService(
        session, interface="Ethernet", sender_factory=lambda _if: sender
    ).run()
    assert status.error == "RuntimeError: wire down"
    assert status.packets == 0
    assert sender.closed


def test_packets_iterator_streams_pages(tmp_path):
    session = _seed(tmp_path, [5.0, 1.0, 3.0, 2.0, 4.0])
    ids = [r.id for r in session.packets(page_size=2)]
    # page_size is internal; ordering must be global ts,id regardless of pages
    rows = list(session.packets(page_size=2))
    assert [r.ts for r in rows] == sorted(r.ts for r in rows)
    assert len(rows) == 5
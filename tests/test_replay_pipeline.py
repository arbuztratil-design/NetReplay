"""P1 #31-38: ReplayOutService modes, selection, transforms and stats."""
from __future__ import annotations

from netreplay.core.packets.models import ParsedPacket
from netreplay.core.replay.inject import ReplayOutService
from netreplay.core.replay.mutation import MutationPipeline, ReplacePattern
from netreplay.core.replay.remap import RemapConfig
from netreplay.core.replay.selection import ReplaySelection
from netreplay.core.replay.timing import ReplayMode
from netreplay.core.storage import open_session


class CollectSender:
    def __init__(self):
        self.sent: list[bytes] = []
        self.closed = False

    def send(self, raw: bytes) -> None:
        self.sent.append(raw)

    def close(self) -> None:
        self.closed = True


def _seed(tmp_path, rows):
    """rows: list of (ts, flow_id, raw)."""
    session = open_session(tmp_path / "pipe.nrp", create=True)
    session.set_name_and_interface("pipe", "Ethernet")
    for ts, flow_id, raw in rows:
        session.add_packet(
            ParsedPacket(
                ts=ts, source="192.0.2.1", destination="192.0.2.2",
                protocol="TCP", src_port=4000, dst_port=443,
                length=len(raw), raw=raw, flow_id=flow_id,
            )
        )
    session.finalize()
    return session


def test_faithful_mode_preserves_exact_timing(tmp_path, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("netreplay.core.replay.timing.time.sleep", lambda s: sleeps.append(s))
    session = _seed(tmp_path, [(10.0, 1, b"a"), (20.0, 1, b"b")])
    ReplayOutService(
        session, interface="Ethernet", max_gap=3.0, dry_run=True,
        mode=ReplayMode.FAITHFUL,
    ).run()
    assert sleeps == [10.0]  # not capped


def test_story_mode_caps_timing(tmp_path, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("netreplay.core.replay.timing.time.sleep", lambda s: sleeps.append(s))
    session = _seed(tmp_path, [(10.0, 1, b"a"), (20.0, 1, b"b")])
    ReplayOutService(
        session, interface="Ethernet", max_gap=3.0, dry_run=True,
        mode=ReplayMode.STORY,
    ).run()
    assert sleeps == [3.0]


def test_selection_sends_only_matching_and_counts_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr("netreplay.core.replay.timing.time.sleep", lambda s: None)
    session = _seed(tmp_path, [(1.0, 1, b"a"), (2.0, 2, b"b"), (3.0, 1, b"c")])
    sender = CollectSender()
    status = ReplayOutService(
        session, interface="Ethernet",
        selection=ReplaySelection.from_values(flow_ids=[1]),
        sender_factory=lambda _if: sender,
    ).run()
    assert sender.sent == [b"a", b"c"]
    assert status.packets == 2
    assert status.skipped == 1


def test_mutation_pipeline_rewrites_frames(tmp_path, monkeypatch):
    monkeypatch.setattr("netreplay.core.replay.timing.time.sleep", lambda s: None)
    session = _seed(tmp_path, [(1.0, 1, b"AA-payload")])
    sender = CollectSender()
    pipeline = MutationPipeline().add(ReplacePattern(b"AA", b"BB"))
    ReplayOutService(
        session, interface="Ethernet", pipeline=pipeline,
        sender_factory=lambda _if: sender,
    ).run()
    assert sender.sent == [b"BB-payload"]


def test_remap_rewrites_frame_fields(tmp_path, monkeypatch):
    monkeypatch.setattr("netreplay.core.replay.timing.time.sleep", lambda s: None)
    from scapy.all import IP, TCP, Ether

    frame = bytes(Ether(src="aa:aa:aa:aa:aa:01", dst="bb:bb:bb:bb:bb:02")
                  / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=443))
    session = _seed(tmp_path, [(1.0, 1, frame)])
    sender = CollectSender()
    remap = RemapConfig.build(ip_map={"10.0.0.1": "172.16.0.1"})
    ReplayOutService(
        session, interface="Ethernet", remap=remap,
        sender_factory=lambda _if: sender,
    ).run()
    assert IP(sender.sent[0][14:]).src == "172.16.0.1"


def test_validation_drops_invalid_frames(tmp_path, monkeypatch):
    monkeypatch.setattr("netreplay.core.replay.timing.time.sleep", lambda s: None)
    session = _seed(tmp_path, [(1.0, 1, b"tiny"), (2.0, 1, b"also-tiny")])
    sender = CollectSender()
    status = ReplayOutService(
        session, interface="Ethernet", validate=True,
        sender_factory=lambda _if: sender,
    ).run()
    assert sender.sent == []
    assert status.failed == 2
    assert status.packets == 0


def test_offset_counts_as_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr("netreplay.core.replay.timing.time.sleep", lambda s: None)
    session = _seed(tmp_path, [(1.0, 1, b"a"), (2.0, 1, b"b"), (3.0, 1, b"c")])
    sender = CollectSender()
    status = ReplayOutService(
        session, interface="Ethernet", offset=1, limit=2,
        sender_factory=lambda _if: sender,
    ).run()
    assert sender.sent == [b"b", b"c"]
    assert status.skipped == 1


def test_status_mode_and_drift_present(tmp_path, monkeypatch):
    monkeypatch.setattr("netreplay.core.replay.timing.time.sleep", lambda s: None)
    session = _seed(tmp_path, [(1.0, 1, b"a"), (2.0, 1, b"b")])
    status = ReplayOutService(
        session, interface="Ethernet", dry_run=True,
        mode=ReplayMode.FAITHFUL,
    ).run()
    assert status.mode == "faithful"
    assert isinstance(status.timing_drift, float)
    assert status.failed == 0


def test_api_accepts_mode_and_selection(tmp_path, monkeypatch):
    import time

    from fastapi.testclient import TestClient

    from netreplay.api import create_app

    monkeypatch.setattr("netreplay.core.replay.timing.time.sleep", lambda s: None)
    session = _seed(tmp_path, [(1.0, 1, b"a"), (2.0, 2, b"b")])
    session_id = session.meta("session_id")
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.post(
            f"/api/replay-out/{session_id}",
            json={
                "interface": "Ethernet",
                "dry_run": True,
                "mode": "faithful",
                "flow_ids": [1],
                "validate_frames": False,
            },
        )
        assert r.status_code == 200
        assert r.json()["mode"] == "faithful"

        body = {"running": True}
        for _ in range(100):
            body = client.get("/api/replay-out/status").json()
            if not body.get("running"):
                break
            time.sleep(0.02)
        assert body["packets"] == 1
        assert body["skipped"] == 1
        assert body["mode"] == "faithful"
        client.post("/api/replay-out/stop")


def test_api_rejects_bad_mode(tmp_path):
    from fastapi.testclient import TestClient

    from netreplay.api import create_app

    session = _seed(tmp_path, [(1.0, 1, b"a")])
    session_id = session.meta("session_id")
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.post(
            f"/api/replay-out/{session_id}",
            json={"interface": "Ethernet", "dry_run": True, "mode": "warp"},
        )
        assert r.status_code == 422

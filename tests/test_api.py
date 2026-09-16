"""FastAPI endpoint tests (no live capture)."""
from __future__ import annotations

import time

from fastapi.testclient import TestClient

from netreplay.api import create_app
from netreplay.core.storage import open_session


def _seed(tmp_path, name="seed session"):
    session = open_session(tmp_path / "s1.nrp", create=True)
    session.set_name_and_interface(name, interface="lo")
    from netreplay.core.flows.models import Flow

    session.upsert_flow(
        Flow(id=7, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
             src_port=1000, dst_port=443, start_ts=100.0, end_ts=200.0,
             packet_count=3, bytes=2000, state="ESTABLISHED")
    )
    from netreplay.core.packets.models import ParsedPacket

    for ts in (100.0, 150.0, 200.0):
        session.add_packet(
            ParsedPacket(
                ts=ts,
                source="10.0.0.1",
                destination="10.0.0.2",
                protocol="TCP",
                src_port=1000,
                dst_port=443,
                length=200,
                raw=b"\x00" * 128,
                flow_id=7,
            )
        )
    session.add_event(100.0, "DNS", None, "DNS QUERY example.com (A)")
    session.add_event(120.0, "TCP", 7, "TCP flow established")
    session.add_event(130.0, "TLS", 7, "TLS ClientHello TLS 1.3 sni=example.com")
    session.add_event(140.0, "TCP", 7, "TCP flow [ESTABLISHED]")
    session.finalize()
    return session.meta("session_id")


def test_sessions_and_timeline(tmp_path):
    session_id = _seed(tmp_path)
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.get("/api/sessions")
        assert r.status_code == 200
        sessions = r.json()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == session_id

        r = client.get(f"/api/sessions/{session_id}")
        info = r.json()
        assert info["packet_count"] == 3
        assert info["flow_count"] == 1
        assert info["status"] == "ready"

        r = client.get(f"/api/sessions/{session_id}/timeline")
        evs = r.json()
        assert len(evs) == 4
        assert evs[0]["type"] == "DNS"
        assert evs[1]["summary"] == "TCP flow established"

        r = client.get(
            f"/api/sessions/{session_id}/timeline",
            params={"types": "TCP,TLS", "start": 125, "end": 145},
        )
        assert [e["type"] for e in r.json()] == ["TLS", "TCP"]

        r = client.get(f"/api/sessions/{session_id}/timeline", params={"limit": 2})
        assert len(r.json()) == 2

        r = client.get(f"/api/sessions/{session_id}/flows")
        assert len(r.json()) == 1

        r = client.get("/api/flows/7?include_packets=true")
        flow = r.json()
        assert flow["packet_count"] == 3
        assert len(flow["packets"]) == 3

        r = client.get("/api/packets/1?raw=true")
        pkt = r.json()
        assert "raw_hex" in pkt
        assert pkt["flow_id"] == 7


def test_websocket_ping_pong(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        with client.websocket_connect("/ws") as ws:
            ws.send_text("ping")
            msg = ws.receive_json()
            assert msg == {"type": "pong"}


def test_capture_status_and_interfaces(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.get("/api/capture/status")
        assert r.json()["running"] is False

        r = client.get("/api/interfaces")
        assert r.status_code == 200
        assert isinstance(r.json(), list)


def test_replay_out_dry_run_cycle(tmp_path):
    session_id = _seed(tmp_path)
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        # idle state before any replay
        r = client.get("/api/replay-out/status")
        assert r.json() == {
            "running": False, "session_id": None, "interface": None,
            "packets": 0, "bytes": 0, "duration": 0.0,
            "dry_run": False, "stopped": False, "error": None,
            "skipped": 0, "failed": 0, "timing_drift": 0.0, "mode": "story",
        }

        r = client.post(
            f"/api/replay-out/{session_id}",
            json={"interface": "Ethernet", "dry_run": True, "max_gap": 0.01},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["running"] is True
        assert body["dry_run"] is True
        assert body["interface"] == "Ethernet"
        assert body["session_id"] == session_id

        body = {"running": True}
        for _ in range(100):
            body = client.get("/api/replay-out/status").json()
            if not body.get("running"):
                break
            time.sleep(0.05)
        assert body["running"] is False
        assert body["packets"] == 3
        assert body["bytes"] == 3 * 200
        assert body["error"] is None

        r = client.post("/api/replay-out/stop")
        assert r.status_code == 200
        assert r.json()["running"] is False


def test_replay_out_unknown_session(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.post(
            "/api/replay-out/does-not-exist",
            json={"interface": "Ethernet", "dry_run": True},
        )
        assert r.status_code == 409
        assert "not found" in r.json()["detail"]


def test_replay_out_rejects_second_while_running(tmp_path):
    session_id = _seed(tmp_path)
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        first = client.post(
            f"/api/replay-out/{session_id}",
            json={
                "interface": "Ethernet", "dry_run": True,
                "speed": 20.0, "max_gap": 2.5,
            },
        )
        assert first.status_code == 200
        assert first.json()["running"] is True
        second = client.post(
            f"/api/replay-out/{session_id}",
            json={"interface": "Ethernet", "dry_run": True},
        )
        assert second.status_code == 409
        assert "already running" in second.json()["detail"]
        third = client.get("/api/replay-out/status")
        assert third.json()["running"] is True
        client.post("/api/replay-out/stop")


def test_bridge_start_stop_status(tmp_path, monkeypatch):
    import queue as _queue

    class _FakePacket:
        def __init__(self, data):
            self._data = data
        def __bytes__(self):
            return self._data

    class _FakeSniffer:
        def __init__(self, iface):
            self.iface = iface
            self._queue = _queue.Queue()
            self._queue.put(None)  # immediately stop
        @property
        def running(self):
            return False
        def start(self):
            pass
        def stop(self):
            pass

    class _FakeSender:
        def __init__(self, iface):
            self.iface = iface
        def send(self, raw):
            pass
        def close(self):
            pass

    monkeypatch.setattr(
        "netreplay.core.proxy.bridge._default_sniffer",
        lambda iface: _FakeSniffer(iface),
    )
    monkeypatch.setattr(
        "netreplay.core.proxy.bridge._default_sender",
        lambda iface: _FakeSender(iface),
    )
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.get("/api/bridge/status")
        body = r.json()
        assert body["running"] is False

        r = client.post("/api/bridge/start", json={
            "left_interface": "eth0", "right_interface": "eth1",
        })
        assert r.status_code == 200
        body = r.json()
        assert body["running"] is True
        assert body["left_interface"] == "eth0"
        assert body["right_interface"] == "eth1"

        for _ in range(50):
            body = client.get("/api/bridge/status").json()
            if not body["running"]:
                break
            time.sleep(0.05)
        assert body["running"] is False

        r = client.post("/api/bridge/stop")
        assert r.status_code == 200
        assert r.json()["running"] is False


def test_bridge_rejects_second_while_running(tmp_path, monkeypatch):
    import queue as _queue

    class _SlowSniffer:
        def __init__(self, iface):
            self.iface = iface
            self._queue = _queue.Queue()
        @property
        def running(self):
            return True
        def start(self):
            pass
        def stop(self):
            pass

    class _FakeSender:
        def __init__(self, iface):
            pass
        def send(self, raw):
            pass
        def close(self):
            pass

    monkeypatch.setattr(
        "netreplay.core.proxy.bridge._default_sniffer",
        lambda iface: _SlowSniffer(iface),
    )
    monkeypatch.setattr(
        "netreplay.core.proxy.bridge._default_sender",
        lambda iface: _FakeSender(iface),
    )
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.post("/api/bridge/start", json={
            "left_interface": "eth0", "right_interface": "eth1",
        })
        assert r.status_code == 200
        assert r.json()["running"] is True
        r2 = client.post("/api/bridge/start", json={
            "left_interface": "eth2", "right_interface": "eth3",
        })
        assert r2.status_code == 409
        assert "already running" in r2.json()["detail"]
        client.post("/api/bridge/stop")


def _seed_like(tmp_path, filename, domain, client_ip="10.0.0.1", server_ip="10.0.0.2"):
    from netreplay.core.flows.models import Flow
    from netreplay.core.packets.models import ParsedPacket

    session = open_session(tmp_path / filename, create=True)
    session.set_name_and_interface(filename, interface="lo")
    session.upsert_flow(
        Flow(id=7, source=client_ip, destination=server_ip, protocol="TCP",
             src_port=1000, dst_port=443, start_ts=100.0, end_ts=200.0,
             packet_count=3, bytes=2000, state="ESTABLISHED")
    )
    for ts in (100.0, 150.0, 200.0):
        session.add_packet(
            ParsedPacket(
                ts=ts, source=client_ip, destination=server_ip, protocol="TCP",
                src_port=1000, dst_port=443, length=200, raw=b"\x00" * 128, flow_id=7,
            )
        )
    session.add_event(100.0, "DNS", None, f"DNS QUERY {domain} (A)")
    session.add_event(130.0, "TLS", 7, f"TLS ClientHello TLS 1.3 sni={domain}")
    session.finalize()
    sid = session.meta("session_id")
    session.close()
    return sid


def test_session_search(tmp_path):
    session_id = _seed(tmp_path)
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.get(f"/api/sessions/{session_id}/search", params={"q": "example.com"})
        assert r.status_code == 200
        body = r.json()
        assert body["query"] == "example.com"
        assert body["total"] >= 2
        kinds = {e["type"] for e in body["events"]}
        assert "DNS" in kinds and "TLS" in kinds

        r = client.get(f"/api/sessions/{session_id}/search", params={"q": "10.0.0.2"})
        body = r.json()
        assert body["total"] >= 4
        assert len(body["flows"]) == 1
        assert len(body["packets"]) == 3
        assert body["flows"][0]["destination"] == "10.0.0.2"

        r = client.get(f"/api/sessions/{session_id}/search", params={"q": "zzz-no-match"})
        assert r.json()["total"] == 0


def test_session_scoped_packet_flow(tmp_path):
    """Session-scoped packet/flow routes resolve ids unambiguously, even when
    two sessions reuse the same integer id."""
    from netreplay.core.packets.models import ParsedPacket

    s1 = _seed(tmp_path)  # s1.nrp: packets 1..3, flow 7
    s2_path = tmp_path / "s2.nrp"
    s2 = open_session(s2_path, create=True)
    s2.set_name_and_interface("second session", interface="lo")
    s2.upsert_flow(
        __import__("netreplay.core.flows.models", fromlist=["Flow"]).Flow(
            id=7, source="198.51.100.1", destination="198.51.100.2", protocol="TCP",
            src_port=1000, dst_port=443, start_ts=50.0, end_ts=60.0,
            packet_count=1, bytes=100, state="SYN",
        )
    )
    s2.add_packet(ParsedPacket(ts=50.0, source="198.51.100.1", destination="198.51.100.2",
                               protocol="TCP", src_port=1000, dst_port=443,
                               length=100, raw=b"\x01" * 100, flow_id=7))
    s2.finalize()
    s2_id = s2.meta("session_id")
    s2.close()

    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        # Same integer id, different sessions -> distinct packets.
        r1 = client.get(f"/api/sessions/{s1}/packets/1?raw=true")
        assert r1.status_code == 200
        assert r1.json()["source"] == "10.0.0.1"

        r2 = client.get(f"/api/sessions/{s2_id}/packets/1?raw=true")
        assert r2.status_code == 200
        assert r2.json()["source"] == "198.51.100.1"

        # Same integer flow id, different sessions -> distinct flows.
        f1 = client.get(f"/api/sessions/{s1}/flows/7")
        assert f1.status_code == 200
        assert f1.json()["source"] == "10.0.0.1"

        f2 = client.get(f"/api/sessions/{s2_id}/flows/7?include_packets=true")
        assert f2.status_code == 200
        assert f2.json()["source"] == "198.51.100.1"
        assert len(f2.json()["packets"]) == 1

        # Unknown ids within a known session -> 404.
        assert client.get(f"/api/sessions/{s1}/packets/999").status_code == 404
        assert client.get(f"/api/sessions/{s1}/flows/999").status_code == 404
        # Unknown session -> 404.
        assert client.get("/api/sessions/nope/packets/1").status_code == 404
        assert client.get("/api/sessions/nope/flows/7").status_code == 404

        # Legacy cross-session routes still resolve (deprecated).
        assert client.get("/api/packets/1").status_code == 200
        assert client.get("/api/flows/7").status_code == 200


def test_session_similar(tmp_path):
    s1 = _seed(tmp_path)
    s2 = _seed_like(tmp_path, "s2.nrp", "example.com")
    s3 = _seed_like(
        tmp_path,
        "s3.nrp",
        "unrelated.net",
        client_ip="172.16.0.9",
        server_ip="1.2.3.4",
    )
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.get(f"/api/sessions/{s1}/similar", params={"top": 5})
        assert r.status_code == 200
        items = r.json()
        ids = [i["session_id"] for i in items]
        assert s1 not in ids
        assert s2 in ids
        assert items[0]["session_id"] == s2
        assert items[0]["score"] > 0.9
        if s3 in items:
            assert ids.index(s2) < ids.index(s3)

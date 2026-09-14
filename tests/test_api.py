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
        pid = session.add_packet(
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
        assert info["status"] == "complete"

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
"""P2 API endpoints: compare, incidents, export, sanitize, regression."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from netreplay.api import create_app
from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage import open_session


def _seed(tmp_path, name):
    session = open_session(tmp_path / f"{name}.nrp", create=True)
    session.set_name_and_interface(name, interface="lo")
    session.upsert_flow(Flow(id=1, source="10.0.0.1", destination="10.0.0.2",
                             protocol="TCP", src_port=1000, dst_port=443,
                             start_ts=0.0, end_ts=1.0, packet_count=2, bytes=200,
                             state="ESTABLISHED"))
    for i in range(2):
        session.add_packet(ParsedPacket(
            ts=float(i), source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
            src_port=1000, dst_port=443, length=100, raw=b"\x00" * 64, flow_id=1,
        ))
    session.add_event(0.5, "DNS", None, "DNS QUERY example.com")
    session.finalize()
    return session.meta("session_id")


def test_api_compare(tmp_path):
    a = _seed(tmp_path, "a")
    b = _seed(tmp_path, "b")
    with TestClient(create_app(tmp_path), raise_server_exceptions=True) as client:
        r = client.get(f"/api/sessions/{a}/compare/{b}")
        assert r.status_code == 200
        body = r.json()
        assert body["identical"] is True
        assert body["flows"]["changed"] == 0
        assert any(e["type"] == "DNS" for e in body["events"])


def test_api_incidents(tmp_path):
    _seed(tmp_path, "a")
    _seed(tmp_path, "b")
    a = open_session(tmp_path / "a.nrp").meta("session_id")
    with TestClient(create_app(tmp_path), raise_server_exceptions=True) as client:
        r = client.get(f"/api/sessions/{a}/incidents", params={"top": 5})
        assert r.status_code == 200
        assert isinstance(r.json(), list)


def test_api_export_json_and_csv(tmp_path):
    a = _seed(tmp_path, "a")
    with TestClient(create_app(tmp_path), raise_server_exceptions=True) as client:
        r = client.get(f"/api/sessions/{a}/export", params={"format": "json"})
        assert r.status_code == 200
        doc = json.loads(r.text)
        assert len(doc["packets"]) == 2

        r2 = client.get(f"/api/sessions/{a}/export", params={"format": "csv", "kind": "flows"})
        assert r2.status_code == 200
        assert "protocol" in r2.text.splitlines()[0]


def test_api_sanitize(tmp_path):
    a = _seed(tmp_path, "a")
    with TestClient(create_app(tmp_path), raise_server_exceptions=True) as client:
        r = client.post(f"/api/sessions/{a}/sanitize")
        assert r.status_code == 200
        body = r.json()
        assert body["packets"] == 2
        assert "ips" in body["redacted"]


def test_api_regression(tmp_path):
    _seed(tmp_path, "a")
    with TestClient(create_app(tmp_path), raise_server_exceptions=True) as client:
        payload = {"cases": [{
            "name": "inline",
            "session": "a.nrp",
            "expect": {"min_packets": 1, "event_types": ["DNS"]},
        }]}
        r = client.post("/api/regression/run", json=payload)
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["passed"] == 1

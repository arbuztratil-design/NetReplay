"""API endpoints added for full GUI coverage: scenarios, filter, layers, loss."""
from __future__ import annotations

from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Ether

from netreplay.api import create_app
from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage import open_session


def _seed(tmp_path, name="s"):
    session = open_session(tmp_path / f"{name}.nrp", create=True)
    session.set_name_and_interface(name, interface="lo")
    session.upsert_flow(Flow(id=1, source="10.0.0.1", destination="10.0.0.2",
                             protocol="TCP", src_port=1000, dst_port=443,
                             start_ts=0.0, end_ts=1.0, packet_count=2, bytes=200,
                             state="ESTABLISHED"))
    frame = bytes(Ether(src="aa:aa:aa:aa:aa:01", dst="bb:bb:bb:bb:bb:02")
                  / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=443) / b"hi")
    session.add_packet(ParsedPacket(
        ts=0.0, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
        src_port=1000, dst_port=443, length=len(frame), raw=frame, flow_id=1,
    ))
    session.add_packet(ParsedPacket(
        ts=1.0, source="10.0.0.2", destination="10.0.0.1", protocol="TCP",
        src_port=443, dst_port=1000, length=len(frame), raw=frame, flow_id=1,
    ))
    session.add_event(0.5, "STREAM_GAP", 1, "gap at seq=100 len=50")
    session.add_event(0.6, "DNS", None, "DNS QUERY example.com")
    session.finalize()
    return session.meta("session_id")


def _client(tmp_path):
    return TestClient(create_app(tmp_path), raise_server_exceptions=True)


def test_scenario_crud_and_runs_api(tmp_path):
    sid = _seed(tmp_path)
    with _client(tmp_path) as client:
        r = client.post(f"/api/sessions/{sid}/scenarios", json={
            "name": "dns probe", "flow_ids": [1], "tags": ["dns"],
        })
        assert r.status_code == 200, r.text
        scenario = r.json()
        assert scenario["name"] == "dns probe"
        scenario_id = scenario["id"]

        r = client.get(f"/api/sessions/{sid}/scenarios")
        assert len(r.json()) == 1

        r = client.patch(f"/api/sessions/{sid}/scenarios/{scenario_id}",
                         json={"name": "renamed", "status": "ready"})
        assert r.json()["name"] == "renamed"
        assert r.json()["status"] == "ready"

        r = client.post(f"/api/sessions/{sid}/scenarios/{scenario_id}/runs", json={"name": "run-1"})
        assert r.status_code == 200
        run_id = r.json()["id"]

        r = client.patch(f"/api/sessions/{sid}/runs/{run_id}",
                         json={"status": "done", "result": {"sent": 2}})
        assert r.json()["status"] == "done"
        assert r.json()["result"]["sent"] == 2

        r = client.get(f"/api/sessions/{sid}/scenarios/{scenario_id}/runs")
        assert len(r.json()) == 1

        r = client.delete(f"/api/sessions/{sid}/scenarios/{scenario_id}")
        assert r.status_code == 200
        assert client.get(f"/api/sessions/{sid}/scenarios").json() == []


def test_annotations_api(tmp_path):
    sid = _seed(tmp_path)
    with _client(tmp_path) as client:
        r = client.post(f"/api/sessions/{sid}/annotations", json={
            "target": "packet", "target_id": 1, "label": "suspicious", "color": "red",
        })
        assert r.status_code == 200, r.text
        ann = r.json()
        assert ann["target"] == "packet"
        assert ann["label"] == "suspicious"

        r = client.get(f"/api/sessions/{sid}/annotations")
        assert len(r.json()) == 1

        r = client.delete(f"/api/sessions/{sid}/annotations/{ann['id']}")
        assert r.status_code == 200
        assert client.get(f"/api/sessions/{sid}/annotations").json() == []


def test_filter_endpoint(tmp_path):
    sid = _seed(tmp_path)
    with _client(tmp_path) as client:
        r = client.get(f"/api/sessions/{sid}/filter", params={"expr": "port == 443", "kind": "flows"})
        assert r.status_code == 200, r.text
        assert r.json()["count"] == 1

        r = client.get(f"/api/sessions/{sid}/filter", params={"expr": "dns", "kind": "events"})
        assert r.json()["count"] == 1

        r = client.get(f"/api/sessions/{sid}/filter", params={"expr": "bogus =="})
        assert r.status_code == 422


def test_layers_endpoint(tmp_path):
    sid = _seed(tmp_path)
    with _client(tmp_path) as client:
        r = client.get(f"/api/sessions/{sid}/packets/1/layers")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["layers"]["name"] == "Ethernet"
        assert body["layers"]["children"][0]["name"] == "IP"
        assert body["size"] > 0
        assert body["hex"]


def test_loss_endpoint(tmp_path):
    sid = _seed(tmp_path)
    with _client(tmp_path) as client:
        r = client.get(f"/api/sessions/{sid}/loss")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 1
        assert body["gaps"] == 1


def test_replay_accepts_remap_and_mutation(tmp_path):
    sid = _seed(tmp_path)
    with _client(tmp_path) as client:
        r = client.post(f"/api/replay-out/{sid}", json={
            "interface": "Ethernet",
            "dry_run": True,
            "ip_map": {"10.0.0.1": "172.16.0.1"},
            "port_map": {"443": 8443},
            "mutations": [{"type": "truncate", "max_length": 40}],
        })
        assert r.status_code == 200, r.text
        client.post("/api/replay-out/stop")

        r = client.post(f"/api/replay-out/{sid}", json={
            "interface": "Ethernet", "dry_run": True,
            "mutations": [{"type": "bogus"}],
        })
        assert r.status_code == 422
        client.post("/api/replay-out/stop")

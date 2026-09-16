"""GUI client coverage: every feature reachable through gui.api.NetReplayClient."""
from __future__ import annotations

from urllib.parse import urlparse

from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Ether

from gui.api import NetReplayClient
from gui.components.toolbox import Toolbox
from netreplay.api import create_app
from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage import open_session


class _Adapter:
    """Routes NetReplayClient calls into a FastAPI TestClient (no sockets)."""

    def __init__(self, client: TestClient):
        self._client = client

    def get(self, url, params=None):
        return self._client.get(urlparse(url).path, params=params)

    def post(self, url, json=None):
        return self._client.post(urlparse(url).path, json=json)

    def patch(self, url, json=None):
        return self._client.patch(urlparse(url).path, json=json)

    def delete(self, url):
        return self._client.delete(urlparse(url).path)


def _seed(tmp_path, name="s"):
    session = open_session(tmp_path / f"{name}.nrp", create=True)
    session.set_name_and_interface(name, interface="lo")
    session.upsert_flow(Flow(id=1, source="10.0.0.1", destination="10.0.0.2",
                             protocol="TCP", src_port=1000, dst_port=443,
                             start_ts=0.0, end_ts=1.0, packet_count=2, bytes=200,
                             state="ESTABLISHED"))
    frame = bytes(Ether(src="aa:aa:aa:aa:aa:01", dst="bb:bb:bb:bb:bb:02")
                  / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=443) / b"hi")
    session.add_packet(ParsedPacket(ts=0.0, source="10.0.0.1", destination="10.0.0.2",
                                    protocol="TCP", src_port=1000, dst_port=443,
                                    length=len(frame), raw=frame, flow_id=1))
    session.add_event(0.5, "STREAM_GAP", 1, "gap at seq=100")
    session.add_event(0.6, "DNS", None, "DNS QUERY example.com")
    session.finalize()
    return session.meta("session_id")


def _client(tmp_path):
    app = create_app(tmp_path)
    tc = TestClient(app, raise_server_exceptions=True)
    tc.__enter__()
    client = NetReplayClient("http://test")
    client._client = _Adapter(tc)
    return client, tc


def test_client_core_reads(tmp_path):
    sid = _seed(tmp_path)
    client, tc = _client(tmp_path)
    try:
        assert client.sessions()[0]["session_id"] == sid
        stats = client.stats(sid)
        assert stats["flow_count"] == 1
        assert client.flows(sid)[0]["dst_port"] == 443
        assert client.packet_layers(sid, 1)["layers"]["name"] == "Ethernet"
        assert client.loss(sid)["gaps"] == 1
        assert client.filter_session(sid, "dns", "events")["count"] == 1
        assert client.packets_page(sid, limit=1)["total"] == 1
    finally:
        tc.__exit__(None, None, None)


def test_client_scenarios_and_annotations(tmp_path):
    sid = _seed(tmp_path)
    client, tc = _client(tmp_path)
    try:
        scenario = client.create_scenario(sid, name="gui", flow_ids=[1], tags=["x"])
        assert client.scenarios(sid)[0]["id"] == scenario["id"]
        client.update_scenario(sid, scenario["id"], status="ready")
        assert client.scenarios(sid)[0]["status"] == "ready"
        run = client.create_run(sid, scenario["id"], name="r1")
        client.update_run(sid, run["id"], status="done", result={"sent": 2})
        assert client.runs(sid, scenario["id"])[0]["result"]["sent"] == 2

        ann = client.add_annotation(sid, "packet", 1, label="mark")
        assert client.annotations(sid)[0]["id"] == ann["id"]
        client.delete_annotation(sid, ann["id"])
        assert client.annotations(sid) == []

        client.delete_scenario(sid, scenario["id"])
        assert client.scenarios(sid) == []
    finally:
        tc.__exit__(None, None, None)


def test_client_forensics_and_export(tmp_path):
    sid = _seed(tmp_path)
    _seed(tmp_path, "other")
    client, tc = _client(tmp_path)
    try:
        sessions = client.sessions()
        other = next(s["session_id"] for s in sessions if s["session_id"] != sid)
        assert client.compare(sid, other)["identical"] is True
        assert isinstance(client.incidents(sid, top=3), list)
        assert "packets" in client.export_text(sid, "json")
        assert client.sanitize(sid)["packets"] == 1
    finally:
        tc.__exit__(None, None, None)


def test_client_regression_and_replay(tmp_path):
    sid = _seed(tmp_path)
    client, tc = _client(tmp_path)
    try:
        report = client.regression_run([{
            "name": "gui case", "session": "s.nrp",
            "expect": {"min_packets": 1, "event_types": ["DNS"]},
        }])
        assert report["ok"] is True

        started = client.replay_start(
            sid, "Ethernet", dry_run=True, mode="faithful",
            flow_ids=[1], validate_frames=False,
            ip_map={"10.0.0.1": "172.16.0.1"}, port_map={443: 8443},
            mutations=[{"type": "truncate", "max_length": 40}],
        )
        assert started["mode"] == "faithful"
        client.replay_stop()
    finally:
        tc.__exit__(None, None, None)


def test_toolbox_builds_and_reports(tmp_path):
    sid = _seed(tmp_path)
    client, tc = _client(tmp_path)
    try:
        tb = Toolbox(
            client,
            lambda: sid,
            lambda: client.sessions(),
            lambda: "Ethernet",
            lambda: None,
        )
        controls = tb.controls()
        assert controls
        tb.refresh_dynamic()
        # exercise a few handlers through their public side effects
        tb._show_loss(sid)
        assert "gaps=1" in tb._output.value
        tb._show_layers(sid, 1)
        assert "Ethernet" in tb._output.value
        tb._show_filter(sid, "port == 443")
        assert "match" in tb._output.value
        tb._stop_replay()
    finally:
        tc.__exit__(None, None, None)

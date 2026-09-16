"""P1 #27-28: paginated packet API and aggregate session statistics."""
from __future__ import annotations

from fastapi.testclient import TestClient

from netreplay.api import create_app
from netreplay.core.stats import compute_stats
from netreplay.core.storage import open_session


def _seed(tmp_path, name="pages"):
    session = open_session(tmp_path / "p.nrp", create=True)
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
            ParsedPacket(ts=ts, source="10.0.0.1", destination="10.0.0.2",
                         protocol="TCP", src_port=1000, dst_port=443,
                         length=200, raw=b"\x01" * 64, flow_id=7)
        )
    session.add_event(110.0, "STREAM_RETRANSMISSION", 7, "retransmission at seq=100")
    session.finalize()
    return session


def test_packets_page_storage(tmp_path) -> None:
    session = _seed(tmp_path)
    rows, total = session.packets_page(limit=2, offset=0)
    assert total == 3
    assert len(rows) == 2
    assert [r.ts for r in rows] == [100.0, 150.0]
    rows2, _ = session.packets_page(limit=2, offset=2)
    assert len(rows2) == 1
    assert rows2[0].ts == 200.0


def test_packets_page_rejects_bad_args(tmp_path) -> None:
    session = _seed(tmp_path)
    import pytest

    with pytest.raises(ValueError):
        session.packets_page(limit=0)
    with pytest.raises(ValueError):
        session.packets_page(offset=-1)


def test_packets_page_api_pagination(tmp_path) -> None:
    session = _seed(tmp_path)
    session_id = session.meta("session_id")
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.get(f"/api/sessions/{session_id}/packets", params={"limit": 2, "offset": 0})
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 3
        assert body["limit"] == 2
        assert len(body["packets"]) == 2
        assert body["packets"][0]["raw_hex"] is None

        r2 = client.get(f"/api/sessions/{session_id}/packets", params={"limit": 2, "offset": 2})
        assert len(r2.json()["packets"]) == 1

        assert client.get(f"/api/sessions/{session_id}/packets", params={"limit": 0}).status_code == 422


def test_compute_stats(tmp_path) -> None:
    session = _seed(tmp_path)
    stats = compute_stats(session)
    assert stats.packet_count == 3
    assert stats.byte_count == 2000
    assert stats.flow_count == 1
    assert stats.duration == 100.0
    assert stats.average_packet_size == 2000 / 3
    assert stats.reset_count == 0
    assert stats.retransmission_count == 1
    assert stats.has_traffic is True


def test_stats_api(tmp_path) -> None:
    session = _seed(tmp_path)
    session_id = session.meta("session_id")
    app = create_app(tmp_path)
    with TestClient(app, raise_server_exceptions=True) as client:
        r = client.get(f"/api/sessions/{session_id}/stats")
        assert r.status_code == 200
        body = r.json()
        assert body["packet_count"] == 3
        assert body["byte_count"] == 2000
        assert body["flow_count"] == 1
        assert body["retransmission_count"] == 1
        assert body["duration"] == 100.0

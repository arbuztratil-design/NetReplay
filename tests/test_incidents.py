"""P2 #45-46: behavioural fingerprints and similar-incident search."""
from __future__ import annotations

from netreplay.core.flows.models import Flow
from netreplay.core.incidents import (
    IncidentProbe,
    build_fingerprint,
    find_similar_incidents,
    fingerprint_similarity,
    port_category,
    search_by_probe,
)
from netreplay.core.storage import open_session


def _seed(tmp_path, name, flows, events):
    session = open_session(tmp_path / f"{name}.nrp", create=True)
    session.set_name_and_interface(name, interface="lo")
    for flow in flows:
        session.upsert_flow(flow)
    for ts, etype, flow_id, summary in events:
        session.add_event(ts, etype, flow_id, summary)
    session.finalize()
    return session


def _flow(id, src, dst, sport, dport, proto="TCP"):
    return Flow(id=id, source=src, destination=dst, protocol=proto, src_port=sport,
                dst_port=dport, start_ts=0.0, end_ts=1.0, packet_count=1, bytes=100, state="ESTABLISHED")


def test_port_category() -> None:
    assert port_category(443) == "web-alt"
    assert port_category(53) == "dns"
    assert port_category(22) == "well-known"
    assert port_category(50000) == "ephemeral"
    assert port_category(None) == "none"


def test_fingerprint_is_address_independent(tmp_path) -> None:
    a = _seed(tmp_path, "a", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 443)], [(1.0, "TLS", None, "h")])
    b = _seed(tmp_path, "b", [_flow(1, "192.168.1.1", "8.8.8.8", 4000, 443)], [(1.0, "TLS", None, "h")])
    fa = build_fingerprint(a)
    fb = build_fingerprint(b)
    # Different addresses, same behaviour -> identical similarity
    assert fingerprint_similarity(fa, fb) == 1.0


def test_fingerprint_similarity_scales(tmp_path) -> None:
    a = _seed(tmp_path, "a", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 443)], [(1.0, "TLS", None, "h")])
    b = _seed(tmp_path, "b", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 53, proto="UDP")], [(1.0, "DNS", None, "q")])
    score = fingerprint_similarity(build_fingerprint(a), build_fingerprint(b))
    assert 0.0 <= score < 1.0


def test_find_similar_incidents_ranks_target(tmp_path) -> None:
    _seed(tmp_path, "target", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 443)], [(1.0, "TLS", None, "h")])
    _seed(tmp_path, "same", [_flow(1, "1.1.1.1", "2.2.2.2", 5000, 443)], [(1.0, "TLS", None, "h")])
    _seed(tmp_path, "other", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 53, proto="UDP")], [(1.0, "DNS", None, "q")])
    matches = find_similar_incidents(tmp_path / "target.nrp", workspace=tmp_path)
    assert matches
    assert matches[0].name == "same"
    assert matches[0].score >= matches[-1].score


def test_incident_probe_from_session_and_search(tmp_path) -> None:
    a = _seed(tmp_path, "a", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 443)], [(1.0, "TLS", None, "h")])
    _seed(tmp_path, "tls2", [_flow(1, "9.9.9.9", "8.8.8.8", 1234, 443)], [(1.0, "TLS", None, "h")])
    _seed(tmp_path, "dns", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 53, proto="UDP")], [(1.0, "DNS", None, "q")])
    probe = IncidentProbe.from_session(a, name="tls-probe")
    assert "TLS" in probe.event_types
    matches = search_by_probe(probe, workspace=tmp_path)
    names = {m.name for m in matches}
    assert "tls2" in names
    assert "dns" not in names

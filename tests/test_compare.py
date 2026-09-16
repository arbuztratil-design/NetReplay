"""P2 #41-44: capture A/B comparison (flows, timing, protocol events)."""
from __future__ import annotations

from netreplay.core.compare import (
    compare_captures,
    compare_events,
    compare_flows,
    compare_timing,
)
from netreplay.core.flows.models import Flow
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


def _flow(id, src, dst, sport, dport, start, end, pkts, by, state="ESTABLISHED", proto="TCP"):
    return Flow(id=id, source=src, destination=dst, protocol=proto, src_port=sport,
                dst_port=dport, start_ts=start, end_ts=end, packet_count=pkts, bytes=by, state=state)


def test_flow_diff_added_removed_changed(tmp_path):
    a = _seed(tmp_path, "a", [
        _flow(1, "10.0.0.1", "10.0.0.2", 1000, 443, 0, 1, 3, 300),
        _flow(2, "10.0.0.5", "10.0.0.6", 1000, 80, 0, 1, 2, 200),
    ], [])
    b = _seed(tmp_path, "b", [
        _flow(1, "10.0.0.1", "10.0.0.2", 1000, 443, 0, 1, 5, 500),
        _flow(3, "10.0.0.9", "10.0.0.10", 1000, 53, 0, 1, 1, 50, proto="UDP"),
    ], [])
    diff = compare_flows(a, b)
    assert {d.status for d in diff.added} == {"added"}
    assert len(diff.removed) == 1
    assert len(diff.changed) == 1
    changed = diff.changed[0]
    assert changed.packet_delta == 2
    assert changed.byte_delta == 200


def test_flow_diff_symmetric_key_ignores_direction(tmp_path):
    a = _seed(tmp_path, "a", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 443, 0, 1, 3, 300)], [])
    b = _seed(tmp_path, "b", [_flow(9, "10.0.0.2", "10.0.0.1", 443, 1000, 0, 1, 3, 300)], [])
    diff = compare_flows(a, b)
    assert len(diff.added) == 0 and len(diff.removed) == 0
    assert diff.deltas[0].status == "unchanged"


def test_timing_diff_durations(tmp_path):
    a = _seed(tmp_path, "a", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 443, 0.0, 1.0, 3, 300)], [])
    b = _seed(tmp_path, "b", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 443, 0.0, 4.0, 3, 300)], [])
    diff = compare_timing(a, b)
    assert diff.duration_before == 0.0  # no packets -> bounds empty
    assert diff.per_flow[0].duration_delta == 3.0


def test_event_diff_counts(tmp_path):
    a = _seed(tmp_path, "a", [], [(1.0, "DNS", None, "q"), (2.0, "DNS", None, "q2")])
    b = _seed(tmp_path, "b", [], [(1.0, "DNS", None, "q"), (2.0, "TLS", None, "h")])
    diff = compare_events(a, b)
    assert diff.get("DNS").delta == -1
    assert diff.get("TLS").delta == 1


def test_compare_captures_identical(tmp_path):
    flows = [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 443, 0, 1, 3, 300)]
    events = [(1.0, "DNS", None, "q")]
    a = _seed(tmp_path, "a", flows, events)
    b = _seed(tmp_path, "b", flows, events)
    report = compare_captures(a, b)
    assert report.identical is True


def test_compare_captures_detects_difference(tmp_path):
    a = _seed(tmp_path, "a", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 443, 0, 1, 3, 300)], [(1.0, "DNS", None, "q")])
    b = _seed(tmp_path, "b", [_flow(1, "10.0.0.1", "10.0.0.2", 1000, 443, 0, 1, 9, 900)], [(1.0, "TLS", None, "h")])
    report = compare_captures(a, b)
    assert report.identical is False
    assert report.flow_diff.changed
    assert report.event_diff.get("TLS").delta == 1

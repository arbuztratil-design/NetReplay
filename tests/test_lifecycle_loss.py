"""P1 #29-30: flow lifecycle events and packet-loss markers."""
from __future__ import annotations

from netreplay.core.flows.lifecycle import (
    FlowPhase,
    flow_lifecycle_events,
    lifecycle_transitions,
    phase_for_state,
)
from netreplay.core.flows.models import Flow
from netreplay.core.loss import detect_loss
from netreplay.core.storage import open_session


def _flow() -> Flow:
    return Flow(
        id=7, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
        src_port=1000, dst_port=443, start_ts=0.0, end_ts=10.0,
        packet_count=5, bytes=500, state="ESTABLISHED",
    )


def test_phase_for_state() -> None:
    assert phase_for_state("NONE") is None
    assert phase_for_state("SYN") is FlowPhase.OPEN
    assert phase_for_state("established") is FlowPhase.ACTIVE
    assert phase_for_state("FIN") is FlowPhase.HALF_CLOSED
    assert phase_for_state("CLOSED") is FlowPhase.CLOSED
    assert phase_for_state("RST") is FlowPhase.CLOSED
    assert phase_for_state("WAT") is None


def test_lifecycle_transition_emits_open() -> None:
    events = lifecycle_transitions(_flow(), "NONE", "SYN", 1.0)
    assert len(events) == 1
    ev = events[0]
    assert ev.phase is FlowPhase.OPEN
    assert ev.event_type == "FLOW_OPEN"
    assert ev.flow_id == 7
    assert "open" in ev.summary


def test_lifecycle_same_phase_is_silent() -> None:
    assert lifecycle_transitions(_flow(), "SYN", "SYN/ACK", 1.0) == []
    assert lifecycle_transitions(_flow(), "SYN/ACK", "ACK", 1.5) == []
    assert lifecycle_transitions(_flow(), "ESTABLISHED", "ESTABLISHED", 2.0) == []


def test_full_lifecycle_sequence() -> None:
    events = flow_lifecycle_events(
        _flow(),
        [
            (1.0, "NONE", "SYN"),
            (1.2, "SYN", "SYN/ACK"),
            (1.4, "SYN/ACK", "ESTABLISHED"),
            (5.0, "ESTABLISHED", "FIN"),
            (6.0, "FIN", "CLOSED"),
        ],
    )
    assert [e.event_type for e in events] == [
        "FLOW_OPEN", "FLOW_ACTIVE", "FLOW_HALF_CLOSED", "FLOW_CLOSED",
    ]
    assert [e.phase for e in events] == [
        FlowPhase.OPEN, FlowPhase.ACTIVE, FlowPhase.HALF_CLOSED, FlowPhase.CLOSED,
    ]


def _seed_loss(tmp_path):
    session = open_session(tmp_path / "loss.nrp", create=True)
    session.set_name_and_interface("loss", interface="lo")
    session.add_event(100.0, "STREAM_GAP", 7, "gap at seq=1400 len=200")
    session.add_event(150.0, "STREAM_GAP", 7, "gap at seq=3600 len=100")
    session.add_event(120.0, "STREAM_RETRANSMISSION", 7, "retransmission at seq=800")
    session.add_event(110.0, "STREAM_GAP", 9, "gap at seq=10 len=64")
    session.finalize()
    return session


def test_detect_loss_markers(tmp_path) -> None:
    report = detect_loss(_seed_loss(tmp_path))
    assert report.has_loss is True
    assert report.total == 4
    assert report.gap_count == 3
    assert report.retransmission_count == 1
    assert report.overlap_count == 0
    assert report.duration == 50.0


def test_loss_markers_pair_consecutive_gaps(tmp_path) -> None:
    report = detect_loss(_seed_loss(tmp_path))
    flow7 = [m for m in report.markers if m.flow_id == 7]
    flow7.sort(key=lambda m: m.start_ts)
    # first gap spans until the next finding on the same flow
    assert flow7[0].start_ts == 100.0
    assert flow7[0].end_ts == 120.0
    assert flow7[0].duration == 20.0
    # last finding on a flow is a zero-width point marker
    assert flow7[-1].start_ts == flow7[-1].end_ts


def test_detect_loss_empty_session(tmp_path) -> None:
    session = open_session(tmp_path / "empty.nrp", create=True)
    session.set_name_and_interface("empty", interface="lo")
    session.finalize()
    report = detect_loss(session)
    assert report.has_loss is False
    assert report.total == 0

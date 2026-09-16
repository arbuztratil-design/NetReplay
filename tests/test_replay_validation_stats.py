"""P1 #37, #38, #40: replay validation, statistics and saved artifacts."""
from __future__ import annotations

from scapy.all import IP, TCP, Ether  # noqa: E402

from netreplay.core.replay.artifact import (
    ReplayArtifact,
    finish_replay_run,
    save_replay_scenario,
    start_replay_run,
)
from netreplay.core.replay.selection import ReplaySelection
from netreplay.core.replay.stats import ReplayStats
from netreplay.core.replay.timing import ReplayMode
from netreplay.core.replay.validate import validate_frame, validate_frames
from netreplay.core.scenario.storage import ScenarioStorage
from netreplay.core.storage import open_session


def _good_frame() -> bytes:
    return bytes(
        Ether(src="aa:aa:aa:aa:aa:01", dst="bb:bb:bb:bb:bb:02")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=5000, dport=443)
        / b"ok"
    )


def test_validate_accepts_good_frame() -> None:
    result = validate_frame(_good_frame(), verify_checksums=True)
    assert result.valid is True
    assert result.issues == []


def test_validate_rejects_short_frame() -> None:
    result = validate_frame(b"\x00\x01\x02")
    assert result.valid is False
    assert "Ethernet" in result.issues[0]


def test_validate_detects_truncated_total_length() -> None:
    frame = bytearray(_good_frame())
    frame[16:18] = (len(frame) + 100).to_bytes(2, "big")
    result = validate_frame(bytes(frame))
    assert result.valid is False
    assert any("total length" in issue for issue in result.issues)


def test_validate_detects_bad_checksum() -> None:
    frame = bytearray(_good_frame())
    frame[24] ^= 0xFF  # corrupt IPv4 header checksum
    result = validate_frame(bytes(frame), verify_checksums=True)
    assert result.valid is False
    assert any("checksum" in issue for issue in result.issues)


def test_validate_non_ipv4_is_structurally_ok() -> None:
    frame = bytes(Ether() / b"\x88\xb5payload")
    assert validate_frame(frame).valid is True


def test_validate_many() -> None:
    results = validate_frames([_good_frame(), b"\x00"])
    assert [r.valid for r in results] == [True, False]


def test_stats_records_and_drift() -> None:
    stats = ReplayStats()
    stats.record_sent(100, scheduled_gap=0.5)
    stats.record_sent(200, scheduled_gap=0.5)
    stats.record_skipped()
    stats.record_failed()
    assert stats.sent == 2
    assert stats.bytes == 300
    assert stats.skipped == 1
    assert stats.failed == 1
    assert stats.attempted == 3
    stats.elapsed = 1.5
    assert stats.timing_drift == 0.5


def test_stats_merge_and_dict() -> None:
    a = ReplayStats(sent=1, bytes=10)
    b = ReplayStats(sent=2, bytes=20, failed=1)
    a.merge(b)
    assert a.sent == 3 and a.bytes == 30 and a.failed == 1
    assert a.to_dict()["sent"] == 3


def _storage(tmp_path):
    session = open_session(tmp_path / "artifact.nrp", create=True)
    session.set_name_and_interface("artifact", interface="lo")
    session.finalize()
    return ScenarioStorage(session)


def test_replay_artifact_parameters() -> None:
    artifact = ReplayArtifact(
        session_id="sess-1",
        name="lab replay",
        mode=ReplayMode.FAITHFUL,
        speed=2.0,
        selection=ReplaySelection.from_values(flow_ids=[3, 1], start_ts=100.0),
    )
    params = artifact.to_parameters()
    assert params["mode"] == "faithful"
    assert params["speed"] == 2.0
    assert params["flow_ids"] == [1, 3]
    assert params["start_ts"] == 100.0


def test_replay_artifact_rejects_bad_input() -> None:
    import pytest

    with pytest.raises(ValueError):
        ReplayArtifact(session_id="s", name="", speed=1.0)
    with pytest.raises(ValueError):
        ReplayArtifact(session_id="s", name="x", speed=0.0)


def test_replay_scenario_run_result_roundtrip(tmp_path) -> None:
    storage = _storage(tmp_path)
    artifact = ReplayArtifact(
        session_id="sess-1", name="roundtrip", mode=ReplayMode.STORY,
        speed=1.0, selection=ReplaySelection.from_values(packet_ids=[1, 2]),
    )
    scenario = save_replay_scenario(storage, artifact)
    assert scenario.id
    assert "replay" in scenario.tags

    run = start_replay_run(storage, scenario, artifact)
    assert run.status.value == "running"
    assert run.parameters["speed"] == 1.0

    stats = ReplayStats(sent=2, bytes=400, skipped=0, failed=0)
    stats.elapsed = 0.1
    finished = finish_replay_run(storage, run, stats)
    assert finished.status.value == "done"
    assert finished.result["sent"] == 2
    assert finished.result["bytes"] == 400

    stored = storage.get_run(run.id)
    assert stored is not None
    assert stored.status.value == "done"
    assert stored.result["sent"] == 2


def test_finish_run_marks_failure(tmp_path) -> None:
    storage = _storage(tmp_path)
    artifact = ReplayArtifact(session_id="sess-1", name="failing")
    scenario = save_replay_scenario(storage, artifact)
    run = start_replay_run(storage, scenario, artifact)
    finished = finish_replay_run(storage, run, ReplayStats(), error="wire down")
    assert finished.status.value == "failed"
    assert finished.result["error"] == "wire down"

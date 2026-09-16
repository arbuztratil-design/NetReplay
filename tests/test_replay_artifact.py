"""#45: replay result artifact linked to its source .nrp."""
from __future__ import annotations

import pytest
from scapy.all import Ether, IP, TCP

from netreplay.core.packets.models import ParsedPacket
from netreplay.core.replay.artifact import (
    REPLAY_RESULT_EXTENSION,
    REPLAY_RESULT_FORMAT,
    REPLAY_RESULT_KIND,
    ReplayArtifact,
    ReplayResultArtifact,
    build_replay_result,
    finish_replay_run,
    replay_result_from_run,
    save_replay_result,
    save_replay_scenario,
    start_replay_run,
)
from netreplay.core.replay.inject import ReplayOutService
from netreplay.core.replay.stats import ReplayStats
from netreplay.core.replay.timing import ReplayMode, VirtualClock
from netreplay.core.scenario.storage import ScenarioStorage
from netreplay.core.storage import open_session


def _make_session(tmp_path, name: str = "source.nrp", count: int = 2):
    session = open_session(tmp_path / name, create=True)
    session.set_name_and_interface(name, interface="lo")
    for i in range(count):
        raw = bytes(
            Ether(src="aa:aa:aa:aa:aa:01", dst="bb:bb:bb:bb:bb:02")
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1000 + i, dport=443)
            / f"p{i}".encode()
        )
        session.add_packet(
            ParsedPacket(
                ts=1.0 + i,
                source="10.0.0.1",
                destination="10.0.0.2",
                protocol="TCP",
                src_port=1000 + i,
                dst_port=443,
                length=len(raw),
                raw=raw,
                flow_id=1,
            )
        )
    session.finalize()
    return session


def test_build_result_links_source(tmp_path) -> None:
    session = _make_session(tmp_path, count=3)
    info = session.info()
    result = build_replay_result(session, stats=ReplayStats(sent=3, bytes=90))
    assert result.session_id == info.session_id
    assert result.source_path == info.path
    assert result.source_packet_count == 3
    assert result.source_integrity_hash == info.integrity_hash
    assert result.source_integrity_hash  # finalize computed a real hash
    assert result.source_format_version == info.format_version
    assert result.source_schema_version == info.schema_version
    assert result.stats["sent"] == 3
    assert result.status == "done"
    assert result.is_complete


def test_result_matches_only_its_own_source(tmp_path) -> None:
    a = _make_session(tmp_path, "a.nrp", count=2)
    b = _make_session(tmp_path, "b.nrp", count=4)
    result = build_replay_result(a)
    assert result.matches_source(a)
    assert result.matches_source(a.info())
    # a different capture is rejected (id, packet count and hash all differ)
    assert not result.matches_source(b)


def test_result_detects_changed_source(tmp_path) -> None:
    session = _make_session(tmp_path, count=2)
    result = build_replay_result(session)
    info = session.info()
    info.packet_count += 1
    assert not result.matches_source(info)
    info = session.info()
    info.integrity_hash = "deadbeef"
    assert not result.matches_source(info)


def test_result_requires_session_id() -> None:
    with pytest.raises(ValueError):
        ReplayResultArtifact()


def test_result_roundtrip_and_nrr_file(tmp_path) -> None:
    session = _make_session(tmp_path, count=2)
    result = build_replay_result(
        session, stats=ReplayStats(sent=2, bytes=120, skipped=1)
    )
    payload = result.to_dict()
    assert payload["kind"] == REPLAY_RESULT_KIND
    assert payload["format"] == REPLAY_RESULT_FORMAT
    restored = ReplayResultArtifact.from_dict(payload)
    assert restored == result
    assert restored.matches_source(session)

    written = result.save(tmp_path / "outcome")
    assert written.suffix == REPLAY_RESULT_EXTENSION
    assert written.exists()
    assert ReplayResultArtifact.load(written) == result


def test_result_rejects_newer_format() -> None:
    with pytest.raises(ValueError):
        ReplayResultArtifact.from_dict({"session_id": "s", "format": 999})


def test_finish_run_embeds_linked_artifact(tmp_path) -> None:
    session = _make_session(tmp_path)
    storage = ScenarioStorage(session)
    artifact = ReplayArtifact(
        session_id=session.info().session_id,
        name="linked",
        mode=ReplayMode.FAITHFUL,
        speed=2.0,
    )
    scenario = save_replay_scenario(storage, artifact)
    run = start_replay_run(storage, scenario, artifact)

    stats = ReplayStats(sent=2, bytes=120)
    stats.elapsed = 0.2
    finished = finish_replay_run(
        storage, run, stats, source=session, artifact=artifact
    )

    recovered = replay_result_from_run(finished)
    assert recovered is not None
    assert recovered.run_id == run.id
    assert recovered.scenario_id == scenario.id
    assert recovered.mode == "faithful"
    assert recovered.speed == 2.0
    assert recovered.stats["sent"] == 2
    assert recovered.matches_source(session)

    stored = storage.get_run(run.id)
    assert stored is not None
    assert stored.result["artifact"]["kind"] == REPLAY_RESULT_KIND
    assert stored.result["artifact"]["session_id"] == session.info().session_id
    assert replay_result_from_run(stored).matches_source(session)


def test_save_replay_result_attaches_after_finish(tmp_path) -> None:
    session = _make_session(tmp_path)
    storage = ScenarioStorage(session)
    artifact = ReplayArtifact(session_id=session.info().session_id, name="late")
    scenario = save_replay_scenario(storage, artifact)
    run = start_replay_run(storage, scenario, artifact)

    finished = finish_replay_run(storage, run, ReplayStats(sent=1))
    assert "artifact" not in finished.result  # no source given yet
    assert replay_result_from_run(finished) is None

    result = save_replay_result(storage, finished, session, artifact=artifact)
    assert result.matches_source(session)
    again = replay_result_from_run(storage.get_run(run.id))
    assert again is not None and again.run_id == run.id


def test_replay_out_virtual_clock_is_deterministic(tmp_path) -> None:
    session = _make_session(tmp_path, count=3)
    clock = VirtualClock()
    status = ReplayOutService(
        session,
        interface="lo",
        dry_run=True,
        mode=ReplayMode.FAITHFUL,
        clock=clock,
    ).run()
    assert status.packets == 3
    assert clock.slept == pytest.approx(2.0)  # ts 1,2,3 -> gaps 1 + 1
    assert status.timing_drift == pytest.approx(0.0)

"""End-to-end: PCAP -> .nrp -> replay -> linked result (#47).

Exercises the full reverse arrow of the canonical data flow on the golden
corpus: a PCAP is imported into an analysed session, the stored frames are
replayed (byte-exact, deterministic), and the outcome is recorded as a
ReplayResultArtifact pinned to the source ``.nrp``.
"""
from __future__ import annotations

import pytest

from netreplay.core.replay.artifact import (
    ReplayArtifact,
    ReplayResultArtifact,
    finish_replay_run,
    replay_result_from_run,
    save_replay_scenario,
    start_replay_run,
)
from netreplay.core.replay.inject import ReplayOutService
from netreplay.core.replay.stats import ReplayStats
from netreplay.core.replay.timing import ReplayMode, VirtualClock
from netreplay.core.scenario.storage import ScenarioStorage
from netreplay.core.service import NetReplayService
from tests import golden_corpus as gc


class FakeSender:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    def send(self, raw: bytes) -> None:
        self.sent.append(raw)

    def close(self) -> None:
        self.closed = True


def _import(tmp_path, scenario: str = "tcp_basic"):
    pcap = gc.write_capture(gc.SCENARIOS[scenario], tmp_path / "in")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    service = NetReplayService(workspace)
    status = service.import_pcap(pcap)
    assert status.error is None
    sessions = service.list_sessions()
    assert len(sessions) == 1
    return service, sessions[0].session_id, status


def test_e2e_pcap_to_nrp_to_byte_exact_replay(tmp_path) -> None:
    service, session_id, import_status = _import(tmp_path)
    session = service.open_session(session_id)
    assert session is not None
    expected = [session.packet(r.id)[1] for r in session.packets()]
    assert len(expected) == import_status.packets

    sender = FakeSender()
    status = ReplayOutService(
        session,
        interface="lo",
        mode=ReplayMode.FAITHFUL,
        sender_factory=lambda _iface: sender,
        clock=VirtualClock(),
    ).run()

    assert status.error is None
    assert status.packets == import_status.packets
    assert sender.sent == expected  # replayed frames are the stored frames
    assert sender.closed


def test_e2e_replay_result_is_linked_to_source_nrp(tmp_path) -> None:
    service, session_id, import_status = _import(tmp_path, "tls_client_hello")
    session = service.open_session(session_id)
    assert session is not None

    # Replay through the public service surface (dry-run: no network).
    controller = service.start_replay(
        session_id, interface="lo", dry_run=True, mode=ReplayMode.FAITHFUL
    )
    assert controller.wait(timeout=30)
    replay_status = controller.status()
    service.stop_replay()
    assert replay_status.error is None
    assert replay_status.packets == import_status.packets

    # Record the outcome as an artifact linked to the source capture.
    storage = ScenarioStorage(session)
    artifact = ReplayArtifact(
        session_id=session.info().session_id,
        name="e2e tls replay",
        mode=ReplayMode.FAITHFUL,
        speed=1.0,
    )
    scenario = save_replay_scenario(storage, artifact)
    run = start_replay_run(storage, scenario, artifact)
    stats = ReplayStats(sent=replay_status.packets, bytes=replay_status.bytes)
    stats.elapsed = replay_status.duration
    finished = finish_replay_run(
        storage, run, stats, source=session, artifact=artifact
    )

    recovered = replay_result_from_run(finished)
    assert recovered is not None
    assert recovered.is_complete
    assert recovered.stats["sent"] == import_status.packets
    assert recovered.matches_source(session)

    # The portable .nrr artifact round-trips and still verifies.
    written = recovered.save(tmp_path / "result")
    assert written.exists()
    reloaded = ReplayResultArtifact.load(written)
    assert reloaded == recovered
    assert reloaded.matches_source(session.info())


def test_e2e_artifact_detects_tampered_source(tmp_path) -> None:
    service, session_id, _ = _import(tmp_path, "tcp_basic")
    session = service.open_session(session_id)
    assert session is not None

    artifact = ReplayArtifact(session_id=session.info().session_id, name="tamper")
    storage = ScenarioStorage(session)
    scenario = save_replay_scenario(storage, artifact)
    run = start_replay_run(storage, scenario, artifact)
    stats = ReplayStats(sent=1)
    finished = finish_replay_run(storage, run, stats, source=session, artifact=artifact)
    recovered = replay_result_from_run(finished)
    assert recovered is not None and recovered.matches_source(session)

    # Same session id, but a different capture fingerprint -> no match.
    other = session.info()
    other.integrity_hash = "0" * 64
    assert not recovered.matches_source(other)
    other = session.info()
    other.packet_count += 1
    assert not recovered.matches_source(other)

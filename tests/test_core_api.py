"""Phase 1 #3, #6, #7: public core API, id types and time base."""
from __future__ import annotations

import time

import pytest

import netreplay.core as core
from netreplay.core.ids import (
    event_id,
    flow_id,
    packet_id,
    session_id,
)
from netreplay.core.replay.config import ReplayConfig
from netreplay.core.replay.timing import ReplayMode
from netreplay.core.storage.database import ts_to_us, us_to_ts
from netreplay.core.timebase import from_us, now_epoch, now_monotonic, to_us, utc_iso


def test_public_api_exports_are_present():
    for name in ("Packet", "Flow", "Event", "Session", "ReplayConfig"):
        assert name in core.__all__
        assert hasattr(core, name)


def test_public_aliases_point_to_models():
    from netreplay.core.events.models import NetworkEvent
    from netreplay.core.packets.models import Packet
    from netreplay.core.storage.database import SessionStorage

    assert core.Event is NetworkEvent
    assert core.Packet is Packet
    assert core.ParsedPacket is not Packet  # parser output stays distinct
    assert core.Session is SessionStorage


def test_id_types_are_zero_cost_and_distinct():
    assert packet_id(3) == 3
    assert flow_id(4) == 4
    assert event_id(5) == 5
    assert session_id("abc") == "abc"
    # NewType is identity at runtime.
    assert isinstance(packet_id(1), int)


def test_replay_config_validation():
    with pytest.raises(ValueError):
        ReplayConfig(speed=0.0)
    with pytest.raises(ValueError):
        ReplayConfig(offset=-1)
    cfg = ReplayConfig(mode="faithful", speed=2.0)
    assert cfg.mode is ReplayMode.FAITHFUL
    kwargs = cfg.to_kwargs()
    assert kwargs["mode"] is ReplayMode.FAITHFUL
    assert kwargs["speed"] == 2.0


def test_timebase_roundtrip_and_rules():
    now = now_epoch()
    assert abs(now - time.time()) < 1.0
    assert now_monotonic() >= 0.0
    us = to_us(1234.5)
    assert us == 1_234_500_000
    assert from_us(us) == 1234.5
    # storage delegates to the canonical rule
    assert ts_to_us(2.0) == to_us(2.0)
    assert us_to_ts(to_us(2.0)) == 2.0
    assert utc_iso(0).endswith("Z")


def test_replay_config_drives_service(tmp_path):
    from netreplay.core.packets.models import ParsedPacket
    from netreplay.core.replay.inject import ReplayOutService
    from netreplay.core.replay.selection import ReplaySelection
    from netreplay.core.storage import open_session

    session = open_session(tmp_path / "cfg.nrp", create=True)
    session.set_name_and_interface("cfg", "lo")
    for i, flow_id_ in enumerate((1, 2, 1)):
        session.add_packet(ParsedPacket(
            ts=float(i), source="10.0.0.1", destination="10.0.0.2",
            protocol="TCP", src_port=1000, dst_port=443, length=10,
            raw=b"frame", flow_id=flow_id_,
        ))
    session.finalize()

    cfg = ReplayConfig(
        mode=ReplayMode.FAITHFUL, dry_run=True,
        selection=ReplaySelection.from_values(flow_ids=[1]),
    )
    status = ReplayOutService(session, interface="Ethernet", config=cfg).run()
    assert status.mode == "faithful"
    assert status.packets == 2  # only flow 1
    assert status.skipped == 1

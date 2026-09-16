"""P1 #34, #36: replay selection and packet mutation pipeline."""
from __future__ import annotations

import pytest

from netreplay.core.replay.mutation import (
    MutationPipeline,
    PadToLength,
    ReplacePattern,
    TruncatePayload,
)
from netreplay.core.replay.selection import ReplaySelection
from netreplay.core.storage.database import PacketRow


def _rows() -> list[PacketRow]:
    return [
        PacketRow(id=1, ts=100.0, source="10.0.0.1", destination="10.0.0.2", protocol="TCP", src_port=5000, dst_port=443, length=100, flow_id=7),
        PacketRow(id=2, ts=110.0, source="10.0.0.2", destination="10.0.0.1", protocol="TCP", src_port=443, dst_port=5000, length=120, flow_id=7),
        PacketRow(id=3, ts=200.0, source="10.0.0.1", destination="8.8.8.8", protocol="UDP", src_port=5000, dst_port=53, length=80, flow_id=9),
    ]


def test_selection_unrestricted_matches_all() -> None:
    sel = ReplaySelection()
    assert sel.is_unrestricted
    assert len(sel.select(_rows())) == 3


def test_selection_by_packet_ids() -> None:
    sel = ReplaySelection.from_values(packet_ids=[1, 3])
    assert [r.id for r in sel.select(_rows())] == [1, 3]


def test_selection_by_flow_ids() -> None:
    sel = ReplaySelection.from_values(flow_ids=[9])
    assert [r.id for r in sel.select(_rows())] == [3]


def test_selection_time_range() -> None:
    sel = ReplaySelection.from_values(start_ts=105.0, end_ts=150.0)
    assert [r.id for r in sel.select(_rows())] == [2]


def test_selection_dimensions_combine() -> None:
    sel = ReplaySelection.from_values(flow_ids=[7], start_ts=105.0)
    assert [r.id for r in sel.select(_rows())] == [2]


def test_selection_rejects_reversed_range() -> None:
    with pytest.raises(ValueError):
        ReplaySelection.from_values(start_ts=10.0, end_ts=5.0)


def test_truncate_payload() -> None:
    assert TruncatePayload(4).apply(b"abcdefgh") == b"abcd"
    assert TruncatePayload(100).apply(b"abc") == b"abc"


def test_truncate_rejects_zero() -> None:
    with pytest.raises(ValueError):
        TruncatePayload(0)


def test_replace_pattern() -> None:
    assert ReplacePattern(b"AB", b"xy").apply(b"ABABz") == b"xyxyz"


def test_replace_rejects_empty_old() -> None:
    with pytest.raises(ValueError):
        ReplacePattern(b"", b"x")


def test_pad_to_length() -> None:
    assert PadToLength(5).apply(b"ab") == b"ab\x00\x00\x00"
    assert PadToLength(2).apply(b"abcd") == b"abcd"


def test_pipeline_applies_in_order() -> None:
    pipeline = MutationPipeline().add(ReplacePattern(b"AA", b"BB")).add(TruncatePayload(4))
    assert pipeline.apply(b"AAAACC") == b"BBBB"
    assert pipeline.is_empty is False
    assert MutationPipeline().is_empty is True

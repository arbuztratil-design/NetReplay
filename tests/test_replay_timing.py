"""P1 #31-33, #39: replay modes, exact timing, speed multiplier, determinism."""
from __future__ import annotations

import pytest

from netreplay.core.replay.timing import (
    PRESET_SPEEDS,
    ReplayMode,
    ReplaySpeed,
    SystemClock,
    VirtualClock,
    build_schedule,
    gap_policy,
    play,
)


def test_speed_rejects_non_positive() -> None:
    with pytest.raises(ValueError):
        ReplaySpeed(0)
    with pytest.raises(ValueError):
        ReplaySpeed(-1.0)
    with pytest.raises(TypeError):
        ReplaySpeed(True)


def test_speed_scale_and_presets() -> None:
    assert ReplaySpeed(1.0).scale(10.0) == 10.0
    assert ReplaySpeed(2.0).scale(10.0) == 5.0
    assert ReplaySpeed(0.5).scale(10.0) == 20.0
    assert ReplaySpeed.preset("10") == ReplaySpeed(10.0)
    assert 0.1 in PRESET_SPEEDS


def test_faithful_gap_policy_preserves_exact() -> None:
    policy = gap_policy(ReplayMode.FAITHFUL, max_gap=1.0)
    assert policy.preserve_exact is True
    assert policy.apply(30.0) == 30.0


def test_story_gap_policy_caps_long_gaps() -> None:
    policy = gap_policy(ReplayMode.STORY, max_gap=5.0)
    assert policy.preserve_exact is False
    assert policy.apply(30.0) == 5.0
    assert policy.apply(1.0) == 1.0


def test_build_schedule_faithful_exact_timing() -> None:
    schedule = build_schedule(
        [100.0, 100.5, 101.0], mode=ReplayMode.FAITHFUL, speed=1.0
    )
    assert schedule == [0.0, 0.5, 0.5]


def test_build_schedule_speed_multiplier() -> None:
    schedule = build_schedule(
        [0.0, 1.0, 2.0], mode=ReplayMode.FAITHFUL, speed=2.0
    )
    assert schedule == [0.0, 0.5, 0.5]
    slower = build_schedule(
        [0.0, 1.0], mode=ReplayMode.FAITHFUL, speed=0.1
    )
    assert slower == [0.0, 10.0]


def test_build_schedule_story_caps_gap() -> None:
    schedule = build_schedule(
        [0.0, 30.0, 30.5], mode=ReplayMode.STORY, speed=1.0
    )
    assert schedule == [0.0, 5.0, 0.5]


def test_schedule_ignores_backwards_timestamps() -> None:
    schedule = build_schedule(
        [0.0, -1.0, 0.5], mode=ReplayMode.FAITHFUL, speed=1.0
    )
    assert schedule == [0.0, 0.0, 1.5]


def test_virtual_clock_accumulates_without_sleeping() -> None:
    clock = VirtualClock(start=10.0)
    assert clock.now() == 10.0
    clock.sleep(2.0)
    clock.sleep(0.0)
    assert clock.now() == 12.0
    assert clock.slept == 2.0


def test_deterministic_replay_same_waits() -> None:
    timestamps = [0.0, 0.25, 1.5, 1.75]
    first = play(timestamps, clock=VirtualClock(), mode=ReplayMode.FAITHFUL, speed=2.0)
    second = play(timestamps, clock=VirtualClock(), mode=ReplayMode.FAITHFUL, speed=2.0)
    assert first == second
    assert first == [0.0, 0.125, 0.625, 0.125]


def test_system_clock_is_zero_cost_for_zero_gap() -> None:
    clock = SystemClock()
    start = clock.now()
    clock.sleep(0.0)
    assert clock.now() >= start
    clock.sleep(0.001)
    assert clock.now() >= start

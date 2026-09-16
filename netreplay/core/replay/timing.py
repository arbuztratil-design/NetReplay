"""Replay semantics, timing and pacing (#31-33, #39).

Two clearly separated replay meanings:

* **Story replay** — the capture is told as a story: long idle gaps are capped
  so the narrative stays watchable. It is for humans.
* **Faithful replay** — the capture is reproduced as recorded: every
  inter-packet delta is preserved exactly so downstream behaviour (timing,
  retransmission windows) matches the original. It is for machines.

Timing is driven by a :class:`Clock`, so the exact same schedule can be
executed on the wall clock (``SystemClock``) or deterministically without
sleeping (``VirtualClock``) — the basis of deterministic replay (#39).
"""
from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

PRESET_SPEEDS: tuple[float, ...] = (0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 10.0)


class ReplayMode(str, Enum):
    """Replay semantics (#31)."""

    STORY = "story"
    FAITHFUL = "faithful"


class ReplaySpeed:
    """Validated replay speed multiplier (#33)."""

    def __init__(self, factor: float = 1.0) -> None:
        if not isinstance(factor, (int, float)) or isinstance(factor, bool):
            raise TypeError("speed must be a number")
        if factor <= 0:
            raise ValueError("speed must be greater than 0")
        self.factor = float(factor)

    def scale(self, seconds: float) -> float:
        """Wall-clock duration for a recorded ``seconds`` interval."""
        return seconds / self.factor

    @classmethod
    def preset(cls, name: str) -> ReplaySpeed:
        try:
            value = float(name)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unknown preset {name!r}") from exc
        if value not in PRESET_SPEEDS:
            raise ValueError(f"unknown preset {name!r}")
        return cls(value)

    def __float__(self) -> float:
        return self.factor

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ReplaySpeed) and other.factor == self.factor

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"ReplaySpeed({self.factor})"


class Clock(Protocol):
    """Time source used to pace replay."""

    def now(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    """Real wall-clock pacing."""

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


class VirtualClock:
    """Deterministic pacing that advances logical time without sleeping.

    Used by deterministic replay (#39) and by tests: the produced schedule is
    identical on every run because it never consults the wall clock.
    """

    def __init__(self, start: float = 0.0) -> None:
        self._now = float(start)
        self._slept = 0.0

    def now(self) -> float:
        return self._now

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            self._now += seconds
            self._slept += seconds

    @property
    def slept(self) -> float:
        return self._slept


@dataclass(frozen=True, slots=True)
class GapPolicy:
    """How recorded inter-packet gaps are translated into playback waits."""

    max_gap: float | None = None
    preserve_exact: bool = True

    def apply(self, gap: float) -> float:
        gap = max(0.0, gap)
        if not self.preserve_exact and self.max_gap is not None:
            return min(gap, self.max_gap)
        return gap


def gap_policy(mode: ReplayMode, max_gap: float = 5.0) -> GapPolicy:
    """Default gap policy per replay mode."""
    if mode is ReplayMode.FAITHFUL:
        return GapPolicy(max_gap=None, preserve_exact=True)
    return GapPolicy(max_gap=max_gap, preserve_exact=False)


def build_schedule(
    timestamps: Sequence[float],
    *,
    mode: ReplayMode = ReplayMode.FAITHFUL,
    speed: ReplaySpeed | float = 1.0,
) -> list[float]:
    """Inter-packet waits (in seconds) for a recorded timestamp sequence.

    The first packet has no preceding gap. Gaps are scaled by ``speed`` and
    shaped by the mode's :class:`GapPolicy`: faithful replay keeps them exact,
    story replay caps long waits.
    """
    rate = speed if isinstance(speed, ReplaySpeed) else ReplaySpeed(speed)
    policy = gap_policy(mode)
    schedule: list[float] = []
    previous: float | None = None
    for ts in timestamps:
        if previous is None:
            schedule.append(0.0)
        else:
            schedule.append(rate.scale(policy.apply(ts - previous)))
        previous = ts
    return schedule


def play(
    timestamps: Iterable[float],
    *,
    clock: Clock,
    mode: ReplayMode = ReplayMode.FAITHFUL,
    speed: ReplaySpeed | float = 1.0,
) -> list[float]:
    """Wait per the schedule and return the waits actually performed."""
    waits = build_schedule(list(timestamps), mode=mode, speed=speed)
    for wait in waits:
        if wait > 0:
            clock.sleep(wait)
    return waits

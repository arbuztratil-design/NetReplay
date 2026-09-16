"""Replay statistics (#38): sent / skipped / failed / timing drift.

A small accumulator that a replay loop feeds as it runs. ``timing_drift`` is
the difference between how long the replay actually took and how long its
schedule said it should take — a positive drift means the machine could not
keep up with the requested pacing.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ReplayStats:
    sent: int = 0
    skipped: int = 0
    failed: int = 0
    bytes: int = 0
    scheduled: float = 0.0
    elapsed: float = 0.0

    def record_sent(self, size: int, scheduled_gap: float = 0.0) -> None:
        self.sent += 1
        self.bytes += max(0, size)
        self.scheduled += max(0.0, scheduled_gap)

    def record_skipped(self) -> None:
        self.skipped += 1

    def record_failed(self) -> None:
        self.failed += 1

    @property
    def attempted(self) -> int:
        return self.sent + self.failed

    @property
    def timing_drift(self) -> float:
        return self.elapsed - self.scheduled

    def merge(self, other: ReplayStats) -> ReplayStats:
        self.sent += other.sent
        self.skipped += other.skipped
        self.failed += other.failed
        self.bytes += other.bytes
        self.scheduled += other.scheduled
        self.elapsed += other.elapsed
        return self

    def to_dict(self) -> dict[str, float | int]:
        return {
            "sent": self.sent,
            "skipped": self.skipped,
            "failed": self.failed,
            "bytes": self.bytes,
            "scheduled": self.scheduled,
            "elapsed": self.elapsed,
            "timing_drift": self.timing_drift,
        }

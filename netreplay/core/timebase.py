"""Time-base rules (phase 1 #7).

NetReplay uses exactly two clocks and never mixes them:

* **Wall-clock / UTC epoch seconds** for everything that is *stored*. Packet
  and event timestamps are epoch seconds (``time.time()``) and are serialized
  into SQLite as integer **microseconds**. This is the single canonical time
  base of a capture and is comparable across files and machines.
* **Monotonic seconds** (``time.monotonic()``) for everything that is
  *measured* (durations, rates, pacing, timing drift). Monotonic values are
  never stored, because they are meaningless outside the running process.

Helpers below are the only sanctioned conversions; callers must not hand-roll
``* 1_000_000`` arithmetic.
"""
from __future__ import annotations

import time

US_PER_SECOND = 1_000_000


def now_epoch() -> float:
    """Current wall-clock time as UTC epoch seconds (the stored time base)."""
    return time.time()


def now_monotonic() -> float:
    """Current monotonic time in seconds (for durations only, never stored)."""
    return time.monotonic()


def to_us(ts: float) -> int:
    """Epoch seconds -> integer microseconds (storage representation)."""
    return int(round(ts * US_PER_SECOND))


def from_us(us: int) -> float:
    """Integer microseconds -> epoch seconds."""
    return us / US_PER_SECOND


def utc_iso(ts: float) -> str:
    """Epoch seconds -> ISO-8601 UTC string (diagnostics/logs)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


__all__ = [
    "US_PER_SECOND",
    "now_epoch",
    "now_monotonic",
    "to_us",
    "from_us",
    "utc_iso",
]

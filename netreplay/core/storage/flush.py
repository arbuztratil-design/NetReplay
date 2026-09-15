"""Configurable write flush policy for captures.

A flush policy decides when a batch of captured packets is committed to the
``.nrp`` store: after N packets, after a time interval, or only at the end of
the capture. Batching writes in a single transaction is the largest capture
throughput win available to the pipeline (a few commits per packet -> one
commit per batch).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class FlushPolicy:
    mode: str = "packets"
    packets: int = 256
    seconds: float = 1.0

    def should_flush(self, pending: int, since: float, now: float) -> bool:
        if self.mode == "never":
            return False
        if self.mode == "time":
            return now - since >= self.seconds
        if self.mode == "packets":
            return pending >= self.packets
        return pending >= 1


def validate(policy: FlushPolicy) -> None:
    if policy.mode not in ("packets", "time", "never"):
        raise ValueError(
            f"invalid flush mode {policy.mode!r} (expected packets | time | never)"
        )
    if policy.packets < 1:
        raise ValueError("flush packets must be >= 1")
    if policy.seconds <= 0:
        raise ValueError("flush seconds must be > 0")


def parse(
    mode: str | None = None,
    packets: int | None = None,
    seconds: float | None = None,
) -> FlushPolicy:
    """Build a :class:`FlushPolicy` from optional overrides.

    ``mode is None`` uses the default flush (packets=256).
    """
    if mode is None:
        return FlushPolicy()
    if mode == "never":
        return FlushPolicy(mode="never")
    if mode in ("packets", "time"):
        policy = FlushPolicy(mode=mode)
        if packets is not None:
            policy.packets = packets
        if seconds is not None:
            policy.seconds = seconds
        validate(policy)
        return policy
    raise ValueError(f"invalid flush mode {mode!r} (expected packets | time | never)")
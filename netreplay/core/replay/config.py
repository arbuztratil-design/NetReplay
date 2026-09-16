"""Canonical replay configuration (phase 1 #3).

``ReplayConfig`` is the single public description of *what* to replay and
*how*: semantics (story/faithful), pace, selection, transforms and validation.
The replay engine accepts it directly, and it is JSON-friendly so it can be
persisted as an artifact later (phase 5).
"""
from __future__ import annotations

from dataclasses import dataclass

from netreplay.core.replay.mutation import MutationPipeline
from netreplay.core.replay.remap import RemapConfig
from netreplay.core.replay.selection import ReplaySelection
from netreplay.core.replay.timing import ReplayMode, ReplaySpeed


@dataclass(slots=True)
class ReplayConfig:
    """Everything needed to run a replay-out."""

    mode: ReplayMode = ReplayMode.STORY
    speed: float = 1.0
    max_gap: float = 5.0
    dry_run: bool = False
    offset: int = 0
    limit: int | None = None
    selection: ReplaySelection | None = None
    remap: RemapConfig | None = None
    pipeline: MutationPipeline | None = None
    validate: bool = False

    def __post_init__(self) -> None:
        ReplaySpeed(self.speed)  # validate
        if not isinstance(self.mode, ReplayMode):
            self.mode = ReplayMode(self.mode)
        if self.offset < 0:
            raise ValueError("offset must be non-negative")
        if self.limit is not None and self.limit < 0:
            raise ValueError("limit must be non-negative")

    def to_kwargs(self) -> dict:
        """Keyword arguments accepted by :class:`ReplayOutService`."""
        return {
            "speed": self.speed,
            "max_gap": self.max_gap,
            "dry_run": self.dry_run,
            "offset": self.offset,
            "limit": self.limit,
            "mode": self.mode,
            "selection": self.selection,
            "remap": self.remap,
            "pipeline": self.pipeline,
            "validate": self.validate,
        }


__all__ = ["ReplayConfig"]

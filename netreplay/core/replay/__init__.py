"""Replay: historical playback of a stored capture.

* ``ReplayService`` — story replay of stored events.
* ``ReplayOutService`` — faithful/story frame injection onto a live interface,
  with selection, remapping, mutation, validation and statistics.
* ``ReplayArtifact`` — save a replay configuration as a Scenario/Run/Result.
* ``ReplayResultArtifact`` — a portable replay outcome linked to its source
  ``.nrp`` (#45).
"""
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
from netreplay.core.replay.config import ReplayConfig
from netreplay.core.replay.inject import ReplayOutService, ReplayOutStatus
from netreplay.core.replay.mutation import MutationPipeline
from netreplay.core.replay.remap import RemapConfig
from netreplay.core.replay.selection import ReplaySelection
from netreplay.core.replay.stats import ReplayStats
from netreplay.core.replay.timing import ReplayMode, ReplaySpeed
from netreplay.core.replay.validate import ValidationResult, validate_frame
from netreplay.core.timeline.service import ReplayService

__all__ = [
    "ReplayOutService",
    "ReplayOutStatus",
    "ReplayService",
    "ReplayMode",
    "ReplaySpeed",
    "ReplayConfig",
    "ReplaySelection",
    "RemapConfig",
    "MutationPipeline",
    "ReplayStats",
    "ReplayArtifact",
    "ReplayResultArtifact",
    "save_replay_scenario",
    "start_replay_run",
    "finish_replay_run",
    "build_replay_result",
    "save_replay_result",
    "replay_result_from_run",
    "REPLAY_RESULT_KIND",
    "REPLAY_RESULT_FORMAT",
    "REPLAY_RESULT_EXTENSION",
    "validate_frame",
    "ValidationResult",
]

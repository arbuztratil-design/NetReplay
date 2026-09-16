"""Replay scenario as a saved artifact (#40): Scenario -> Run -> Result.

A replay configuration (mode, speed, selection, remapping, mutation) can be
persisted as a Scenario, executed as a ScenarioRun, and its outcome stored as
the Run's Result — so a replay is reproducible and auditable later.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from netreplay.core.replay.mutation import MutationPipeline
from netreplay.core.replay.remap import RemapConfig
from netreplay.core.replay.selection import ReplaySelection
from netreplay.core.replay.stats import ReplayStats
from netreplay.core.replay.timing import ReplayMode, ReplaySpeed
from netreplay.core.scenario.models import (
    FlowSelector,
    PacketRange,
    RunStatus,
    Scenario,
    ScenarioRun,
    ScenarioSelection,
    TimeRange,
)
from netreplay.core.scenario.storage import ScenarioStorage


@dataclass(slots=True)
class ReplayArtifact:
    """Everything needed to reproduce a replay."""

    session_id: str
    name: str
    mode: ReplayMode = ReplayMode.STORY
    speed: float = 1.0
    selection: ReplaySelection | None = None
    remap: RemapConfig | None = None
    pipeline: MutationPipeline | None = None
    dry_run: bool = False
    description: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        ReplaySpeed(self.speed)  # validate speed up-front
        if not self.name:
            raise ValueError("replay artifact needs a name")

    def to_parameters(self) -> dict[str, Any]:
        selection = self.selection
        params: dict[str, Any] = {
            "mode": self.mode.value,
            "speed": self.speed,
            "dry_run": self.dry_run,
        }
        if selection is not None:
            params["packet_ids"] = sorted(selection.packet_ids) if selection.packet_ids else None
            params["flow_ids"] = sorted(selection.flow_ids) if selection.flow_ids else None
            params["start_ts"] = selection.start_ts
            params["end_ts"] = selection.end_ts
        if self.remap is not None:
            params["remap"] = {
                "macs": len(self.remap.mac_map),
                "ips": len(self.remap.ip_map),
                "ports": len(self.remap.port_map),
            }
        if self.pipeline is not None and not self.pipeline.is_empty:
            params["mutations"] = [type(m).__name__ for m in self.pipeline.mutations]
        return params

    def to_scenario_selection(self) -> ScenarioSelection:
        selection = self.selection
        flow_ids = sorted(selection.flow_ids) if selection and selection.flow_ids else []
        return ScenarioSelection(
            session_id=self.session_id,
            flows=FlowSelector(flow_ids=flow_ids, include_all=not flow_ids),
            time_range=TimeRange(
                start=selection.start_ts if selection else None,
                end=selection.end_ts if selection else None,
            ),
            packets=PacketRange(start=None, end=None),
            protocols=[],
        )


def save_replay_scenario(
    storage: ScenarioStorage, artifact: ReplayArtifact
) -> Scenario:
    """Persist a replay configuration as a Scenario (#40)."""
    scenario = storage.create_scenario(
        name=artifact.name,
        session_id=artifact.session_id,
        description=artifact.description or f"Replay ({artifact.mode.value})",
        selection=artifact.to_scenario_selection(),
        tags=sorted({"replay", artifact.mode.value, *artifact.tags}),
        notes=artifact.to_parameters().__repr__(),
    )
    return scenario


def start_replay_run(
    storage: ScenarioStorage, scenario: Scenario, artifact: ReplayArtifact
) -> ScenarioRun:
    """Open a ScenarioRun for *artifact* and mark it RUNNING."""
    run = storage.create_run(scenario, name=artifact.name)
    run.status = RunStatus.RUNNING
    run.parameters = artifact.to_parameters()
    run.started_at = time.time() * 1000.0
    storage.update_run(run)
    return run


def finish_replay_run(
    storage: ScenarioStorage,
    run: ScenarioRun,
    stats: ReplayStats,
    *,
    aborted: bool = False,
    error: str | None = None,
) -> ScenarioRun:
    """Store the replay Result on the Run (#40)."""
    if error is not None:
        run.status = RunStatus.FAILED
    elif aborted:
        run.status = RunStatus.ABORTED
    else:
        run.status = RunStatus.DONE
    result: dict[str, Any] = stats.to_dict()
    if error is not None:
        result["error"] = error
    run.result = result
    run.finished_at = time.time() * 1000.0
    storage.update_run(run)
    return run

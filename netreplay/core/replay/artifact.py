"""Replay scenario as a saved artifact (#40): Scenario -> Run -> Result.

A replay configuration (mode, speed, selection, remapping, mutation) can be
persisted as a Scenario, executed as a ScenarioRun, and its outcome stored as
the Run's Result — so a replay is reproducible and auditable later.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
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

# Portable replay-result artifact (#45). A ``.nrr`` file is JSON that pins a
# replay outcome to the exact source ``.nrp`` it was derived from.
REPLAY_RESULT_FORMAT = 1
REPLAY_RESULT_EXTENSION = ".nrr"
REPLAY_RESULT_KIND = "netreplay.replay-result"


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


@dataclass(slots=True)
class ReplayResultArtifact:
    """A replay outcome pinned to the source ``.nrp`` it was produced from.

    The link is the triple ``session_id`` + ``source_integrity_hash`` +
    ``source_packet_count`` (plus the recorded path and format/schema
    versions), so a stored result can later be checked against the capture it
    claims to describe — :meth:`matches_source` returns ``False`` the moment
    the source capture has changed.
    """

    session_id: str = ""
    source_path: str = ""
    scenario_id: str = ""
    run_id: str = ""
    status: str = RunStatus.DONE.value
    mode: str = ReplayMode.STORY.value
    speed: float = 1.0
    dry_run: bool = False
    stats: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    started_at: float | None = None
    finished_at: float | None = None
    source_integrity_hash: str | None = None
    source_packet_count: int = 0
    source_format_version: int = 0
    source_schema_version: int = 0
    created_at: float = field(default_factory=time.time)
    format_version: int = REPLAY_RESULT_FORMAT

    def __post_init__(self) -> None:
        if not self.session_id:
            raise ValueError("replay result artifact needs a session_id")

    @property
    def is_complete(self) -> bool:
        return self.status == RunStatus.DONE.value

    def source_link(self) -> dict[str, Any]:
        """The minimal verifiable link back to the source capture."""
        return {
            "session_id": self.session_id,
            "source_path": self.source_path,
            "source_integrity_hash": self.source_integrity_hash,
            "source_packet_count": self.source_packet_count,
            "source_format_version": self.source_format_version,
            "source_schema_version": self.source_schema_version,
        }

    def matches_source(self, source: Any) -> bool:
        """True if *source* is the same capture this result was derived from."""
        info = source.info() if hasattr(source, "info") else source
        got_id = str(getattr(info, "session_id", "") or "")
        if self.session_id and got_id and got_id != self.session_id:
            return False
        count = int(getattr(info, "packet_count", 0) or 0)
        if self.source_packet_count and count != self.source_packet_count:
            return False
        want_hash = self.source_integrity_hash
        got_hash = getattr(info, "integrity_hash", None)
        if want_hash and got_hash and want_hash != got_hash:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": REPLAY_RESULT_KIND,
            "format": self.format_version,
            "session_id": self.session_id,
            "source_path": self.source_path,
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "status": self.status,
            "mode": self.mode,
            "speed": self.speed,
            "dry_run": self.dry_run,
            "stats": dict(self.stats),
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "source_integrity_hash": self.source_integrity_hash,
            "source_packet_count": self.source_packet_count,
            "source_format_version": self.source_format_version,
            "source_schema_version": self.source_schema_version,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReplayResultArtifact:
        version = int(data.get("format", REPLAY_RESULT_FORMAT) or 0)
        if version > REPLAY_RESULT_FORMAT:
            raise ValueError(
                f"replay result format v{version} is newer than supported "
                f"v{REPLAY_RESULT_FORMAT}; upgrade NetReplay"
            )
        known = {f for f in cls.__dataclass_fields__}
        fields = {k: v for k, v in data.items() if k in known}
        return cls(**fields)

    def save(self, path: str | Path) -> Path:
        """Write the artifact as a portable ``.nrr`` JSON file."""
        target = Path(path)
        if target.suffix.lower() != REPLAY_RESULT_EXTENSION:
            target = target.with_suffix(REPLAY_RESULT_EXTENSION)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return target

    @classmethod
    def load(cls, path: str | Path) -> ReplayResultArtifact:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("not a replay result artifact")
        return cls.from_dict(data)


def _source_link_fields(source: Any) -> dict[str, Any]:
    """Extract the verifiable source-``.nrp`` link from a session or its info."""
    info = source.info() if hasattr(source, "info") else source
    return {
        "session_id": str(getattr(info, "session_id", "") or ""),
        "source_path": str(getattr(info, "path", "") or ""),
        "source_integrity_hash": getattr(info, "integrity_hash", None),
        "source_packet_count": int(getattr(info, "packet_count", 0) or 0),
        "source_format_version": int(getattr(info, "format_version", 0) or 0),
        "source_schema_version": int(getattr(info, "schema_version", 0) or 0),
    }


def build_replay_result(
    source: Any,
    run: ScenarioRun | None = None,
    *,
    artifact: ReplayArtifact | None = None,
    stats: ReplayStats | None = None,
    error: str | None = None,
) -> ReplayResultArtifact:
    """Build a :class:`ReplayResultArtifact` linked to the source ``.nrp``."""
    link = _source_link_fields(source)
    params = dict(run.parameters) if run is not None else {}
    mode = artifact.mode.value if artifact is not None else params.get(
        "mode", ReplayMode.STORY.value
    )
    speed = artifact.speed if artifact is not None else params.get("speed", 1.0)
    dry_run = artifact.dry_run if artifact is not None else bool(params.get("dry_run", False))
    if stats is not None:
        result_stats = stats.to_dict()
    else:
        result_stats = {
            k: v
            for k, v in (run.result if run is not None else {}).items()
            if k != "artifact"
        }
    status = run.status if run is not None else RunStatus.DONE
    return ReplayResultArtifact(
        session_id=link["session_id"],
        source_path=link["source_path"],
        scenario_id=run.scenario_id if run is not None else "",
        run_id=run.id if run is not None else "",
        status=status.value if isinstance(status, RunStatus) else str(status),
        mode=mode,
        speed=float(speed),
        dry_run=dry_run,
        stats=result_stats,
        error=error,
        started_at=run.started_at if run is not None else None,
        finished_at=run.finished_at if run is not None else None,
        source_integrity_hash=link["source_integrity_hash"],
        source_packet_count=link["source_packet_count"],
        source_format_version=link["source_format_version"],
        source_schema_version=link["source_schema_version"],
    )


def save_replay_result(
    storage: ScenarioStorage,
    run: ScenarioRun,
    source: Any,
    *,
    artifact: ReplayArtifact | None = None,
    error: str | None = None,
) -> ReplayResultArtifact:
    """Attach a linked result artifact to *run* and persist it (#45)."""
    result = build_replay_result(source, run, artifact=artifact, error=error)
    payload = dict(run.result or {})
    payload["artifact"] = result.to_dict()
    run.result = payload
    storage.update_run(run)
    return result


def replay_result_from_run(run: ScenarioRun) -> ReplayResultArtifact | None:
    """Recover the linked result artifact stored on a run, if any."""
    raw = (run.result or {}).get("artifact")
    if not isinstance(raw, dict):
        return None
    try:
        return ReplayResultArtifact.from_dict(raw)
    except ValueError:
        return None


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
    source: Any = None,
    artifact: ReplayArtifact | None = None,
) -> ScenarioRun:
    """Store the replay Result on the Run (#40).

    When *source* (the originating ``.nrp`` session or its ``SessionInfo``) is
    given, a :class:`ReplayResultArtifact` linked back to that capture is built
    and embedded in the result (#45).
    """
    if error is not None:
        run.status = RunStatus.FAILED
    elif aborted:
        run.status = RunStatus.ABORTED
    else:
        run.status = RunStatus.DONE
    result: dict[str, Any] = stats.to_dict()
    if error is not None:
        result["error"] = error
    run.finished_at = time.time() * 1000.0
    if source is not None:
        link = build_replay_result(
            source, run, artifact=artifact, stats=stats, error=error
        )
        result["artifact"] = link.to_dict()
    run.result = result
    storage.update_run(run)
    return run

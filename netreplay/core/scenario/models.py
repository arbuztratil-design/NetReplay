"""Scenario domain model.

A :class:`Scenario` turns a raw capture into a reproducible, saveable case:
the analyst picks a slice of a session (flows, time range, packet range,
protocols) and gives it a name, a description and optional notes. The same
scenario can then be run many times -- every run is a :class:`ScenarioRun`
that captures parameters, state transitions and a final result, so one case
can be re-executed (e.g. replayed, re-analyzed, diffed) without re-capturing.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def new_scenario_id() -> str:
    return uuid.uuid4().hex


def new_run_id() -> str:
    return uuid.uuid4().hex


class ScenarioStatus(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    ARCHIVED = "archived"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass(slots=True)
class TimeRange:
    """Optional absolute window inside a session (seconds)."""

    start: float | None = None
    end: float | None = None

    def contains(self, ts: float) -> bool:
        if self.start is not None and ts < self.start:
            return False
        if self.end is not None and ts > self.end:
            return False
        return True


@dataclass(slots=True)
class FlowSelector:
    """Selects which flows belong to a scenario."""

    flow_ids: list[int] = field(default_factory=list)
    include_all: bool = False

    def matches(self, flow_id: int) -> bool:
        return self.include_all or flow_id in self.flow_ids


@dataclass(slots=True)
class PacketRange:
    """Optional packet cursor window."""

    start: int | None = None
    end: int | None = None


@dataclass(slots=True)
class ScenarioSelection:
    """Everything that identifies what part of a session a scenario covers."""

    session_id: str
    flows: FlowSelector = field(default_factory=FlowSelector)
    time_range: TimeRange = field(default_factory=TimeRange)
    packets: PacketRange = field(default_factory=PacketRange)
    protocols: list[str] = field(default_factory=list)

    def matches_packet(self, ts: float, protocol: str, flow_id: int | None) -> bool:
        if not self.time_range.contains(ts):
            return False
        if self.protocols and protocol not in self.protocols:
            return False
        if flow_id is not None and not self.flows.matches(flow_id):
            return False
        return True


@dataclass(slots=True)
class Scenario:
    """A reproducible case derived from one capture session."""

    id: str = field(default_factory=new_scenario_id)
    session_id: str = ""
    name: str = ""
    description: str = ""
    selection: ScenarioSelection = field(default_factory=lambda: ScenarioSelection(""))
    created_at: float = field(default_factory=time.time)
    status: ScenarioStatus = ScenarioStatus.DRAFT
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    def for_run(self, run_id: str | None = None, parameters: dict[str, Any] | None = None) -> ScenarioRun:
        return ScenarioRun(
            id=run_id or new_run_id(),
            scenario_id=self.id,
            session_id=self.session_id,
            name=self.name,
            selection=self.selection,
            parameters=dict(parameters or {}),
        )


@dataclass(slots=True)
class ScenarioRun:
    """One execution of a :class:`Scenario`."""

    id: str = field(default_factory=new_run_id)
    scenario_id: str = ""
    session_id: str = ""
    name: str = ""
    selection: ScenarioSelection = field(default_factory=lambda: ScenarioSelection(""))
    status: RunStatus = RunStatus.PENDING
    parameters: dict[str, Any] = field(default_factory=dict)
    started_at: float | None = None
    finished_at: float | None = None
    result: dict[str, Any] = field(default_factory=dict)

    def start(self) -> None:
        self.status = RunStatus.RUNNING
        self.started_at = time.time()

    def finish(self, result: dict[str, Any] | None = None, failed: bool = False) -> None:
        self.status = RunStatus.FAILED if failed else RunStatus.DONE
        self.finished_at = time.time()
        if result:
            self.result = result
        elif failed:
            self.result = {"error": "run failed"}


# ------------------------------------------------------------------ annotations


class AnnotationTarget(str, Enum):
    PACKET = "packet"
    FLOW = "flow"
    EVENT = "event"
    TIME_RANGE = "time-range"


@dataclass(slots=True)
class Annotation:
    """An analyst note pinned to a packet, flow, event or time window."""

    target: AnnotationTarget
    target_id: int | None = None
    session_id: str = ""
    label: str = ""
    notes: str = ""
    color: str = "yellow"
    created_at: float = field(default_factory=time.time)
    start_ts: float | None = None
    end_ts: float | None = None
    id: int | None = None

    def validate(self) -> bool:
        if self.target is AnnotationTarget.TIME_RANGE:
            return self.start_ts is not None
        return self.target_id is not None

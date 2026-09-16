"""Scenario persistence: scenarios, runs and annotations.

All tables live in the session's own ``*.nrp`` SQLite file so a scenario is
co-located with the flows/packets it selects and stays saveable as a unit.
Schema is created idempotently; every call opens a short-lived connection so
reads/writes are safe from API threads regardless of capture batching.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path

from netreplay.core.scenario.models import (
    Annotation,
    AnnotationTarget,
    FlowSelector,
    PacketRange,
    RunStatus,
    Scenario,
    ScenarioRun,
    ScenarioSelection,
    ScenarioStatus,
    TimeRange,
    new_run_id,
    new_scenario_id,
)

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS scenarios (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    selection   TEXT NOT NULL DEFAULT '{}',
    tags        TEXT NOT NULL DEFAULT '[]',
    notes       TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'draft',
    created_at  REAL NOT NULL,
    updated_at  REAL
);
CREATE TABLE IF NOT EXISTS scenario_runs (
    id          TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    parameters  TEXT NOT NULL DEFAULT '{}',
    result      TEXT NOT NULL DEFAULT '{}',
    started_at  REAL,
    finished_at REAL
);
CREATE TABLE IF NOT EXISTS annotations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    target     TEXT NOT NULL,
    target_id  TEXT,
    label      TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT '',
    color      TEXT NOT NULL DEFAULT 'yellow',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scenarios_session ON scenarios(session_id);
CREATE INDEX IF NOT EXISTS idx_runs_scenario ON scenario_runs(scenario_id);
CREATE INDEX IF NOT EXISTS idx_annotations_session ON annotations(session_id);
"""


def _now_ms() -> float:
    return time.time() * 1000.0


def _selection_json(selection: ScenarioSelection | None) -> str:
    if selection is None:
        return "{}"
    flows = selection.flows
    time_range = selection.time_range
    packets = selection.packets
    return json.dumps({
        "session_id": selection.session_id,
        "flows": {
            "flow_ids": list(flows.flow_ids) if flows else [],
            "include_all": bool(flows.include_all) if flows else False,
        },
        "time_range": {
            "start": time_range.start if time_range else None,
            "end": time_range.end if time_range else None,
        },
        "packets": {
            "start": packets.start if packets else None,
            "end": packets.end if packets else None,
        },
        "protocols": list(selection.protocols or []),
    })


def _selection_from_json(raw: str) -> ScenarioSelection:
    try:
        data = json.loads(raw or "{}")
    except (ValueError, TypeError):
        data = {}
    flows = data.get("flows") or {}
    tr = data.get("time_range") or {}
    pr = data.get("packets") or {}
    return ScenarioSelection(
        session_id=data.get("session_id") or "",
        flows=FlowSelector(
            flow_ids=list(flows.get("flow_ids") or []),
            include_all=bool(flows.get("include_all")),
        ) if flows else FlowSelector(),
        time_range=TimeRange(
            start=tr.get("start"), end=tr.get("end"),
        ) if tr else TimeRange(),
        packets=PacketRange(
            start=pr.get("start"), end=pr.get("end"),
        ) if pr else PacketRange(),
        protocols=list(data.get("protocols") or []),
    )


def _row_to_scenario(row: sqlite3.Row) -> Scenario:
    return Scenario(
        id=row["id"],
        session_id=row["session_id"],
        name=row["name"],
        description=row["description"],
        selection=_selection_from_json(row["selection"] or "{}"),
        tags=json.loads(row["tags"] or "[]"),
        notes=row["notes"] or "",
        status=ScenarioStatus(row["status"]),
        created_at=row["created_at"] / 1000.0,
    )


def _row_to_run(row: sqlite3.Row) -> ScenarioRun:
    return ScenarioRun(
        id=row["id"],
        scenario_id=row["scenario_id"],
        session_id=row["session_id"],
        name=row["name"],
        status=RunStatus(row["status"]),
        parameters=json.loads(row["parameters"] or "{}"),
        result=json.loads(row["result"] or "{}"),
        started_at=row["started_at"] / 1000.0 if row["started_at"] else None,
        finished_at=row["finished_at"] / 1000.0 if row["finished_at"] else None,
    )


def _row_to_annotation(row: sqlite3.Row) -> Annotation:
    return Annotation(
        id=row["id"],
        session_id=row["session_id"],
        target=AnnotationTarget(row["target"]),
        target_id=row["target_id"],
        label=row["label"],
        notes=row["notes"],
        color=row["color"],
        created_at=row["created_at"] / 1000.0,
    )


class ScenarioStorage:
    """CRUD for scenarios, runs and annotations inside one session file."""

    def __init__(self, session) -> None:
        self.session = session
        self.path = Path(getattr(session, "path", session))

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(_DDL)
        return conn

    # ------------------------------------------------------------ scenarios

    def create_scenario(
        self,
        name: str,
        session_id: str,
        description: str = "",
        selection: ScenarioSelection | None = None,
        tags: list[str] | None = None,
        notes: str = "",
    ) -> Scenario:
        scenario = Scenario(
            id=new_scenario_id(),
            session_id=session_id,
            name=name,
            description=description,
            selection=selection or ScenarioSelection(session_id=session_id),
            tags=tags or [],
            notes=notes,
        )
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO scenarios (id, session_id, name, description,"
                " selection, tags, notes, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (scenario.id, session_id, name, description,
                 _selection_json(scenario.selection) if scenario.selection else "{}",
                 json.dumps(scenario.tags), notes, scenario.status.value,
                 _now_ms()),
            )
            conn.commit()
        finally:
            conn.close()
        return scenario

    def get_scenario(self, scenario_id: str) -> Scenario | None:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM scenarios WHERE id=?", (scenario_id,)
            ).fetchone()
            return _row_to_scenario(row) if row else None
        finally:
            conn.close()

    def list_scenarios(self, session_id: str | None = None) -> list[Scenario]:
        conn = self._conn()
        try:
            if session_id is None:
                rows = conn.execute(
                    "SELECT * FROM scenarios ORDER BY created_at"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scenarios WHERE session_id=?"
                    " ORDER BY created_at", (session_id,),
                ).fetchall()
            return [_row_to_scenario(r) for r in rows]
        finally:
            conn.close()

    def update_scenario(self, scenario: Scenario) -> bool:
        conn = self._conn()
        try:
            cur = conn.execute(
                "UPDATE scenarios SET name=?, description=?, selection=?,"
                " tags=?, notes=?, status=?, updated_at=? WHERE id=?",
                (scenario.name, scenario.description,
                 _selection_json(scenario.selection) if scenario.selection else "{}",
                 json.dumps(scenario.tags), scenario.notes,
                 scenario.status.value, _now_ms(), scenario.id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def delete_scenario(self, scenario_id: str) -> bool:
        conn = self._conn()
        try:
            conn.execute(
                "DELETE FROM scenario_runs WHERE scenario_id=?", (scenario_id,)
            )
            cur = conn.execute(
                "DELETE FROM scenarios WHERE id=?", (scenario_id,)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ------------------------------------------------------------ runs

    def create_run(self, scenario: Scenario, name: str = "") -> ScenarioRun:
        run = ScenarioRun(
            id=new_run_id(),
            scenario_id=scenario.id,
            session_id=scenario.session_id,
            name=name or f"Run of {scenario.name}",
        )
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO scenario_runs (id, scenario_id, session_id, name,"
                " status) VALUES (?,?,?,?,?)",
                (run.id, run.scenario_id, run.session_id, run.name,
                 run.status.value),
            )
            conn.commit()
        finally:
            conn.close()
        return run

    def get_run(self, run_id: str) -> ScenarioRun | None:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM scenario_runs WHERE id=?", (run_id,)
            ).fetchone()
            return _row_to_run(row) if row else None
        finally:
            conn.close()

    def list_runs(self, scenario_id: str | None = None) -> list[ScenarioRun]:
        conn = self._conn()
        try:
            if scenario_id is None:
                rows = conn.execute(
                    "SELECT * FROM scenario_runs ORDER BY started_at"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scenario_runs WHERE scenario_id=?"
                    " ORDER BY started_at", (scenario_id,),
                ).fetchall()
            return [_row_to_run(r) for r in rows]
        finally:
            conn.close()

    def update_run(self, run: ScenarioRun) -> bool:
        status = run.status if isinstance(run.status, str) else run.status.value
        conn = self._conn()
        try:
            cur = conn.execute(
                "UPDATE scenario_runs SET name=?, status=?, parameters=?,"
                " result=?, started_at=?, finished_at=? WHERE id=?",
                (run.name, status, json.dumps(run.parameters),
                 json.dumps(run.result), run.started_at, run.finished_at,
                 run.id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def delete_run(self, run_id: str) -> bool:
        conn = self._conn()
        try:
            cur = conn.execute(
                "DELETE FROM scenario_runs WHERE id=?", (run_id,)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ---------------------------------------------------------- annotations

    def add_annotation(self, annotation: Annotation) -> Annotation:
        conn = self._conn()
        try:
            cur = conn.execute(
                "INSERT INTO annotations (session_id, target, target_id,"
                " label, notes, color, created_at) VALUES (?,?,?,?,?,?,?)",
                (annotation.session_id, annotation.target.value,
                 annotation.target_id, annotation.label, annotation.notes,
                 annotation.color, _now_ms()),
            )
            annotation.id = int(cur.lastrowid or 0)
            conn.commit()
        finally:
            conn.close()
        return annotation

    def list_annotations(self, session_id: str | None = None) -> list[Annotation]:
        conn = self._conn()
        try:
            if session_id is None:
                rows = conn.execute(
                    "SELECT * FROM annotations ORDER BY created_at"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM annotations WHERE session_id=?"
                    " ORDER BY created_at", (session_id,),
                ).fetchall()
            return [_row_to_annotation(r) for r in rows]
        finally:
            conn.close()

    def delete_annotation(self, annotation_id: int) -> bool:
        conn = self._conn()
        try:
            cur = conn.execute(
                "DELETE FROM annotations WHERE id=?", (annotation_id,)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

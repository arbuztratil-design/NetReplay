"""Scenario API: create/list/update/delete scenarios, run a scenario, annotations."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from netreplay.api.routes.util import get_session
from netreplay.api.schemas import (
    AnnotationIn,
    AnnotationOut,
    ScenarioCreateIn,
    ScenarioOut,
    ScenarioRunOut,
)
from netreplay.core.scenario.storage import ScenarioStorage
from netreplay.core.scenario.models import (
    Annotation as AnnotationModel,
    AnnotationTarget,
    Scenario as ScenarioModel,
    ScenarioStatus,
    ScenarioSelection,
)

router = APIRouter(prefix="/scenarios")


def _scenario_storage(request) -> ScenarioStorage:
    session = get_session(request)
    return session.scenario


def _scenario_out(s: ScenarioModel) -> ScenarioOut:
    return ScenarioOut(
        id=s.id,
        session_id=s.session_id,
        name=s.name,
        description=s.description,
        created_at=s.created_at,
        status=s.status.value,
        selection=s.selection.to_dict() if hasattr(s.selection, "to_dict") else {},
        tags=s.tags,
        notes=s.notes,
    )


def _run_out(r) -> ScenarioRunOut:
    return ScenarioRunOut(
        id=r.id,
        scenario_id=r.scenario_id,
        session_id=r.session_id,
        name=r.name,
        status=r.status.value,
        started_at=r.started_at,
        finished_at=r.fished_at if hasattr(r, "fished_at") else r.finished_at,
        parameters=r.parameters,
        result=r.result,
    )


@router.get("", response_model=list[ScenarioOut])
def list_scenarios(
    session_id: str | None = None,
) -> list[ScenarioOut]:
    storage = _scenario_storage(????)
    return [_scenario_out(s) for s in storage.list_scenarios(session_id)]

"""Scenario API: scenarios, runs and annotations co-located in a session."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from netreplay.api.routes import get_session
from netreplay.api.schemas import (
    AnnotationIn,
    AnnotationOut,
    RunCreateIn,
    RunUpdateIn,
    ScenarioCreateIn,
    ScenarioOut,
    ScenarioRunOut,
    ScenarioUpdateIn,
)
from netreplay.core.scenario.models import (
    Annotation as AnnotationModel,
)
from netreplay.core.scenario.models import (
    AnnotationTarget,
    FlowSelector,
    PacketRange,
    RunStatus,
    ScenarioSelection,
    ScenarioStatus,
    TimeRange,
)
from netreplay.core.scenario.models import (
    Scenario as ScenarioModel,
)
from netreplay.core.scenario.storage import ScenarioStorage

router = APIRouter(tags=["scenarios"])


def _storage(request: Request, session_id: str) -> ScenarioStorage:
    return ScenarioStorage(get_session(request, session_id))


def _scenario_out(s: ScenarioModel) -> ScenarioOut:
    return ScenarioOut(
        id=s.id,
        session_id=s.session_id,
        name=s.name,
        description=s.description,
        created_at=s.created_at,
        status=s.status.value,
        tags=list(s.tags),
        notes=s.notes,
    )


def _run_out(r) -> ScenarioRunOut:
    return ScenarioRunOut(
        id=r.id,
        scenario_id=r.scenario_id,
        session_id=r.session_id,
        name=r.name,
        status=r.status.value if hasattr(r.status, "value") else str(r.status),
        started_at=r.started_at,
        finished_at=r.finished_at,
        parameters=dict(r.parameters or {}),
        result=dict(r.result or {}),
    )


def _annotation_out(a: AnnotationModel) -> AnnotationOut:
    return AnnotationOut(
        id=a.id,
        session_id=a.session_id,
        target=a.target.value if hasattr(a.target, "value") else str(a.target),
        target_id=a.target_id,
        label=a.label,
        notes=a.notes,
        color=a.color,
        created_at=a.created_at,
    )


def _selection_from(body: ScenarioCreateIn, session_id: str) -> ScenarioSelection:
    return ScenarioSelection(
        session_id=session_id,
        flows=FlowSelector(
            flow_ids=list(body.flow_ids), include_all=not body.flow_ids
        ),
        time_range=TimeRange(start=body.start_ts, end=body.end_ts),
        packets=PacketRange(start=None, end=None),
        protocols=list(body.protocols),
    )


@router.get("/sessions/{session_id}/scenarios", response_model=list[ScenarioOut])
def list_scenarios(request: Request, session_id: str) -> list[ScenarioOut]:
    return [_scenario_out(s) for s in _storage(request, session_id).list_scenarios()]


@router.post("/sessions/{session_id}/scenarios", response_model=ScenarioOut)
def create_scenario(
    request: Request, session_id: str, body: ScenarioCreateIn
) -> ScenarioOut:
    scenario = _storage(request, session_id).create_scenario(
        name=body.name,
        session_id=session_id,
        description=body.description,
        selection=_selection_from(body, session_id),
        tags=body.tags,
        notes=body.notes,
    )
    return _scenario_out(scenario)


@router.get("/sessions/{session_id}/scenarios/{scenario_id}", response_model=ScenarioOut)
def get_scenario(request: Request, session_id: str, scenario_id: str) -> ScenarioOut:
    scenario = _storage(request, session_id).get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"scenario not found: {scenario_id}")
    return _scenario_out(scenario)


@router.patch("/sessions/{session_id}/scenarios/{scenario_id}", response_model=ScenarioOut)
def update_scenario(
    request: Request, session_id: str, scenario_id: str, body: ScenarioUpdateIn
) -> ScenarioOut:
    storage = _storage(request, session_id)
    scenario = storage.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"scenario not found: {scenario_id}")
    if body.name is not None:
        scenario.name = body.name
    if body.description is not None:
        scenario.description = body.description
    if body.tags is not None:
        scenario.tags = body.tags
    if body.notes is not None:
        scenario.notes = body.notes
    if body.status is not None:
        try:
            scenario.status = ScenarioStatus(body.status)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"bad status: {body.status}") from exc
    storage.update_scenario(scenario)
    return _scenario_out(scenario)


@router.delete("/sessions/{session_id}/scenarios/{scenario_id}")
def delete_scenario(request: Request, session_id: str, scenario_id: str) -> dict:
    deleted = _storage(request, session_id).delete_scenario(scenario_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"scenario not found: {scenario_id}")
    return {"deleted": scenario_id}


@router.get(
    "/sessions/{session_id}/scenarios/{scenario_id}/runs",
    response_model=list[ScenarioRunOut],
)
def list_runs(request: Request, session_id: str, scenario_id: str) -> list[ScenarioRunOut]:
    return [_run_out(r) for r in _storage(request, session_id).list_runs(scenario_id)]


@router.post(
    "/sessions/{session_id}/scenarios/{scenario_id}/runs",
    response_model=ScenarioRunOut,
)
def create_run(
    request: Request, session_id: str, scenario_id: str, body: RunCreateIn
) -> ScenarioRunOut:
    storage = _storage(request, session_id)
    scenario = storage.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"scenario not found: {scenario_id}")
    run = storage.create_run(scenario, name=body.name)
    return _run_out(run)


@router.patch("/sessions/{session_id}/runs/{run_id}", response_model=ScenarioRunOut)
def update_run(
    request: Request, session_id: str, run_id: str, body: RunUpdateIn
) -> ScenarioRunOut:
    storage = _storage(request, session_id)
    run = storage.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    if body.status is not None:
        try:
            run.status = RunStatus(body.status)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"bad status: {body.status}") from exc
    if body.result is not None:
        run.result = body.result
    storage.update_run(run)
    return _run_out(run)


@router.get("/sessions/{session_id}/annotations", response_model=list[AnnotationOut])
def list_annotations(request: Request, session_id: str) -> list[AnnotationOut]:
    return [
        _annotation_out(a)
        for a in _storage(request, session_id).list_annotations(session_id)
    ]


@router.post("/sessions/{session_id}/annotations", response_model=AnnotationOut)
def add_annotation(
    request: Request, session_id: str, body: AnnotationIn
) -> AnnotationOut:
    try:
        target = AnnotationTarget(body.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"bad target: {body.target}") from exc
    annotation = _storage(request, session_id).add_annotation(
        AnnotationModel(
            target=target,
            target_id=body.target_id,
            session_id=session_id,
            label=body.label,
            notes=body.notes,
            color=body.color,
        )
    )
    return _annotation_out(annotation)


@router.delete("/sessions/{session_id}/annotations/{annotation_id}")
def delete_annotation(
    request: Request, session_id: str, annotation_id: int
) -> dict:
    deleted = _storage(request, session_id).delete_annotation(annotation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"annotation not found: {annotation_id}")
    return {"deleted": annotation_id}

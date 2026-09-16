"""P1 #16-18: scenario CRUD + runs + annotations on a real session file."""
from __future__ import annotations

from netreplay.core.scenario.models import (
    Annotation,
    AnnotationTarget,
    FlowSelector,
    PacketRange,
    ScenarioSelection,
    TimeRange,
)
from netreplay.core.scenario.storage import ScenarioStorage
from netreplay.core.storage.database import SessionStorage


def _selection(session_id: str = "sess-1") -> ScenarioSelection:
    return ScenarioSelection(
        session_id=session_id,
        flows=FlowSelector(flow_ids=["f1", "f2"], include_all=False),
        time_range=TimeRange(start=100.0, end=200.0),
        packets=PacketRange(start=1, end=50),
        protocols=["dns", "http"],
    )


def test_scenario_crud(tmp_path) -> None:
    session = SessionStorage(tmp_path / "probe.nrp", create=True)
    store = ScenarioStorage(session)

    created = store.create_scenario(
        name="DNS probe",
        session_id="sess-1",
        selection=_selection(),
        tags=["dns", "lab"],
    )
    assert created.id
    assert created.status.value == "draft"
    assert created.session_id == "sess-1"

    got = store.get_scenario(created.id)
    assert got is not None
    assert got.name == "DNS probe"
    assert got.selection.session_id == "sess-1"

    all_scenarios = store.list_scenarios(session_id="sess-1")
    assert len(all_scenarios) == 1

    got.name = "DNS probe v2"
    got.tags.append("v2")
    assert store.update_scenario(got) is True

    updated = store.get_scenario(created.id)
    assert updated.name == "DNS probe v2"
    assert "v2" in updated.tags

    assert store.delete_scenario(created.id) is True
    assert store.get_scenario(created.id) is None


def test_scenario_runs(tmp_path) -> None:
    session = SessionStorage(tmp_path / "runs.nrp", create=True)
    store = ScenarioStorage(session)

    scenario = store.create_scenario(
        name="Capture run", session_id="sess-2",
    )
    run = store.create_run(scenario, name="Run 1")
    assert run.id
    assert run.status.value == "pending"
    assert run.scenario_id == scenario.id

    got = store.get_run(run.id)
    assert got is not None
    assert got.name == "Run 1"

    got.status = "done"
    got.result = {"packets": 42}
    assert store.update_run(got) is True

    runs = store.list_runs(scenario_id=scenario.id)
    assert len(runs) == 1
    assert runs[0].status.value == "done"
    assert runs[0].result["packets"] == 42


def test_annotations_crud(tmp_path) -> None:
    session = SessionStorage(tmp_path / "ann.nrp", create=True)
    store = ScenarioStorage(session)

    ann = store.add_annotation(Annotation(
        target=AnnotationTarget.PACKET,
        target_id=7,
        session_id="sess-3",
        label="suspicious",
        notes="odd TTL",
        color="red",
    ))
    assert ann.id

    listed = store.list_annotations(session_id="sess-3")
    assert len(listed) == 1
    assert listed[0].label == "suspicious"
    assert listed[0].target.value == "packet"

    assert store.delete_annotation(ann.id) is True
    assert store.list_annotations(session_id="sess-3") == []

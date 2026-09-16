"""P2 #50: regression-test runner over .nrp captures."""
from __future__ import annotations

import json

from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.regression import (
    Expectations,
    RegressionCase,
    cases_from_scenarios,
    check_expectations,
    load_cases,
    run_case,
    run_regression,
)
from netreplay.core.scenario.storage import ScenarioStorage
from netreplay.core.storage import open_session


def _seed(tmp_path, name="case"):
    session = open_session(tmp_path / f"{name}.nrp", create=True)
    session.set_name_and_interface(name, interface="lo")
    session.upsert_flow(Flow(id=1, source="10.0.0.1", destination="10.0.0.2",
                             protocol="TCP", src_port=1000, dst_port=443,
                             start_ts=0.0, end_ts=1.0, packet_count=2, bytes=200,
                             state="ESTABLISHED"))
    for i in range(2):
        session.add_packet(ParsedPacket(
            ts=float(i), source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
            src_port=1000, dst_port=443, length=100, raw=b"frame", flow_id=1,
        ))
    session.add_event(0.5, "DNS", None, "DNS QUERY example.com")
    session.finalize()
    return session


def test_expectations_from_dict_rejects_unknown() -> None:
    assert Expectations.from_dict({"min_packets": 1}).min_packets == 1
    import pytest

    with pytest.raises(ValueError):
        Expectations.from_dict({"bogus": 1})


def test_check_expectations_pass_and_fail(tmp_path) -> None:
    session = _seed(tmp_path)
    ok = check_expectations(session, Expectations(
        min_packets=2, min_flows=1, event_types=["DNS"], max_resets=0,
    ))
    assert all(c.passed for c in ok)

    bad = check_expectations(session, Expectations(
        min_packets=100, event_types=["TLS"],
    ))
    assert any(not c.passed for c in bad)


def test_run_case_missing_session_fails(tmp_path) -> None:
    case = RegressionCase(name="missing", session_path=tmp_path / "nope.nrp")
    result = run_case(case)
    assert result.passed is False
    assert result.error is not None


def test_load_and_run_cases_from_json(tmp_path) -> None:
    _seed(tmp_path, "dns")
    check_file = tmp_path / "dns.check.json"
    check_file.write_text(json.dumps({
        "name": "dns regression",
        "session": "dns.nrp",
        "expect": {"min_packets": 2, "min_flows": 1, "event_types": ["DNS"]},
    }), encoding="utf-8")
    cases = load_cases(tmp_path)
    assert len(cases) == 1
    report = run_regression(cases)
    assert report.ok is True
    assert report.summary() == "1 passed, 0 failed"


def test_run_regression_reports_failure(tmp_path) -> None:
    _seed(tmp_path, "case")
    case = RegressionCase(
        name="too-strict",
        session_path=tmp_path / "case.nrp",
        expect=Expectations(min_packets=1000),
    )
    report = run_regression([case])
    assert report.ok is False
    assert report.failed == 1


def test_cases_from_scenarios(tmp_path) -> None:
    session = _seed(tmp_path, "scn")
    storage = ScenarioStorage(session)
    storage.create_scenario(
        name="scenario regression",
        session_id=session.meta("session_id"),
        notes=json.dumps({"min_packets": 1, "event_types": ["DNS"]}),
    )
    cases = cases_from_scenarios(tmp_path / "scn.nrp")
    assert len(cases) == 1
    assert cases[0].name == "scenario regression"
    result = run_case(cases[0])
    assert result.passed is True

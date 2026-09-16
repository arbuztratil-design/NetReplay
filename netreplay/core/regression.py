"""Regression-test runner over ``.nrp`` captures (#50).

Turns NetReplay into a network-regression platform: a capture plus a set of
expectations becomes a repeatable test. Expectations can be stored either as
JSON (``*.check.json``) or as a Scenario's notes inside a session, so a test
suite lives right next to the captures it validates and can run in CI.

Example check file::

    {
      "name": "dns regression",
      "session": "dns.nrp",
      "expect": {
        "min_packets": 10,
        "min_flows": 2,
        "event_types": ["DNS"],
        "max_resets": 0
      }
    }
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from netreplay.core.stats import compute_stats
from netreplay.core.storage import SessionStorage, open_session


@dataclass(slots=True)
class Expectations:
    min_packets: int | None = None
    max_packets: int | None = None
    min_flows: int | None = None
    max_flows: int | None = None
    event_types: list[str] = field(default_factory=list)
    max_resets: int | None = None
    min_duration: float | None = None
    max_duration: float | None = None

    @classmethod
    def from_dict(cls, data: dict) -> Expectations:
        allowed = set(cls.__dataclass_fields__)
        unknown = set(data) - allowed
        if unknown:
            raise ValueError(f"unknown expectation keys: {sorted(unknown)}")
        return cls(**{k: data[k] for k in data if k in allowed})

    def to_dict(self) -> dict:
        return {
            key: value
            for key, value in (
                (name, getattr(self, name)) for name in self.__dataclass_fields__
            )
            if value not in (None, [], "")
        }


@dataclass(slots=True)
class CheckResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass(slots=True)
class RegressionCase:
    name: str
    session_path: Path
    expect: Expectations = field(default_factory=Expectations)


@dataclass(slots=True)
class RegressionResult:
    name: str
    passed: bool
    checks: list[CheckResult] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class RegressionReport:
    results: list[RegressionResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def ok(self) -> bool:
        return self.failed == 0

    def summary(self) -> str:
        return f"{self.passed} passed, {self.failed} failed"


def check_expectations(session: SessionStorage, expect: Expectations) -> list[CheckResult]:
    """Evaluate expectations against a session; returns per-rule results."""
    stats = compute_stats(session)
    event_types = {row.event_type.upper() for row in session.events(limit=1_000_000)}
    checks: list[CheckResult] = []

    def compare(name: str, actual: float, minimum: float | None, maximum: float | None) -> None:
        if minimum is not None:
            checks.append(CheckResult(f"{name} >= {minimum}", actual >= minimum, f"actual={actual}"))
        if maximum is not None:
            checks.append(CheckResult(f"{name} <= {maximum}", actual <= maximum, f"actual={actual}"))

    compare("packets", stats.packet_count, expect.min_packets, expect.max_packets)
    compare("flows", stats.flow_count, expect.min_flows, expect.max_flows)
    compare("duration", stats.duration, expect.min_duration, expect.max_duration)
    if expect.max_resets is not None:
        checks.append(CheckResult(
            f"resets <= {expect.max_resets}", stats.reset_count <= expect.max_resets,
            f"actual={stats.reset_count}",
        ))
    for wanted in expect.event_types:
        checks.append(CheckResult(
            f"event {wanted}", wanted.upper() in event_types,
            f"present={sorted(event_types)}",
        ))
    return checks


def run_case(case: RegressionCase) -> RegressionResult:
    """Run one regression case against its capture (#50)."""
    try:
        session = open_session(case.session_path)
    except Exception as exc:  # noqa: BLE001 - reported as a failed test
        return RegressionResult(name=case.name, passed=False, error=f"{type(exc).__name__}: {exc}")
    if session is None:
        return RegressionResult(name=case.name, passed=False, error="session not found")
    checks = check_expectations(session, case.expect)
    return RegressionResult(
        name=case.name,
        passed=all(c.passed for c in checks),
        checks=checks,
    )


def run_regression(cases: list[RegressionCase]) -> RegressionReport:
    return RegressionReport(results=[run_case(case) for case in cases])


def load_cases(path: str | Path) -> list[RegressionCase]:
    """Load regression cases from a JSON file or every ``*.check.json`` in a dir."""
    root = Path(path)
    files = sorted(root.glob("*.check.json")) if root.is_dir() else [root]
    cases: list[RegressionCase] = []
    for file in files:
        data = json.loads(Path(file).read_text(encoding="utf-8"))
        base = Path(file).parent
        session_name = data.get("session")
        if not session_name:
            raise ValueError(f"{file}: missing 'session'")
        cases.append(RegressionCase(
            name=data.get("name") or Path(session_name).stem,
            session_path=(base / session_name),
            expect=Expectations.from_dict(data.get("expect", {})),
        ))
    return cases


def cases_from_scenarios(session_path: str | Path) -> list[RegressionCase]:
    """Build regression cases from scenarios stored in one session (#50)."""
    from netreplay.core.scenario.storage import ScenarioStorage

    session = open_session(session_path)
    if session is None:
        raise FileNotFoundError(f"session not found: {session_path}")
    storage = ScenarioStorage(session)
    cases: list[RegressionCase] = []
    for scenario in storage.list_scenarios():
        raw_notes = scenario.notes or ""
        expect = Expectations()
        if raw_notes.strip().startswith("{"):
            expect = Expectations.from_dict(json.loads(raw_notes))
        cases.append(RegressionCase(
            name=scenario.name or scenario.id,
            session_path=Path(session_path),
            expect=expect,
        ))
    return cases

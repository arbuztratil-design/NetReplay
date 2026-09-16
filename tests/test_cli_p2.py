"""P2 CLI smoke tests: export / sanitize / compare / incidents / regression."""
from __future__ import annotations

import json

from typer.testing import CliRunner

from netreplay.cli.main import app
from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage import open_session

runner = CliRunner()


def _seed(tmp_path, name):
    session = open_session(tmp_path / f"{name}.nrp", create=True)
    session.set_name_and_interface(name, interface="lo")
    session.upsert_flow(Flow(id=1, source="10.0.0.1", destination="10.0.0.2",
                             protocol="TCP", src_port=1000, dst_port=443,
                             start_ts=0.0, end_ts=1.0, packet_count=2, bytes=200,
                             state="ESTABLISHED"))
    for i in range(2):
        session.add_packet(ParsedPacket(
            ts=float(i), source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
            src_port=1000, dst_port=443, length=100, raw=b"\x00" * 64, flow_id=1,
        ))
    session.add_event(0.5, "DNS", None, "DNS QUERY example.com")
    session.finalize()
    return session


def test_cli_export(tmp_path):
    _seed(tmp_path, "a")
    out = tmp_path / "a.json"
    result = runner.invoke(app, ["export", str(tmp_path / "a.nrp"), "-o", str(out), "-f", "json"])
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert "Rows:" in result.output


def test_cli_sanitize(tmp_path):
    _seed(tmp_path, "a")
    out = tmp_path / "clean.nrp"
    result = runner.invoke(app, ["sanitize", str(tmp_path / "a.nrp"), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert "Redacted" in result.output


def test_cli_compare(tmp_path):
    _seed(tmp_path, "a")
    _seed(tmp_path, "b")
    result = runner.invoke(app, ["compare", str(tmp_path / "a.nrp"), str(tmp_path / "b.nrp")])
    assert result.exit_code == 0, result.output
    assert "Identical: yes" in result.output


def test_cli_incidents(tmp_path):
    _seed(tmp_path, "a")
    _seed(tmp_path, "b")
    result = runner.invoke(app, ["incidents", str(tmp_path / "a.nrp"), "-w", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "similar incidents" in result.output


def test_cli_regression_pass(tmp_path):
    _seed(tmp_path, "a")
    check = tmp_path / "a.check.json"
    check.write_text(json.dumps({
        "name": "cli regression",
        "session": "a.nrp",
        "expect": {"min_packets": 1, "event_types": ["DNS"]},
    }), encoding="utf-8")
    result = runner.invoke(app, ["regression", str(check)])
    assert result.exit_code == 0, result.output
    assert "PASS" in result.output


def test_cli_regression_fail_exit_code(tmp_path):
    _seed(tmp_path, "a")
    check = tmp_path / "a.check.json"
    check.write_text(json.dumps({
        "name": "too strict",
        "session": "a.nrp",
        "expect": {"min_packets": 9999},
    }), encoding="utf-8")
    result = runner.invoke(app, ["regression", str(check)])
    assert result.exit_code == 1
    assert "FAIL" in result.output

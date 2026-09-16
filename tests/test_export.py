"""P2 #48: export to PCAP/PCAPNG/JSON/NDJSON/CSV."""
from __future__ import annotations

import csv
import json
import struct

import pytest

from scapy.all import Ether, IP, TCP

from netreplay.core.export import (
    export_csv,
    export_json,
    export_ndjson,
    export_pcap,
    export_pcapng,
    export_session,
)
from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage import open_session


def _seed(tmp_path):
    session = open_session(tmp_path / "exp.nrp", create=True)
    session.set_name_and_interface("export-me", interface="eth0")
    session.upsert_flow(Flow(id=1, source="10.0.0.1", destination="10.0.0.2",
                             protocol="TCP", src_port=5000, dst_port=443,
                             start_ts=0.0, end_ts=1.0, packet_count=2, bytes=148,
                             state="ESTABLISHED"))
    for i in range(2):
        frame = bytes(Ether(src="aa:aa:aa:aa:aa:01", dst="bb:bb:bb:bb:bb:02")
                      / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=443)
                      / (bytes([i]) * 4))
        session.add_packet(ParsedPacket(
            ts=1.0 + i, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
            src_port=5000, dst_port=443, length=len(frame), raw=frame, flow_id=1,
        ))
    session.add_event(1.0, "TLS", 1, "TLS ClientHello")
    session.finalize()
    return session


def test_export_pcap_header_and_count(tmp_path) -> None:
    session = _seed(tmp_path)
    out = tmp_path / "out.pcap"
    count = export_pcap(session, out)
    assert count == 2
    data = out.read_bytes()
    magic, vmaj, vmin, _tz, _sf, snap, link = struct.unpack("<IHHiIII", data[:24])
    assert magic == 0xA1B2C3D4
    assert (vmaj, vmin) == (2, 4)
    assert snap == 65535
    assert link == 1
    assert len(data) > 24


def test_export_pcapng_has_blocks(tmp_path) -> None:
    session = _seed(tmp_path)
    out = tmp_path / "out.pcapng"
    count = export_pcapng(session, out)
    assert count == 2
    data = out.read_bytes()
    assert data[:4] == b"\x0a\x0d\x0d\x0a"  # SHB
    assert struct.unpack("<I", data[8:12])[0] == 0x1A2B3C4D  # byte-order magic


def test_export_json_structure(tmp_path) -> None:
    session = _seed(tmp_path)
    out = tmp_path / "out.json"
    count = export_json(session, out)
    assert count == 2
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["name"] == "export-me"
    assert len(doc["flows"]) == 1
    assert len(doc["events"]) == 1
    assert len(doc["packets"]) == 2
    assert doc["packets"][0]["raw_len"] > 0


def test_export_ndjson_lines(tmp_path) -> None:
    session = _seed(tmp_path)
    out = tmp_path / "out.ndjson"
    count = export_ndjson(session, out)
    assert count == 2
    lines = [line for line in out.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 2
    assert json.loads(lines[0])["protocol"] == "TCP"


def test_export_csv_packets_and_flows(tmp_path) -> None:
    session = _seed(tmp_path)
    packets_csv = tmp_path / "packets.csv"
    assert export_csv(session, packets_csv, kind="packets") == 2
    with open(packets_csv, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["source"] == "10.0.0.1"
    assert rows[0]["dst_port"] == "443"

    flows_csv = tmp_path / "flows.csv"
    assert export_csv(session, flows_csv, kind="flows") == 1
    with open(flows_csv, encoding="utf-8", newline="") as handle:
        flow_rows = list(csv.DictReader(handle))
    assert flow_rows[0]["state"] == "ESTABLISHED"


def test_export_csv_rejects_bad_kind(tmp_path) -> None:
    session = _seed(tmp_path)
    with pytest.raises(ValueError):
        export_csv(session, tmp_path / "x.csv", kind="bogus")


def test_export_session_dispatch(tmp_path) -> None:
    session = _seed(tmp_path)
    assert export_session(session, tmp_path / "a.pcap", "pcap") == 2
    assert export_session(session, tmp_path / "a.csv", "csv") == 2
    with pytest.raises(ValueError):
        export_session(session, tmp_path / "a.zzz", "zzz")

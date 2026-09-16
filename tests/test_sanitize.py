"""P2 #47: capture sanitization/redaction."""
from __future__ import annotations

from scapy.all import Ether, IP, TCP

from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.sanitize import RedactionPolicy, Redactor, sanitize_session
from netreplay.core.storage import open_session


def _seed(src):
    session = open_session(src, create=True)
    session.set_name_and_interface("original", interface="eth0")
    session.upsert_flow(Flow(
        id=1, source="203.0.113.7", destination="10.1.2.3", protocol="TCP",
        src_port=5000, dst_port=443, start_ts=0.0, end_ts=1.0,
        packet_count=1, bytes=74, state="ESTABLISHED",
    ))
    frame = bytes(
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="203.0.113.7", dst="10.1.2.3") / TCP(sport=5000, dport=443) / b"secret"
    )
    session.add_packet(ParsedPacket(
        ts=1.0, source="203.0.113.7", destination="10.1.2.3", protocol="TCP",
        src_port=5000, dst_port=443, length=len(frame), raw=frame, flow_id=1,
    ))
    session.add_event(1.0, "DNS", None, "DNS QUERY example.com (A)")
    session.add_event(2.0, "TLS", 1, "TLS ClientHello sni=example.com")
    session.finalize()
    return session


def test_redactor_deterministic_and_distinct():
    redactor = Redactor(RedactionPolicy())
    assert redactor.ip("1.2.3.4") == redactor.ip("1.2.3.4")
    assert redactor.ip("1.2.3.4") != redactor.ip("5.6.7.8")
    assert redactor.domain("a.com") == "host-0.example"
    assert redactor.text("visit a.com then b.org") == "visit host-0.example then host-1.example"


def test_redactor_disabled_policy_is_identity():
    redactor = Redactor(RedactionPolicy(redact_ips=False, redact_macs=False, redact_domains=False))
    assert redactor.ip("1.2.3.4") == "1.2.3.4"
    assert redactor.text("a.com") == "a.com"


def test_sanitize_session_removes_identifiers(tmp_path):
    _seed(tmp_path / "orig.nrp")
    report = sanitize_session(tmp_path / "orig.nrp", tmp_path / "clean.nrp")
    assert report.flows == 1
    assert report.packets == 1
    assert report.events == 2
    assert report.ips_redacted == 2  # 203.0.113.7 and 10.1.2.3

    clean = open_session(tmp_path / "clean.nrp")
    flows = clean.flows()
    assert flows[0].source.startswith("10.255.")
    assert "203.0.113.7" not in flows[0].source

    summaries = [row.summary for row in clean.events(limit=100)]
    assert any("host-0.example" in s for s in summaries)
    assert all("example.com" not in s for s in summaries)

    row = next(iter(clean.packets()))
    _meta, raw = clean.packet(row.id)
    assert raw[12:14] == b"\x08\x00"
    assert raw[26:30] != bytes([203, 0, 113, 7])  # source IP rewritten
    assert raw[0:6] != bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])  # MAC rewritten


def test_sanitize_refuses_missing_source(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        sanitize_session(tmp_path / "nope.nrp", tmp_path / "out.nrp")

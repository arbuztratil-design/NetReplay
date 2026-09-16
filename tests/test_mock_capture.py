"""Mock and PCAP-file capture backends for the CLI/pipeline (no Npcap needed)."""
from __future__ import annotations

import time

from scapy.all import DNS, DNSQR, IP, UDP, Ether
from scapy.utils import PcapWriter

from netreplay.core.capture import MockBackend, PcapBackend
from netreplay.core.packets.parser import parse_packet
from netreplay.core.service import NetReplayService
from netreplay.core.storage import open_session


def test_mock_backend_emits_parseable_frames():
    backend = MockBackend(packets=12)
    backend.start()
    frames = list(backend.packets())
    assert len(frames) == 12
    protocols = set()
    for frame in frames:
        parsed = parse_packet(frame.data, ts=frame.ts)
        assert parsed.source and parsed.destination
        protocols.add(parsed.protocol)
    assert "ARP" in protocols
    assert "TCP" in protocols
    assert "DNS" in protocols or "UDP" in protocols


def test_mock_capture_pipeline(tmp_path):
    output = tmp_path / "mock.nrp"
    service = NetReplayService(tmp_path)
    backend = MockBackend(packets=40)
    controller = service.start_capture(interface="mock", output=output, backend=backend)
    deadline = time.time() + 20
    while controller.status().running and time.time() < deadline:
        time.sleep(0.02)
    controller.stop(timeout=5)

    session = open_session(output)
    info = session.info()
    assert info.status == "ready"
    assert info.packet_count >= 20
    assert info.flow_count >= 2

    events = session.events(limit=500)
    kinds = {e.event_type for e in events}
    assert "TCP" in kinds
    assert "DNS" in kinds
    assert "TLS" in kinds
    assert any(e.event_type == "DNS" and "example.com" in e.summary for e in events)
    assert any(e.event_type == "TLS" and "sni=example.com" in e.summary for e in events)


def _write_dns_pcap(path, count: int = 1) -> None:
    with PcapWriter(str(path), sync=True, linktype=1) as w:
        for i in range(count):
            pkt = (
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                / IP(src="192.168.1.10", dst="8.8.8.8")
                / UDP(sport=53000 + i, dport=53)
                / DNS(qr=0, qd=DNSQR(qname="example.com", qtype="A"))
            )
            pkt.time = float(1000 + i)
            w.write(pkt)


def test_pcap_backend_reads_file(tmp_path):
    path = tmp_path / "demo.pcap"
    _write_dns_pcap(path, count=3)
    backend = PcapBackend(path)
    backend.start()
    frames = list(backend.packets())
    assert len(frames) == 3
    parsed = parse_packet(frames[0].data, ts=frames[0].ts)
    assert parsed.protocol == "DNS"


def test_capture_cli_mock(tmp_path):
    from typer.testing import CliRunner

    from netreplay.cli.main import app

    output = tmp_path / "cli_mock.nrp"
    result = CliRunner().invoke(
        app, ["capture", "--mock", "--output", str(output), "--mock-packets", "40"]
    )
    assert result.exit_code == 0, result.output
    session = open_session(output)
    info = session.info()
    assert info.packet_count >= 20
    assert info.flow_count >= 2


def test_capture_cli_source(tmp_path):
    from typer.testing import CliRunner

    from netreplay.cli.main import app

    pcap = tmp_path / "src.pcap"
    _write_dns_pcap(pcap, count=3)
    output = tmp_path / "cli_src.nrp"
    result = CliRunner().invoke(
        app, ["capture", "--source", str(pcap), "--output", str(output)]
    )
    assert result.exit_code == 0, result.output
    session = open_session(output)
    info = session.info()
    assert info.packet_count == 3
    assert info.flow_count == 3  # one per distinct source port


def test_capture_cli_rejects_conflicting_sources(tmp_path):
    from typer.testing import CliRunner

    from netreplay.cli.main import app

    result = CliRunner().invoke(
        app, ["capture", "--mock", "--source", "x.pcap", "--output", str(tmp_path / "c.nrp")]
    )
    assert result.exit_code == 1
    assert "mutually exclusive" in result.output

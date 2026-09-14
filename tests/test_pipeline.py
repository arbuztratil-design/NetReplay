"""End-to-end pipeline test with a fake capture backend.

Drives the real pipeline (backend -> parser -> flows -> events -> storage)
without touching the network.
"""
from __future__ import annotations

import time

from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP

from netreplay.core.capture.base import CaptureBackend
from netreplay.core.packets.models import CapturedPacket
from netreplay.core.service import CaptureController
from netreplay.core.storage import open_session


class FakeBackend(CaptureBackend):
    def __init__(self, interface, packets):
        super().__init__(interface)
        self._packets = list(packets)
        self.started = False
        self._running = False
        self._error: Exception | None = None

    @property
    def running(self):
        return self._running

    def start(self):
        self.started = True
        self._running = True

    def stop(self):
        self._running = False

    def packets(self):
        for p in self._packets:
            yield p
        self._running = False
        if self._error is not None:
            raise self._error


def _handshake_packets():
    """Small synthetic conversation: TCP handshake + a DNS query."""
    pkts = []
    ts = 100.0
    pairs = [
        (TCP(sport=49152, dport=443, flags="S"),
         "192.168.1.5", "142.250.0.1"),
        (TCP(sport=443, dport=49152, flags="SA"),
         "142.250.0.1", "192.168.1.5"),
        (TCP(sport=49152, dport=443, flags="A"),
         "192.168.1.5", "142.250.0.1"),
    ]
    for layer, src, dst in pairs:
        pkt = Ether() / IP(src=src, dst=dst) / layer
        pkts.append(CapturedPacket(ts=ts, data=bytes(pkt)))
        ts += 0.05
    dns = (
        Ether()
        / IP(src="192.168.1.5", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(qr=0, qd=DNSQR(qname="example.com", qtype="A"))
    )
    pkts.append(CapturedPacket(ts=ts, data=bytes(dns)))
    return pkts


def test_capture_pipeline(tmp_path):
    output = tmp_path / "pipe.nrp"
    events: list = []
    backend = FakeBackend("fake0", _handshake_packets())
    controller = CaptureController(
        interface="fake0", output=output, on_event=lambda e: events.append(e), backend=backend
    )
    controller.start()
    deadline = time.time() + 15
    while controller.status().running and time.time() < deadline:
        time.sleep(0.02)
    controller.stop(timeout=5)

    session = open_session(output)
    info = session.info()
    assert info.status == "complete"
    assert info.packet_count == 4
    assert info.flow_count == 2  # TCP flow + DNS flow

    kinds = [e.type for e in events]
    assert "TCP" in kinds
    assert "DNS" in kinds
    summaries = [e.summary for e in events]
    assert any(s.endswith("[ESTABLISHED]") for s in summaries)
    assert any(s.startswith("DNS QUERY") for s in summaries)

    flows = session.flows()
    tcp_flow = next(f for f in flows if f.protocol == "TCP")
    assert tcp_flow.state == "ESTABLISHED"
    assert tcp_flow.packet_count == 3
    dns_flow = next(f for f in flows if f.protocol in ("DNS", "UDP"))
    assert dns_flow.packet_count == 1

    # Packets are retrievable together with raw bytes.
    packets = session.packets_for_flow(tcp_flow.id)
    assert len(packets) == 3
    _, raw = session.packet(packets[0].id)
    assert len(raw) == packets[0].length


def test_capture_error_is_reported(tmp_path):
    """A failing backend (e.g. no Npcap) must surface as controller.status().error."""
    from netreplay.core.capture.base import CaptureError

    output = tmp_path / "failed.nrp"
    backend = FakeBackend("fake0", [])
    backend._error = CaptureError("boom: no pcap provider")
    controller = CaptureController(
        interface="fake0", output=output, backend=backend
    )
    controller.start()
    deadline = time.time() + 15
    while controller.status().running and time.time() < deadline:
        time.sleep(0.02)
    controller.stop(timeout=5)

    status = controller.status()
    assert status.error is not None
    assert "boom: no pcap provider" in status.error
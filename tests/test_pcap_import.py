from __future__ import annotations

from pathlib import Path

import scapy.all as scapy
from scapy.utils import PcapWriter

from netreplay.core.service import NetReplayService
from netreplay.core.storage import open_session


def test_pcap_backend_import(tmp_path: Path) -> None:
    pcap_file = tmp_path / "sample.pcap"
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    scapy.conf.verb = 0
    mac_a = "00:11:22:33:44:55"
    mac_b = "66:77:88:99:aa:bb"
    mac_c = "aa:bb:cc:dd:ee:ff"
    packets = [
        scapy.Ether(src=mac_a, dst=mac_b) / scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.TCP(sport=1234, dport=80, flags="S"),
        scapy.Ether(src=mac_b, dst=mac_a) / scapy.IP(src="192.0.2.2", dst="192.0.2.1") / scapy.TCP(sport=80, dport=1234, flags="SA"),
        scapy.Ether(src=mac_a, dst=mac_b) / scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.TCP(sport=1234, dport=80, flags="A"),
        scapy.Ether(src=mac_c, dst=mac_b) / scapy.IP(src="192.0.2.3", dst="192.0.2.4") / scapy.UDP(sport=5678, dport=53),
    ]

    with PcapWriter(str(pcap_file), sync=True) as writer:
        for pkt in packets:
            writer.write(pkt)

    with PcapWriter(str(pcap_file), sync=True) as writer:
        for pkt in packets:
            writer.write(pkt)

    service = NetReplayService(workspace)
    status = service.import_pcap(pcap_file)

    assert status.packets == 4
    assert status.flows >= 2
    assert not status.running
    assert status.error is None

    sessions = service.list_sessions()
    assert len(sessions) == 1
    storage = service.open_session(sessions[0].session_id)
    assert storage is not None

    flows_list = list(storage.flows())
    assert len(flows_list) >= 2

    tcp_flow = next((f for f in flows_list if f.protocol == "TCP"), None)
    assert tcp_flow is not None
    assert tcp_flow.source in {"192.0.2.1", "192.0.2.2"}

    events = list(storage.events())
    assert len(events) >= 2

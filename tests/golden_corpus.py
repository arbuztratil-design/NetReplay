"""Golden PCAP/PCAPNG test corpus (#46).

Deterministic captures covering the traffic classes NetReplay must get right:
TCP handshake/data, retransmission, sequence gap, IPv4 + IPv6, TLS
ClientHello, HTTP/2 preface and malformed frames. Each scenario ships with the
*expected* facts the engine must produce, so a regression in the parser,
reassembly, protocol analyzers or storage fails a specific golden assertion
instead of silently changing behaviour.

Captures are built at test time (no binary blobs in the repo); use
:func:`write_corpus` to materialise them into a directory when needed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import scapy.all as scapy
from scapy.all import Ether, IP, IPv6, Raw, TCP, UDP
from scapy.utils import PcapNgWriter, PcapWriter

scapy.conf.verb = 0

MAC_C = "00:11:22:33:44:55"  # client / initiator
MAC_S = "66:77:88:99:aa:bb"  # server / responder
IP_C, IP_S = "192.0.2.1", "192.0.2.2"
V6_C, V6_S = "2001:db8::1", "2001:db8::2"


# --------------------------------------------------------------------- builders


def tls_client_hello(sni: str = "example.com") -> bytes:
    """A minimal TLS record carrying a ClientHello (SNI + ALPN + TLS 1.3)."""
    body = bytearray()
    body += b"\x03\x03" + bytes(32)  # version + random
    body += b"\x00"  # session id length
    body += b"\x00\x02\x13\x01"  # one cipher suite (TLS_AES_128_GCM_SHA256)
    body += b"\x00"  # compression methods length
    name = sni.encode()
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    list_data = len(entry).to_bytes(2, "big") + entry
    sni_ext = b"\x00\x00" + len(list_data).to_bytes(2, "big") + list_data
    alpn_list = b"\x00\x02h2"
    alpn_ext = b"\x00\x10" + len(alpn_list).to_bytes(2, "big") + alpn_list
    ver_list = b"\x02\x03\x04"
    ver_ext = b"\x00\x2b" + len(ver_list).to_bytes(2, "big") + ver_list
    body += (len(sni_ext) + len(alpn_ext) + len(ver_ext)).to_bytes(2, "big")
    body += sni_ext + alpn_ext + ver_ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def http2_preface_and_settings() -> bytes:
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = b"\x00\x00\x06" + b"\x04" + b"\x00" + b"\x00\x00\x00\x00"
    settings += b"\x00\x03\x00\x00\x00\x64"  # MAX_CONCURRENT_STREAMS=100
    return preface + settings


def _c2s(**kw):
    return Ether(src=MAC_C, dst=MAC_S) / IP(src=IP_C, dst=IP_S) / TCP(**kw)


def _s2c(**kw):
    return Ether(src=MAC_S, dst=MAC_C) / IP(src=IP_S, dst=IP_C) / TCP(**kw)


def _handshake(sport: int, dport: int) -> list:
    return [
        _c2s(sport=sport, dport=dport, seq=0, flags="S"),
        _s2c(sport=dport, dport=sport, seq=0, ack=1, flags="SA"),
        _c2s(sport=sport, dport=dport, seq=1, ack=1, flags="A"),
    ]


def _scenario_tcp_basic() -> list:
    return _handshake(1234, 80) + [
        _c2s(sport=1234, dport=80, seq=1, ack=1, flags="PA")
        / Raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        _s2c(sport=80, dport=1234, seq=1, ack=19, flags="PA")
        / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        _c2s(sport=1234, dport=80, seq=19, ack=36, flags="FA"),
    ]


def _scenario_tcp_retransmission() -> list:
    return _handshake(1234, 80) + [
        _c2s(sport=1234, dport=80, seq=1, ack=1, flags="PA") / Raw(b"hello"),
        _s2c(sport=80, dport=1234, seq=1, ack=6, flags="A"),
        _c2s(sport=1234, dport=80, seq=1, ack=1, flags="PA") / Raw(b"hello"),
    ]


def _scenario_tcp_gap() -> list:
    return _handshake(1234, 80) + [
        _c2s(sport=1234, dport=80, seq=1, ack=1, flags="PA") / Raw(b"AAAA"),
        _c2s(sport=1234, dport=80, seq=100, ack=1, flags="PA") / Raw(b"BBBB"),
    ]


def _scenario_ipv4_ipv6() -> list:
    return [
        Ether(src=MAC_C, dst=MAC_S) / IP(src=IP_C, dst=IP_S)
        / TCP(sport=2345, dport=443, seq=1, flags="PA") / Raw(b"v4"),
        Ether(src=MAC_C, dst=MAC_S) / IPv6(src=V6_C, dst=V6_S)
        / TCP(sport=3456, dport=443, seq=1, flags="PA") / Raw(b"v6"),
        Ether(src=MAC_C, dst=MAC_S) / IP(src=IP_C, dst=IP_S)
        / UDP(sport=5353, dport=53) / Raw(b"\x00\x01"),
    ]


def _scenario_tls_client_hello() -> list:
    return _handshake(4000, 443) + [
        _c2s(sport=4000, dport=443, seq=1, ack=1, flags="PA")
        / Raw(tls_client_hello("example.com")),
    ]


def _scenario_http2_preface() -> list:
    return _handshake(5000, 8080) + [
        _c2s(sport=5000, dport=8080, seq=1, ack=1, flags="PA")
        / Raw(http2_preface_and_settings()),
    ]


def _scenario_malformed() -> list:
    """One good frame plus two frames the parser must tolerate, not crash on:
    a zeroed short Ethernet frame and an unknown EtherType carrying garbage."""
    short = Ether(bytes(14))
    unknown = Ether(src=MAC_C, dst=MAC_S, type=0x9999) / Raw(b"garbage")
    return [
        Ether(src=MAC_C, dst=MAC_S) / IP(src=IP_C, dst=IP_S)
        / TCP(sport=1234, dport=80, seq=1, flags="PA") / Raw(b"ok"),
        short,
        unknown,
    ]


# ------------------------------------------------------------------ golden data


@dataclass(slots=True)
class GoldenCapture:
    name: str
    packets: list
    suffix: str = ".pcap"
    expected_packets: int = 0
    protocols: frozenset[str] = frozenset()
    event_types: frozenset[str] = frozenset()
    facts: dict[str, str] = field(default_factory=dict)
    has_ipv6: bool = False
    min_flows: int = 0


def _build() -> dict[str, GoldenCapture]:
    return {
        "tcp_basic": GoldenCapture(
            name="tcp_basic",
            packets=_scenario_tcp_basic(),
            expected_packets=6,
            protocols=frozenset({"TCP"}),
            event_types=frozenset({"TCP", "HTTP"}),
            min_flows=1,
        ),
        "tcp_retransmission": GoldenCapture(
            name="tcp_retransmission",
            packets=_scenario_tcp_retransmission(),
            expected_packets=6,
            protocols=frozenset({"TCP"}),
            event_types=frozenset({"STREAM_RETRANSMISSION"}),
            min_flows=1,
        ),
        "tcp_gap": GoldenCapture(
            name="tcp_gap",
            packets=_scenario_tcp_gap(),
            expected_packets=5,
            protocols=frozenset({"TCP"}),
            event_types=frozenset({"STREAM_GAP"}),
            min_flows=1,
        ),
        "ipv4_ipv6": GoldenCapture(
            name="ipv4_ipv6",
            packets=_scenario_ipv4_ipv6(),
            expected_packets=3,
            protocols=frozenset({"TCP", "DNS"}),
            has_ipv6=True,
            min_flows=2,
        ),
        "tls_client_hello": GoldenCapture(
            name="tls_client_hello",
            packets=_scenario_tls_client_hello(),
            expected_packets=4,
            protocols=frozenset({"TCP"}),
            event_types=frozenset({"TLS"}),
            facts={"tls.sni": "example.com"},
            min_flows=1,
        ),
        "http2_preface": GoldenCapture(
            name="http2_preface",
            packets=_scenario_http2_preface(),
            expected_packets=4,
            protocols=frozenset({"TCP"}),
            event_types=frozenset({"HTTP2"}),
            facts={"http2.frame_type": "SETTINGS"},
            min_flows=1,
        ),
        "malformed": GoldenCapture(
            name="malformed",
            packets=_scenario_malformed(),
            expected_packets=3,
            min_flows=1,
        ),
        "tcp_basic_pcapng": GoldenCapture(
            name="tcp_basic_pcapng",
            packets=_scenario_tcp_basic(),
            suffix=".pcapng",
            expected_packets=6,
            protocols=frozenset({"TCP"}),
            event_types=frozenset({"TCP", "HTTP"}),
            min_flows=1,
        ),
    }


SCENARIOS: dict[str, GoldenCapture] = _build()


def _stamp(packets: list) -> list:
    for i, pkt in enumerate(packets):
        pkt.time = 1.0 + i * 0.001
    return packets


def write_capture(capture: GoldenCapture, directory: Path) -> Path:
    """Write one golden capture to *directory* and return the file path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{capture.name}{capture.suffix}"
    packets = _stamp(capture.packets)
    if capture.suffix == ".pcapng":
        with PcapNgWriter(str(path)) as writer:
            for pkt in packets:
                writer.write(pkt)
    else:
        with PcapWriter(str(path), sync=True) as writer:
            for pkt in packets:
                writer.write(pkt)
    return path


def build(name: str, directory: Path) -> tuple[GoldenCapture, Path]:
    """Write the named scenario to *directory*."""
    return SCENARIOS[name], write_capture(SCENARIOS[name], directory)


def write_corpus(directory: str | Path) -> list[Path]:
    """Materialise every golden capture into *directory*."""
    base = Path(directory)
    return [write_capture(cap, base) for cap in SCENARIOS.values()]

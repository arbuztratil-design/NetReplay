"""P2 #49: HTTP/1.x, HTTP/2 and QUIC analyzers."""
from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, UDP

from netreplay.core.packets.models import ParsedPacket
from netreplay.core.protocols.analyzer import analyze_app_layer
from netreplay.core.protocols.http import (
    H2_PREFACE,
    analyze_http,
    analyze_http2,
    analyze_quic,
)


def test_http_request() -> None:
    payload = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: text/html\r\n\r\n"
    )
    info = analyze_http(payload)
    assert info is not None
    assert info.kind == "request"
    assert info.method == "GET"
    assert info.path == "/index.html"
    assert info.host == "example.com"
    assert "GET" in info.summary()


def test_http_response() -> None:
    payload = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nbody"
    info = analyze_http(payload)
    assert info is not None
    assert info.kind == "response"
    assert info.status == 404
    assert info.summary() == "HTTP 404 HTTP/1.1"


def test_http_rejects_non_http_bytes() -> None:
    assert analyze_http(b"\x16\x03\x01\x02\x00binary") is None
    assert analyze_http(b"FOOBAR /x HTTP/1.1\r\n\r\n") is None
    assert analyze_http(b"") is None


def test_http2_preface_and_frame() -> None:
    frame = b"\x00\x00\x00" + bytes([4]) + b"\x00" + (0).to_bytes(4, "big")
    info = analyze_http2(H2_PREFACE + frame)
    assert info is not None
    assert info.frame_type == "SETTINGS"
    assert info.length == 0
    assert info.stream_id == 0


def test_http2_preface_only() -> None:
    info = analyze_http2(H2_PREFACE)
    assert info is not None
    assert info.frame_type == "(preface)"


def test_http2_rejects_plain_http() -> None:
    assert analyze_http2(b"GET / HTTP/1.1\r\n\r\n") is None


def _quic_initial() -> bytes:
    first = 0xC0  # long header + Initial
    version = (1).to_bytes(4, "big")
    dcid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    payload = bytes([first]) + version + bytes([len(dcid)]) + dcid + bytes([0])
    return payload + b"\x00\x01\x02"


def test_quic_initial_detection() -> None:
    info = analyze_quic(_quic_initial())
    assert info is not None
    assert info.version == "QUIC v1"
    assert info.packet_type == "Initial"
    assert info.dcid_len == 8


def test_quic_rejects_short_or_short_header() -> None:
    assert analyze_quic(b"\x00\x01") is None
    assert analyze_quic(b"\x40" + b"\x00\x00\x00\x01" + b"\x00") is None  # short header


def test_analyzer_extracts_http_on_port_80() -> None:
    http_payload = b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n"
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80) / Raw(http_payload)
    parsed = ParsedPacket(protocol="TCP", src_port=5000, dst_port=80)
    analyze_app_layer(parsed, pkt)
    assert "http" in parsed.info
    assert parsed.info["http"].host == "test.local"


def test_analyzer_extracts_quic_on_udp_443() -> None:
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=443) / Raw(_quic_initial())
    parsed = ParsedPacket(protocol="UDP", src_port=5000, dst_port=443)
    analyze_app_layer(parsed, pkt)
    assert "quic" in parsed.info
    assert parsed.info["quic"].version == "QUIC v1"

"""Application-layer protocol analyzers.

Clean boundary between L2-L4 packet parsing and L7 analysis.  The parser
(``parser.py``) handles Ethernet/IP/TCP/UDP and delegates application-level
inspection here.  Each ``analyze_*`` function accepts raw bytes or parsed
data and returns structured info — or ``None`` if the payload does not match.

This module is deliberately free of Scapy imports: analyzers work on raw
byte buffers so they can be reused on reassembled TCP streams (#12).
"""
from __future__ import annotations

from typing import Any

from netreplay.core.protocols import dns as dns_mod
from netreplay.core.protocols import http as http_mod
from netreplay.core.protocols import tls as tls_mod

_HTTP_PORTS = {80, 8000, 8080, 8888}
_QUIC_PORTS = {443, 80}


# ---------------------------------------------------------------------------
# Per-packet helpers (called from parser.py)
# ---------------------------------------------------------------------------

def analyze_dns_packet(dns_layer: object) -> dns_mod.DNSInfo | None:
    """Analyze DNS from a Scapy ``DNS`` layer object."""
    return dns_mod.analyze(dns_layer)


def analyze_tls_payload(payload: bytes) -> tls_mod.TLSInfo | None:
    """Analyze a single TLS record from raw payload bytes."""
    return tls_mod.analyze(payload)


def analyze_app_layer(parsed: Any, pkt: Any) -> None:
    """Run L7 analyzers on a parsed packet and populate ``parsed.info``.

    ``parsed`` is a :class:`ParsedPacket`, ``pkt`` is a Scapy packet.
    This is the single entry point that parser.py calls after L2-L4 parsing.
    """
    try:
        _analyze_dns(parsed, pkt)
    except Exception:  # noqa: BLE001
        pass
    try:
        _analyze_tls(parsed, pkt)
    except Exception:  # noqa: BLE001
        pass
    try:
        _analyze_http(parsed, pkt)
    except Exception:  # noqa: BLE001
        pass
    try:
        _analyze_quic(parsed, pkt)
    except Exception:  # noqa: BLE001
        pass


def _analyze_dns(parsed: Any, pkt: Any) -> None:
    from scapy.layers.dns import DNS  # noqa: F401 – lazy

    dns_layer = pkt.getlayer(DNS)
    if dns_layer is None:
        return
    info = dns_mod.analyze(dns_layer)
    if info is not None:
        parsed.info["dns"] = info  # type: ignore[union-attr]


def _analyze_tls(parsed: Any, pkt: Any) -> None:
    from scapy.packet import Raw  # noqa: F401 – lazy

    raw_layer = pkt.getlayer(Raw)
    if raw_layer is None:
        return
    payload = bytes(raw_layer.load)
    info = tls_mod.analyze(payload)
    if info is not None:
        parsed.info["tls"] = info  # type: ignore[union-attr]


def _analyze_http(parsed: Any, pkt: Any) -> None:
    """Analyze HTTP/1.x or HTTP/2 on web-ports TCP payloads (#49)."""
    from scapy.packet import Raw  # noqa: F401 – lazy

    ports = {getattr(parsed, "src_port", None), getattr(parsed, "dst_port", None)}
    if not (_HTTP_PORTS & {p for p in ports if p is not None}):
        return
    raw_layer = pkt.getlayer(Raw)
    if raw_layer is None:
        return
    payload = bytes(raw_layer.load)
    h2 = http_mod.analyze_http2(payload)
    if h2 is not None:
        parsed.info["http2"] = h2  # type: ignore[union-attr]
        return
    http = http_mod.analyze_http(payload)
    if http is not None:
        parsed.info["http"] = http  # type: ignore[union-attr]


def _analyze_quic(parsed: Any, pkt: Any) -> None:
    """Detect QUIC over UDP on 443/80 (#49)."""
    from scapy.packet import Raw  # noqa: F401 – lazy

    if (getattr(parsed, "protocol", "") or "").upper() != "UDP":
        return
    ports = {getattr(parsed, "src_port", None), getattr(parsed, "dst_port", None)}
    if not (_QUIC_PORTS & {p for p in ports if p is not None}):
        return
    raw_layer = pkt.getlayer(Raw)
    if raw_layer is None:
        return
    info = http_mod.analyze_quic(bytes(raw_layer.load))
    if info is not None:
        parsed.info["quic"] = info  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Stream-level analysis (operates on reassembled byte streams, #12)
# ---------------------------------------------------------------------------

def analyze_tls_stream(data: bytes) -> list[tls_mod.TLSInfo]:
    """Parse a contiguous byte stream for TLS handshake records.

    Unlike :func:`analyze_tls_payload` which only looks at the first
    record, this walks the stream and returns info for every complete
    handshake message found.  Useful when TLS analysis runs on a
    reassembled TCP stream where records may span multiple segments.
    """
    results: list[tls_mod.TLSInfo] = []
    off = 0
    while off + 5 <= len(data):
        if data[off] != tls_mod.TLS_HANDSHAKE:
            off += 1
            continue
        version_code = int.from_bytes(data[off + 1 : off + 3], "big")
        rec_len = int.from_bytes(data[off + 3 : off + 5], "big")
        body_start = off + 5
        body_end = body_start + rec_len
        if body_end > len(data):
            break  # incomplete record at end of stream
        body = data[body_start:body_end]
        if len(body) >= 4:
            h_msg_type = body[0]
            h_name = tls_mod._HANDSHAKE_TYPES.get(h_msg_type, f"Handshake({h_msg_type})")
            sni = None
            if h_msg_type == 1:
                sni = tls_mod._parse_sni_from_client_hello(body[4:])
            results.append(
                tls_mod.TLSInfo(
                    record_type=tls_mod.TLS_HANDSHAKE,
                    handshake_type=h_msg_type,
                    handshake_name=h_name,
                    version=tls_mod.tls_version_name(version_code),
                    sni=sni,
                )
            )
        off = body_end
    return results

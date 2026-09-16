"""Packet parser built on Scapy.

The parser turns raw packet bytes into a :class:`ParsedPacket` with
normalised metadata and protocol-specific hints (TCP flags, TTL, DNS / TLS
metadata). Scapy is imported lazily to keep module import cheap.

Application-layer analysis (DNS, TLS) is delegated to
:mod:`netreplay.core.protocols.analyzer` which provides a clean boundary
between L2-L4 packet parsing and L7 inspection.
"""
from __future__ import annotations

import logging

from netreplay.core.packets.models import ParsedPacket
from netreplay.core.protocols import analyzer

logger = logging.getLogger(__name__)

_TRANSPORT = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    58: "ICMPv6",
}


def _load_scapy():
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: F401
    from scapy.layers.inet6 import IPv6  # noqa: F401
    from scapy.layers.l2 import ARP, Ether  # noqa: F401
    from scapy.layers.dns import DNS  # noqa: F401
    from scapy.packet import Raw  # noqa: F401

    return locals()


_cache: dict = {}


def _scapy(name):
    if not _cache:
        _cache.update(_load_scapy())
    return _cache[name]


def parse_packet(raw: bytes, ts: float = 0.0) -> ParsedPacket:
    """Parse raw captured bytes into a :class:`ParsedPacket`."""
    Ether = _scapy("Ether")
    try:
        pkt = Ether(raw)
    except Exception:
        logger.debug("Unable to parse frame of %d bytes", len(raw))
        return ParsedPacket(ts=ts, length=len(raw), protocol="UNKNOWN", raw=raw)

    parsed = ParsedPacket(ts=ts, length=len(raw), raw=raw)

    eth_type = getattr(pkt, "type", None)
    dl_src = getattr(pkt, "src", "")
    dl_dst = getattr(pkt, "dst", "")

    if pkt.haslayer(_scapy("IP")):
        l3 = pkt.getlayer(_scapy("IP"))
        parsed.source = l3.src
        parsed.destination = l3.dst
        parsed.ttl = int(getattr(l3, "ttl", 0))
        proto_num = int(getattr(l3, "proto", 0))
        parsed.protocol = _TRANSPORT.get(proto_num, f"IP({proto_num})")
    elif pkt.haslayer(_scapy("IPv6")):
        l3 = pkt.getlayer(_scapy("IPv6"))
        parsed.source = l3.src
        parsed.destination = l3.dst
        next_hdr = int(getattr(l3, "nh", 0))
        parsed.protocol = _TRANSPORT.get(next_hdr, f"IP({next_hdr})")
    elif pkt.haslayer(_scapy("ARP")):
        arp = pkt.getlayer(_scapy("ARP"))
        parsed.source = getattr(arp, "psrc", "") or dl_src
        parsed.destination = getattr(arp, "pdst", "") or dl_dst
        parsed.protocol = "ARP"
    else:
        parsed.source = dl_src
        parsed.destination = dl_dst
        parsed.protocol = f"L2(0x{eth_type:04x})" if eth_type else "L2"

    tcp = pkt.getlayer(_scapy("TCP"))
    udp = pkt.getlayer(_scapy("UDP"))
    if tcp is not None:
        parsed.src_port = int(tcp.sport)
        parsed.dst_port = int(tcp.dport)
        flags_raw = int(tcp.flags)
        parsed.info["tcp_flags"] = flags_raw
        parsed.info["tcp_seq"] = int(tcp.seq)
        parsed.info["tcp_ack"] = int(tcp.ack)
        parsed.info["tcp_window"] = int(tcp.window)
        if flags_raw & 0x02:
            parsed.info["tcp_syn"] = True
        if flags_raw & 0x10:
            parsed.info["tcp_ack_bit"] = True
        if flags_raw & 0x01:
            parsed.info["tcp_fin"] = True
        if flags_raw & 0x04:
            parsed.info["tcp_rst"] = True
    elif udp is not None:
        parsed.src_port = int(udp.sport)
        parsed.dst_port = int(udp.dport)
        is_dns_port = parsed.dst_port == 53 or parsed.src_port == 53
        if is_dns_port and pkt.getlayer(_scapy("DNS")) is not None:
            parsed.protocol = "DNS"
        elif is_dns_port:
            parsed.protocol = "DNS"
        elif pkt.getlayer(_scapy("DNS")) is not None:
            parsed.protocol = "DNS"

    # Delegate L7 analysis (DNS, TLS) to the analyzer module.
    analyzer.analyze_app_layer(parsed, pkt)

    parsed.info["eth_type"] = int(eth_type) if eth_type is not None else None
    return parsed
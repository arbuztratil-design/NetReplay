"""Packet parsing tests: feed crafted Scapy packets through the parser."""
from __future__ import annotations

from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, Raw, TCP, UDP
from scapy.all import IPv6 as IPv6_

from netreplay.core.packets.parser import parse_packet


def _parse(**kwargs):
    pkt = kwargs["pkt"]
    ts = kwargs.get("ts", 1234.5)
    return parse_packet(bytes(pkt), ts=ts)


def test_tcp_ipv4():
    p = _parse(
        pkt=Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")
        / IP(src="192.168.1.5", dst="8.8.8.8", ttl=64)
        / TCP(sport=49152, dport=443, flags="S", seq=1000)
    )
    assert p.source == "192.168.1.5"
    assert p.destination == "8.8.8.8"
    assert p.protocol == "TCP"
    assert p.src_port == 49152
    assert p.dst_port == 443
    assert p.ttl == 64
    assert p.info.get("tcp_syn") is True
    assert p.info.get("tcp_flags") & 0x02
    assert p.ts == 1234.5
    assert p.length > 0


def test_udp():
    p = _parse(
        pkt=Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=12345, dport=9999)
    )
    assert p.protocol == "UDP"
    assert p.src_port == 12345
    assert p.dst_port == 9999


def test_ipv6():
    p = _parse(
        pkt=Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb")
        / IPv6_(src="fe80::1", dst="fe80::2")
        / TCP(sport=1000, dport=2000, flags="A")
    )
    assert p.protocol == "TCP"
    assert p.source == "fe80::1"
    assert p.destination == "fe80::2"


def test_icmp():
    p = _parse(pkt=Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())
    assert p.protocol == "ICMP"


def test_arp():
    p = _parse(
        pkt=Ether()
        / ARP(psrc="10.0.0.1", pdst="10.0.0.2", hwsrc="11:11:11:11:11:11")
    )
    assert p.protocol == "ARP"
    assert p.source == "10.0.0.1"
    assert p.destination == "10.0.0.2"


def test_dns_query():
    p = _parse(
        pkt=Ether()
        / IP(src="192.168.1.5", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(qr=0, qd=DNSQR(qname="example.com", qtype="A"))
    )
    assert p.protocol == "DNS"
    dns = p.info["dns"]
    assert dns.is_query is True
    assert dns.qname == "example.com"
    assert dns.qtype == "A"


def test_dns_response():
    p = _parse(
        pkt=Ether()
        / IP(src="8.8.8.8", dst="192.168.1.5")
        / UDP(sport=53, dport=53000)
        / DNS(
            qr=1,
            rcode=0,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34"),
        )
    )
    dns = p.info["dns"]
    assert dns.is_query is False
    assert dns.rcode == 0
    assert "93.184.216.34" in dns.answers
    assert "example.com" in dns.summary()


def test_tls_client_hello():
    from netreplay.core.protocols.tls import analyze

    hello = _build_client_hello(sni="example.org")
    info = analyze(hello)
    assert info is not None
    assert info.handshake_name == "ClientHello"
    assert info.handshake_type == 1
    assert info.version == "TLS 1.2"
    assert info.sni == "example.org"


def test_tls_non_tls_payload_is_none():
    from netreplay.core.protocols.tls import analyze

    assert analyze(b"\x00\x01\x02\x03") is None
    assert analyze(b"") is None


def test_tls_detected_through_parser():
    hello = _build_client_hello(sni="chat.example")
    p = _parse(
        pkt=Ether()
        / IP(src="192.168.1.5", dst="142.250.0.1")
        / TCP(sport=49152, dport=443, flags="PA")
        / Raw(hello)
    )
    tls = p.info.get("tls")
    assert tls is not None
    assert tls.handshake_name == "ClientHello"
    assert tls.sni == "chat.example"


def test_garbage_bytes():
    p = parse_packet(b"\x00\x01\x02\x03\x04", ts=1.0)
    assert p.protocol == "UNKNOWN"
    assert p.length == 5


def _build_client_hello(sni: str) -> bytes:
    """Manually assemble a TLS 1.2 ClientHello with an SNI extension."""
    session_id = b"\x00" * 32
    cipher_suites = bytes.fromhex("1301 1302 c02b c02f".replace(" ", ""))
    compression = b"\x01\x00"
    legacy_version = bytes.fromhex("0303")
    random = bytes(range(32))

    server_name_list = b"\x00" + len(sni).to_bytes(2, "big") + sni.encode()
    ext_data = len(server_name_list).to_bytes(2, "big") + server_name_list
    extension_block = (
        (0).to_bytes(2, "big") + len(ext_data).to_bytes(2, "big") + ext_data
    )
    extensions = len(extension_block).to_bytes(2, "big") + extension_block

    body = (
        legacy_version
        + random
        + bytes([len(session_id)])
        + session_id
        + (len(cipher_suites)).to_bytes(2, "big")
        + cipher_suites
        + compression
        + extensions
    )

    handshake = bytes([1]) + len(body).to_bytes(3, "big") + body
    record = bytes([0x16]) + bytes.fromhex("0303") + len(handshake).to_bytes(2, "big")
    return record + handshake
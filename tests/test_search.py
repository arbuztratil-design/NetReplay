"""Search and similarity: domains, IPs, and workspace ranking."""
from __future__ import annotations

import time

import pytest
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw

from netreplay.core.capture.base import CaptureBackend
from netreplay.core.packets.models import CapturedPacket
from netreplay.core.search import (
    fingerprint,
    search_session,
    similar_sessions,
    similarity,
)
from netreplay.core.service import CaptureController
from netreplay.core.storage import open_session


class FakeBackend(CaptureBackend):
    def __init__(self, interface, packets):
        super().__init__(interface)
        self._packets = list(packets)
        self._running = False

    @property
    def running(self):
        return self._running

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def packets(self):
        yield from self._packets
        self._running = False


def _build_session(tmp_path, filename, packets):
    output = tmp_path / filename
    controller = CaptureController(
        interface="fake0",
        output=output,
        backend=FakeBackend("fake0", packets),
    )
    controller.start()
    deadline = time.time() + 15
    while controller.status().running and time.time() < deadline:
        time.sleep(0.02)
    controller.stop(timeout=5)
    return output


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


def _browser_packets(
    client: str = "192.168.1.5",
    server: str = "10.0.0.8",
    domain: str = "example.com",
    sni: str = "shop.example.net",
    dns_ip: str = "8.8.8.8",
):
    """TCP handshake + TLS ClientHello + DNS query/response for one domain."""
    pkts = []
    ts = 100.0
    pairs = [
        (TCP(sport=49152, dport=443, flags="S"), client, server),
        (TCP(sport=443, dport=49152, flags="SA"), server, client),
        (TCP(sport=49152, dport=443, flags="A"), client, server),
    ]
    for layer, src, dst in pairs:
        pkt = Ether() / IP(src=src, dst=dst) / layer
        pkts.append(CapturedPacket(ts=ts, data=bytes(pkt)))
        ts += 0.05
    hello = (
        Ether()
        / IP(src=client, dst=server)
        / TCP(sport=49152, dport=443, flags="PA")
        / Raw(_build_client_hello(sni))
    )
    pkts.append(CapturedPacket(ts=ts, data=bytes(hello)))
    ts += 0.05
    query = (
        Ether()
        / IP(src=client, dst=dns_ip)
        / UDP(sport=53000, dport=53)
        / DNS(qr=0, qd=DNSQR(qname=domain, qtype="A"))
    )
    pkts.append(CapturedPacket(ts=ts, data=bytes(query)))
    ts += 0.02
    response = (
        Ether()
        / IP(src=dns_ip, dst=client)
        / UDP(sport=53, dport=53000)
        / DNS(
            qr=1,
            qd=DNSQR(qname=domain, qtype="A"),
            an=DNSRR(rrname=domain, rdata=server, type="A"),
        )
    )
    pkts.append(CapturedPacket(ts=ts, data=bytes(response)))
    return pkts


def test_search_by_domain(tmp_path):
    path = _build_session(tmp_path, "a.nrp", _browser_packets())
    result = search_session(open_session(path), "example.com")
    assert result.query == "example.com"
    assert result.flows == []
    assert result.packets == []
    summaries = [e.summary for e in result.events]
    assert any(s.startswith("DNS QUERY example.com") for s in summaries)
    assert any(s.startswith("DNS RESPONSE example.com") for s in summaries)
    assert any(("DNS" in s and "answers=10.0.0.8" in s) for s in summaries)

    sni = search_session(open_session(path), "shop.example.net")
    assert any("sni=shop.example.net" in e.summary for e in sni.events)


def test_search_by_ip(tmp_path):
    path = _build_session(tmp_path, "a.nrp", _browser_packets())
    result = search_session(open_session(path), "10.0.0.8")
    assert result.total > 0
    assert any(f.source == "10.0.0.8" or f.destination == "10.0.0.8" for f in result.flows)
    assert any(p.source == "10.0.0.8" or p.destination == "10.0.0.8" for p in result.packets)
    assert any("answers=10.0.0.8" in e.summary for e in result.events)


def test_search_no_matches(tmp_path):
    path = _build_session(tmp_path, "a.nrp", _browser_packets())
    result = search_session(open_session(path), "not.here.example")
    assert result.total == 0


def test_fingerprint_domains_ips_ports(tmp_path):
    path = _build_session(tmp_path, "a.nrp", _browser_packets())
    fp = fingerprint(open_session(path))
    assert fp.domains["example.com"] >= 1
    assert fp.domains["shop.example.net"] >= 1
    assert fp.ips["192.168.1.5"] >= 1
    assert fp.ips["10.0.0.8"] >= 1
    assert fp.ips["8.8.8.8"] >= 1
    assert fp.ports.get("TCP:443") == 1
    assert fp.ports.get("DNS:53") == 1


def test_similarity_self_is_one(tmp_path):
    path = _build_session(tmp_path, "a.nrp", _browser_packets())
    fp = fingerprint(open_session(path))
    assert similarity(fp, fingerprint(open_session(path))) == pytest.approx(1.0)


def test_similar_sessions_rank(tmp_path):
    a = _build_session(tmp_path, "a.nrp", _browser_packets())
    b = _build_session(
        tmp_path,
        "b.nrp",
        _browser_packets(client="192.168.1.5", server="10.0.0.8", domain="example.com"),
    )
    c = _build_session(
        tmp_path,
        "c.nrp",
        _browser_packets(
            client="172.16.0.9",
            server="1.2.3.4",
            domain="unrelated.net",
            sni="total.other.net",
            dns_ip="9.9.9.9",
        ),
    )
    with open_session(a) as sa:
        target_id = sa.meta("session_id")
    with open_session(b) as sb:
        b_id = sb.meta("session_id")
    with open_session(c) as sc:
        c_id = sc.meta("session_id")

    found = similar_sessions(a, workspace=tmp_path)
    ids = [s.session_id for s in found]
    assert target_id not in ids
    assert found[0].session_id == b_id
    assert found[0].score > 0.9
    assert b_id in ids
    assert c_id not in found or ids.index(c_id) > ids.index(b_id)
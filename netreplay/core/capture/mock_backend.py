"""Deterministic synthetic packet source for demos and tests.

Produces a small conversation story (ARP, DNS + TCP/TLS handshake towards a
resolvable-looking host, an HTTP exchange) as real Ethernet frames, so the
whole NetReplay pipeline (parser -> flows -> timeline -> storage) runs without
Npcap and without a stored PCAP file.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Iterator

from netreplay.core.capture.base import CaptureBackend
from netreplay.core.packets.models import CapturedPacket

_CLIENT_MAC = "00:11:22:33:44:55"
_SERVER_MAC = "66:77:88:99:aa:bb"
_CLIENT_IP = "192.168.1.10"
_GATEWAY_IP = "192.168.1.1"
_DNS_IP = "8.8.8.8"
_WEB_IP = "93.184.216.34"  # example.com
_TLS_VERSION = 0x0303


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def _tls_client_hello(sni: str) -> bytes:
    """A minimal but well-formed TLS ClientHello record with an SNI extension."""
    name = sni.encode("ascii", errors="replace")
    name_entry = b"\x00" + _u16(len(name)) + name
    ext_payload = _u16(len(name_entry)) + name_entry  # name_list_len + names
    sni_ext = _u16(0x0000) + _u16(len(ext_payload)) + ext_payload
    body = bytearray()
    body += _u16(_TLS_VERSION)
    body += bytes(range(32))  # deterministic client random
    body += b"\x00"  # no session id
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02F, 0xC02B]
    body += _u16(len(ciphers) * 2)
    for cipher in ciphers:
        body += _u16(cipher)
    body += b"\x01\x00"  # one compression method: null
    body += _u16(len(sni_ext)) + sni_ext
    hello = b"\x01" + _u24(len(body)) + bytes(body)  # handshake: ClientHello
    return b"\x16" + _u16(0x0301) + _u16(len(hello)) + hello


def _build_scenes() -> list[CapturedPacket]:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw

    scenes: list[CapturedPacket] = []

    def scene(pkt) -> None:
        scenes.append(CapturedPacket(ts=0.0, data=bytes(pkt)))

    # ARP who-has -> reply
    scene(Ether(src=_CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
          / ARP(op=1, hwsrc=_CLIENT_MAC, psrc=_CLIENT_IP, pdst=_GATEWAY_IP))
    scene(Ether(src="aa:bb:cc:dd:ee:ff", dst=_CLIENT_MAC)
          / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc=_GATEWAY_IP, hwdst=_CLIENT_MAC, pdst=_CLIENT_IP))

    # DNS query + response for example.com
    scene(Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
          / IP(src=_CLIENT_IP, dst=_DNS_IP) / UDP(sport=53000, dport=53)
          / DNS(qr=0, qd=DNSQR(qname="example.com", qtype="A")))
    scene(Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
          / IP(src=_DNS_IP, dst=_CLIENT_IP) / UDP(sport=53, dport=53000)
          / DNS(qr=1, qd=DNSQR(qname="example.com", qtype="A"),
                an=DNSRR(rrname="example.com", rdata=_WEB_IP)))

    # TCP/TLS handshake to example.com:443
    sport = 49152
    for flags in ("S", "SA", "A"):
        scene(Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
              / IP(src=_CLIENT_IP, dst=_WEB_IP) / TCP(sport=sport, dport=443, flags=flags))
    # TLS ClientHello on the established connection
    scene(Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
          / IP(src=_CLIENT_IP, dst=_WEB_IP) / TCP(sport=sport, dport=443, flags="PA")
          / Raw(load=_tls_client_hello("example.com")))
    scene(Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
          / IP(src=_WEB_IP, dst=_CLIENT_IP) / TCP(sport=443, dport=sport, flags="A"))
    # teardown
    scene(Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
          / IP(src=_CLIENT_IP, dst=_WEB_IP) / TCP(sport=sport, dport=443, flags="FA"))
    scene(Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
          / IP(src=_WEB_IP, dst=_CLIENT_IP) / TCP(sport=443, dport=sport, flags="A"))

    # Plain HTTP exchange to example.com:80
    scene(Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
          / IP(src=_CLIENT_IP, dst=_WEB_IP) / TCP(sport=sport + 1, dport=80, flags="S"))
    scene(Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
          / IP(src=_WEB_IP, dst=_CLIENT_IP) / TCP(sport=80, dport=sport + 1, flags="SA"))
    scene(Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
          / IP(src=_CLIENT_IP, dst=_WEB_IP) / TCP(sport=sport + 1, dport=80, flags="A"))
    scene(Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
          / IP(src=_CLIENT_IP, dst=_WEB_IP) / TCP(sport=sport + 1, dport=80, flags="PA")
          / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
    scene(Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
          / IP(src=_WEB_IP, dst=_CLIENT_IP) / TCP(sport=80, dport=sport + 1, flags="A"))
    scene(Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
          / IP(src=_CLIENT_IP, dst=_WEB_IP) / TCP(sport=sport + 1, dport=80, flags="FA"))
    scene(Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
          / IP(src=_WEB_IP, dst=_CLIENT_IP) / TCP(sport=80, dport=sport + 1, flags="A"))

    return scenes


_CONVERSATION: list[CapturedPacket] = _build_scenes()


class MockBackend(CaptureBackend):
    """Emit a deterministic synthetic conversation, optionally paced.

    ``packets`` limits the total number of emitted frames (0 = until stopped);
    ``rate`` paces emission in packets per second (0 = as fast as possible).
    """

    def __init__(
        self,
        interface: str = "mock",
        packets: int = 0,
        rate: float = 0.0,
    ) -> None:
        super().__init__(interface)
        self.packets_limit = packets
        self.rate = rate
        self._running = threading.Event()

    @property
    def running(self) -> bool:
        return self._running.is_set()

    def start(self) -> None:
        self._running.set()

    def stop(self) -> None:
        self._running.clear()

    def packets(self) -> Iterator[CapturedPacket]:
        gap = 1.0 / self.rate if self.rate > 0 else 0.02
        base = time.time()
        emitted = 0
        try:
            while self._running.is_set():
                if self.packets_limit and emitted >= self.packets_limit:
                    break
                for scene in _CONVERSATION:
                    if not self._running.is_set():
                        return
                    if self.packets_limit and emitted >= self.packets_limit:
                        return
                    packet = CapturedPacket(ts=base + emitted * gap, data=scene.data)
                    yield packet
                    emitted += 1
                    if self.rate > 0:
                        time.sleep(max(0.0, gap - 0.002))
        finally:
            self._running.clear()
"""P1 #35: IP/MAC/port remapping of raw frames (checksums kept valid)."""
from __future__ import annotations

import pytest

pytest.importorskip("scapy")

from scapy.all import IP, TCP, UDP, Ether  # noqa: E402

from netreplay.core.replay.remap import (  # noqa: E402
    MacAddress,
    RemapConfig,
    _checksum,
    remap_frame,
)


def _tcp_frame() -> bytes:
    return bytes(
        Ether(src="aa:aa:aa:aa:aa:01", dst="bb:bb:bb:bb:bb:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
        / TCP(sport=5000, dport=443, flags="S", seq=1000)
        / b"hello"
    )


def _udp_frame() -> bytes:
    return bytes(
        Ether(src="aa:aa:aa:aa:aa:01", dst="bb:bb:bb:bb:bb:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
        / UDP(sport=5000, dport=53)
        / b"query"
    )


def test_config_parses_addresses() -> None:
    cfg = RemapConfig.build(
        mac_map={"aa:aa:aa:aa:aa:01": "cc:cc:cc:cc:cc:03"},
        ip_map={"10.0.0.1": "192.168.1.1"},
        port_map={443: 8443},
    )
    assert MacAddress.parse("cc:cc:cc:cc:cc:03").raw in cfg.mac_map.values()
    assert not cfg.is_empty


def test_config_rejects_bad_addresses() -> None:
    with pytest.raises(ValueError):
        RemapConfig.build(mac_map={"x": "not-a-mac"})
    with pytest.raises(ValueError):
        RemapConfig.build(ip_map={"999.1.1.1": "10.0.0.1"})
    with pytest.raises(ValueError):
        RemapConfig.build(port_map={443: 99999})


def test_remap_mac_ips_and_ports() -> None:
    cfg = RemapConfig.build(
        mac_map={"aa:aa:aa:aa:aa:01": "cc:cc:cc:cc:cc:03",
                 "bb:bb:bb:bb:bb:02": "dd:dd:dd:dd:dd:04"},
        ip_map={"10.0.0.1": "192.168.1.1", "10.0.0.2": "192.168.1.2"},
        port_map={443: 8443, 5000: 6000},
    )
    out = remap_frame(_tcp_frame(), cfg)
    ip = IP(out[14:])
    tcp = ip[TCP]
    assert ip.src == "192.168.1.1"
    assert ip.dst == "192.168.1.2"
    assert tcp.sport == 6000
    assert tcp.dport == 8443
    assert out[0:6] == bytes.fromhex("dddddddddd04")
    assert out[6:12] == bytes.fromhex("cccccccccc03")


def test_remap_ipv4_checksum_stays_valid() -> None:
    cfg = RemapConfig.build(ip_map={"10.0.0.1": "172.16.0.9"})
    out = remap_frame(_tcp_frame(), cfg)
    ihl = (out[14] & 0x0F) * 4
    stored = int.from_bytes(out[24:26], "big")
    header = bytearray(out[14 : 14 + ihl])
    header[10:12] = b"\x00\x00"
    assert stored == _checksum(bytes(header))


def test_remap_tcp_checksum_stays_valid() -> None:
    cfg = RemapConfig.build(ip_map={"10.0.0.1": "172.16.0.9"}, port_map={443: 8443})
    out = remap_frame(_tcp_frame(), cfg)
    ihl = (out[14] & 0x0F) * 4
    base = 14 + ihl
    total_length = int.from_bytes(out[16:18], "big")
    transport_length = total_length - ihl
    stored = int.from_bytes(out[base + 16 : base + 18], "big")
    segment = bytearray(out[base : base + transport_length])
    segment[16:18] = b"\x00\x00"
    pseudo = (
        out[26:30] + out[30:34] + b"\x00" + bytes([6])
        + transport_length.to_bytes(2, "big")
    )
    assert stored == _checksum(pseudo + bytes(segment))


def test_remap_udp_checksum_stays_valid() -> None:
    cfg = RemapConfig.build(ip_map={"10.0.0.2": "192.168.1.2"}, port_map={53: 5353})
    out = remap_frame(_udp_frame(), cfg)
    ihl = (out[14] & 0x0F) * 4
    base = 14 + ihl
    transport_length = len(out) - base
    stored = int.from_bytes(out[base + 6 : base + 8], "big")
    assert stored != 0
    segment = bytearray(out[base : base + transport_length])
    segment[6:8] = b"\x00\x00"
    pseudo = (
        out[26:30] + out[30:34] + b"\x00" + bytes([17])
        + transport_length.to_bytes(2, "big")
    )
    assert stored == _checksum(pseudo + bytes(segment))


def test_remap_leaves_non_ipv4_untouched() -> None:
    frame = bytes(Ether(src="aa:aa:aa:aa:aa:01", dst="bb:bb:bb:bb:bb:02") / b"\x88\xb5payload")
    cfg = RemapConfig.build(ip_map={"10.0.0.1": "192.168.1.1"})
    assert remap_frame(frame, cfg) == frame


def test_remap_empty_config_is_noop() -> None:
    frame = _tcp_frame()
    assert remap_frame(frame, RemapConfig()) == frame

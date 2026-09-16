"""IP / MAC / port remapping (#35): replay into a different network.

Rewrites addresses and ports inside raw Ethernet/IPv4/TCP/UDP frames and
recomputes the affected checksums, so a capture recorded in one network can be
replayed into a lab network with different addressing.

Only Ethernet + IPv4 (TCP/UDP) frames are rewritten; anything else is returned
untouched. IP fragments are re-addressed but their transport checksum is left
alone (it can only be validated after reassembly).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

_ETHERTYPE_IPV4 = 0x0800
_IPPROTO_TCP = 6
_IPPROTO_UDP = 17


@dataclass(frozen=True, slots=True)
class MacAddress:
    raw: bytes

    @classmethod
    def parse(cls, text: str) -> MacAddress:
        parts = text.strip().lower().replace("-", ":").split(":")
        if len(parts) != 6:
            raise ValueError(f"invalid MAC address: {text!r}")
        try:
            return cls(bytes(int(p, 16) for p in parts))
        except ValueError as exc:
            raise ValueError(f"invalid MAC address: {text!r}") from exc

    def __str__(self) -> str:  # pragma: no cover - debug aid
        return ":".join(f"{b:02x}" for b in self.raw)


@dataclass(frozen=True, slots=True)
class Ipv4Address:
    raw: bytes

    @classmethod
    def parse(cls, text: str) -> Ipv4Address:
        try:
            return cls(struct.pack("!I", struct.unpack("!I", bytes(int(p) for p in text.split(".")))[0]))
        except (ValueError, struct.error) as exc:
            raise ValueError(f"invalid IPv4 address: {text!r}") from exc

    def __str__(self) -> str:  # pragma: no cover - debug aid
        return ".".join(str(b) for b in self.raw)


@dataclass(frozen=True, slots=True)
class RemapConfig:
    mac_map: dict[bytes, bytes] = field(default_factory=dict)
    ip_map: dict[bytes, bytes] = field(default_factory=dict)
    port_map: dict[int, int] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        mac_map: dict[str, str] | None = None,
        ip_map: dict[str, str] | None = None,
        port_map: dict[int, int] | None = None,
    ) -> RemapConfig:
        macs = {
            MacAddress.parse(k).raw: MacAddress.parse(v).raw
            for k, v in (mac_map or {}).items()
        }
        ips = {
            Ipv4Address.parse(k).raw: Ipv4Address.parse(v).raw
            for k, v in (ip_map or {}).items()
        }
        ports = {int(k): int(v) for k, v in (port_map or {}).items()}
        for new_port in ports.values():
            if not 0 <= new_port <= 65535:
                raise ValueError(f"port out of range: {new_port}")
        return cls(mac_map=macs, ip_map=ips, port_map=ports)

    @property
    def is_empty(self) -> bool:
        return not (self.mac_map or self.ip_map or self.port_map)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac_of(raw: bytes, offset: int) -> bytes:
    return raw[offset : offset + 6]


def remap_frame(raw: bytes, config: RemapConfig) -> bytes:
    """Return *raw* with MAC/IP/port fields remapped and checksums fixed."""
    if config.is_empty or len(raw) < 14:
        return raw
    buf = bytearray(raw)

    if config.mac_map:
        dst = _mac_of(raw, 0)
        src = _mac_of(raw, 6)
        if dst in config.mac_map:
            buf[0:6] = config.mac_map[dst]
        if src in config.mac_map:
            buf[6:12] = config.mac_map[src]

    ethertype = int.from_bytes(raw[12:14], "big")
    if ethertype != _ETHERTYPE_IPV4 or len(raw) < 34:
        return bytes(buf)

    ihl = (raw[14] & 0x0F) * 4
    if ihl < 20 or len(raw) < 14 + ihl:
        return bytes(buf)
    protocol = raw[23]
    total_length = int.from_bytes(raw[16:18], "big")
    fragment_offset = int.from_bytes(raw[20:22], "big") & 0x1FFF

    ip_changed = False
    if config.ip_map:
        src_ip = raw[26:30]
        dst_ip = raw[30:34]
        if src_ip in config.ip_map:
            buf[26:30] = config.ip_map[src_ip]
            ip_changed = True
        if dst_ip in config.ip_map:
            buf[30:34] = config.ip_map[dst_ip]
            ip_changed = True

    transport_offsets = _port_offsets(raw, ihl, protocol)
    ports_changed = False
    if config.port_map and transport_offsets is not None:
        for port_offset in transport_offsets:
            port = int.from_bytes(raw[port_offset : port_offset + 2], "big")
            if port in config.port_map:
                buf[port_offset : port_offset + 2] = config.port_map[port].to_bytes(2, "big")
                ports_changed = True

    if ip_changed:
        buf[24:26] = b"\x00\x00"
        buf[24:26] = _checksum(bytes(buf[14 : 14 + ihl])).to_bytes(2, "big")

    if (ip_changed or ports_changed) and fragment_offset == 0 and transport_offsets is not None:
        _fix_transport_checksum(buf, raw, ihl, protocol, total_length)

    return bytes(buf)


def _port_offsets(raw: bytes, ihl: int, protocol: int) -> tuple[int, int] | None:
    if protocol in (_IPPROTO_TCP, _IPPROTO_UDP):
        base = 14 + ihl
        if len(raw) >= base + 4:
            return (base, base + 2)
    return None


def _fix_transport_checksum(
    buf: bytearray, raw: bytes, ihl: int, protocol: int, total_length: int
) -> None:
    base = 14 + ihl
    transport_length = max(0, total_length - ihl)
    if transport_length < 4 or len(raw) < base + transport_length:
        transport_length = len(buf) - base
    if protocol == _IPPROTO_UDP:
        checksum_offset = base + 6
        original = int.from_bytes(raw[checksum_offset : checksum_offset + 2], "big")
        if original == 0:
            return  # checksum disabled by sender
        length_offset = base + 4
        buf[length_offset : length_offset + 2] = transport_length.to_bytes(2, "big")
    elif protocol == _IPPROTO_TCP:
        checksum_offset = base + 16
    else:
        return

    if len(buf) < checksum_offset + 2:
        return
    buf[checksum_offset : checksum_offset + 2] = b"\x00\x00"
    pseudo = (
        bytes(buf[26:30])
        + bytes(buf[30:34])
        + b"\x00"
        + bytes([protocol])
        + transport_length.to_bytes(2, "big")
    )
    segment = pseudo + bytes(buf[base : base + transport_length])
    buf[checksum_offset : checksum_offset + 2] = _checksum(segment).to_bytes(2, "big")

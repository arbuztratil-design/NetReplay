"""Replay validation (#37): check frames before they hit the wire.

A capture can contain malformed or truncated frames; replaying them wastes
bandwidth or confuses the peer. :func:`validate_frame` performs structural
checks (Ethernet/IPv4 length/version, transport header presence) and can
optionally verify the IPv4 header checksum.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

_ETHERTYPE_IPV4 = 0x0800
_IPPROTO_TCP = 6
_IPPROTO_UDP = 17


@dataclass(slots=True)
class ValidationResult:
    valid: bool = True
    issues: list[str] = field(default_factory=list)

    def add(self, issue: str) -> None:
        self.valid = False
        self.issues.append(issue)


def _ipv4_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def validate_frame(raw: bytes, *, verify_checksums: bool = False) -> ValidationResult:
    """Validate one raw Ethernet frame; never raises."""
    result = ValidationResult()
    if len(raw) < 14:
        result.add("frame shorter than Ethernet header")
        return result

    ethertype = int.from_bytes(raw[12:14], "big")
    if ethertype != _ETHERTYPE_IPV4:
        return result  # non-IPv4: structurally fine for our purposes

    if len(raw) < 34:
        result.add("truncated IPv4 header")
        return result

    version = raw[14] >> 4
    if version != 4:
        result.add(f"unexpected IPv4 version {version}")
    ihl = (raw[14] & 0x0F) * 4
    if ihl < 20:
        result.add(f"invalid IPv4 IHL {ihl}")
        return result
    if len(raw) < 14 + ihl:
        result.add("truncated IPv4 options")
        return result

    total_length = int.from_bytes(raw[16:18], "big")
    if total_length < ihl:
        result.add("IPv4 total length smaller than header")
    elif 14 + total_length > len(raw):
        result.add("frame shorter than IPv4 total length")

    protocol = raw[23]
    if protocol in (_IPPROTO_TCP, _IPPROTO_UDP):
        if total_length < ihl + 4:
            result.add("transport header truncated")
        if verify_checksums and protocol == _IPPROTO_TCP:
            header = bytearray(raw[14 : 14 + ihl])
            stored = int.from_bytes(header[10:12], "big")
            header[10:12] = b"\x00\x00"
            if _ipv4_checksum(bytes(header)) != stored:
                result.add("IPv4 header checksum mismatch")
    elif verify_checksums and protocol:
        header = bytearray(raw[14 : 14 + ihl])
        stored = int.from_bytes(header[10:12], "big")
        header[10:12] = b"\x00\x00"
        if _ipv4_checksum(bytes(header)) != stored:
            result.add("IPv4 header checksum mismatch")
    return result


def validate_frames(
    frames: Iterable[bytes], *, verify_checksums: bool = False
) -> list[ValidationResult]:
    return [validate_frame(f, verify_checksums=verify_checksums) for f in frames]

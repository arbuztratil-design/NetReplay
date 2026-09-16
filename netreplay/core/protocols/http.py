"""HTTP/1.x, HTTP/2 and QUIC analyzers (#49).

These parsers work on raw payload bytes (no Scapy dependency) so they can run
both on individual packets and on reassembled TCP streams:

* :func:`analyze_http` recognizes HTTP/1.x request/response start lines and
  extracts the method/path/status, ``Host`` and ``Content-Type``.
* :func:`analyze_http2` recognizes the HTTP/2 client connection preface and
  decodes the first frame header.
* :func:`analyze_quic` recognizes QUIC long-header packets and decodes the
  version (e.g. QUIC v1) and packet type.

They are deliberately conservative: anything that does not clearly match
returns ``None`` rather than guessing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_HTTP_METHODS = (
    b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS",
    b"PATCH", b"TRACE", b"CONNECT",
)

_HTTP2_FRAME_TYPES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
    5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE",
    9: "CONTINUATION",
}

_QUIC_VERSIONS = {
    0x00000001: "QUIC v1",
    0x6B3343CF: "QUIC v2",
    0xFF00001D: "draft-29",
}

_QUIC_PACKET_TYPES = {
    0x00: "Initial",
    0x01: "0-RTT",
    0x02: "Handshake",
    0x03: "Retry",
}


@dataclass(slots=True)
class HTTPInfo:
    kind: str  # "request" | "response"
    method: str = ""
    path: str = ""
    status: int = 0
    version: str = ""
    host: str = ""
    content_type: str = ""

    def summary(self) -> str:
        if self.kind == "request":
            target = self.host or self.path
            return f"HTTP {self.method} {target} {self.version}".strip()
        return f"HTTP {self.status} {self.version}".strip()


@dataclass(slots=True)
class HTTP2Info:
    frame_type: str
    length: int
    flags: int
    stream_id: int
    preface: bool = True

    def summary(self) -> str:
        return f"HTTP/2 {self.frame_type} stream={self.stream_id} len={self.length}"


@dataclass(slots=True)
class QUICInfo:
    version: str
    packet_type: str
    dcid_len: int = 0
    scid_len: int = 0

    def summary(self) -> str:
        return f"{self.version} {self.packet_type}"


def _header_value(headers: dict[str, str], name: str) -> str:
    return headers.get(name.lower(), "")


def analyze_http(payload: bytes) -> HTTPInfo | None:
    """Parse an HTTP/1.x request or response from the start of *payload*."""
    if not payload:
        return None
    head = payload.split(b"\r\n\r\n", 1)[0]
    if not head:
        return None
    lines = head.split(b"\r\n")
    start = lines[0]
    if b" " not in start:
        return None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, _, value = line.partition(b":")
        headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()

    if start.startswith(b"HTTP/"):
        parts = start.split(b" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        return HTTPInfo(
            kind="response",
            status=int(parts[1]),
            version=parts[0].decode("latin-1", "replace"),
            content_type=_header_value(headers, "content-type"),
        )

    method = start.split(b" ", 1)[0]
    if method not in _HTTP_METHODS:
        return None
    parts = start.split(b" ", 2)
    path = parts[1].decode("latin-1", "replace") if len(parts) > 1 else "/"
    version = parts[2].decode("latin-1", "replace") if len(parts) > 2 else "HTTP/1.0"
    if not version.startswith("HTTP/"):
        return None
    return HTTPInfo(
        kind="request",
        method=method.decode("ascii"),
        path=path,
        version=version,
        host=_header_value(headers, "host"),
        content_type=_header_value(headers, "content-type"),
    )


def analyze_http2(payload: bytes) -> HTTP2Info | None:
    """Detect the HTTP/2 preface and decode the following frame header."""
    if not payload.startswith(H2_PREFACE):
        return None
    rest = payload[len(H2_PREFACE):]
    if len(rest) < 9:
        return HTTP2Info(frame_type="(preface)", length=0, flags=0, stream_id=0)
    length = int.from_bytes(rest[0:3], "big")
    frame_type = rest[3]
    flags = rest[4]
    stream_id = int.from_bytes(rest[5:9], "big") & 0x7FFFFFFF
    return HTTP2Info(
        frame_type=_HTTP2_FRAME_TYPES.get(frame_type, f"TYPE({frame_type})"),
        length=length,
        flags=flags,
        stream_id=stream_id,
    )


def analyze_quic(payload: bytes) -> QUICInfo | None:
    """Detect a QUIC long-header packet and decode version + type."""
    if len(payload) < 7:
        return None
    first = payload[0]
    if not (first & 0x80):  # long header form required
        return None
    version = int.from_bytes(payload[1:5], "big")
    if version == 0:
        return None  # version negotiation packet; not a session we describe
    dcid_len = payload[5]
    offset = 6 + dcid_len
    if offset >= len(payload):
        return None
    scid_len = payload[offset]
    packet_type = _QUIC_PACKET_TYPES.get((first & 0x30) >> 4, "Unknown")
    name = _QUIC_VERSIONS.get(version)
    if name is None:
        name = f"QUIC 0x{version:08x}"
    return QUICInfo(version=name, packet_type=packet_type, dcid_len=dcid_len, scid_len=scid_len)

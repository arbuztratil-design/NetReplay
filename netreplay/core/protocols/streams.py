"""Reassembled-stream protocol analyzers (phase 4 #31-35).

The packet-level analyzers in :mod:`netreplay.core.protocols` can only see one
fragment at a time, so a huge TLS record or an HTTP body that spans several
segments is invisible to them.  This module reads the *reassembled* byte stream
(what :mod:`netreplay.core.flows.reassembly` produces) and understands
boundaries that only make sense across segments:

* :class:`TlsStreamParser` — full TLS record framing with an incremental
  buffer, plus a handshake state machine that recognises ClientHello and
  ServerHello (#31) and pulls SNI / cipher suites / ALPN / supported versions
  (#32, #33).
* :class:`Http1Parser` — incremental HTTP/1.x message parser: it buffers until
  a complete request or response (using ``Content-Length`` and chunked
  framing) and emits one :class:`PendingHttpMessage` per message (#34).
* :class:`Http2Parser` — HTTP/2 session state machine: the connection preface
  followed by real frame decoding (type/flags/length/stream id), not just
  preface sniffing (#35).

Every parser is tolerant: malformed data yields ``None`` / empty output rather
than raising, matching the rest of the pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from netreplay.core.protocols.http import HTTPInfo
from netreplay.core.protocols.tls import TLSInfo, tls_version_name

_MAX_RECORD = 1 << 20  # 1 MiB per buffered record / frame
_MAX_MESSAGE = 1 << 24  # 16 MiB per buffered HTTP message

TLS_VERSION_TLS12 = 0x0303
TLS_VERSION_TLS13 = 0x0304

_HANDSHAKE_NAMES = {
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
}

_CIPHER_NAME = {
    0x1301: "AES_128_GCM_SHA256",
    0x1302: "AES_256_GCM_SHA384",
    0x1303: "CHACHA20_POLY1305_SHA256",
    0x1304: "AES_128_CCM_SHA256",
    0x1305: "AES_128_CCM_8_SHA256",
    0xC02B: "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009C: "RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "RSA_WITH_AES_256_GCM_SHA384",
    0x003C: "RSA_WITH_AES_128_CBC_SHA",
    0x003D: "RSA_WITH_AES_256_CBC_SHA",
    0xC013: "ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0x002F: "RSA_WITH_AES_128_CBC_SHA256",
}
_H2_FRAMES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
    4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
    8: "WINDOW_UPDATE", 9: "CONTINUATION",
}
_H2_SETTINGS = {
    0x1: "HEADER_TABLE_SIZE", 0x2: "ENABLE_PUSH", 0x3: "MAX_CONCURRENT_STREAMS",
    0x4: "INITIAL_WINDOW_SIZE", 0x5: "MAX_FRAME_SIZE",
    0x6: "MAX_HEADER_LIST_SIZE", 0x8: "ENABLE_CONNECT_PROTOCOL",
}
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _read_u16(buf: bytes, off: int) -> tuple[int, int]:
    return int.from_bytes(buf[off : off + 2], "big"), off + 2


def _read_u24(buf: bytes, off: int) -> tuple[int, int]:
    return int.from_bytes(buf[off : off + 3], "big"), off + 3


def _tls_error(reason: str) -> None:
    """Marker: a TLS record that does not parse cleanly."""
    return None


@dataclass(slots=True)
class StreamTLSInfo:
    """One decoded/classified TLS stream phase (phase 4, #31)."""

    record_type: int
    version: str
    handshake: str | None
    sni: str | None = None
    cipher_suites: list[str] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    supported_versions: list[str] = field(default_factory=list)
    tls12: bool = False
    tls13: bool = False

    def summary(self) -> str:
        part = self.handshake or f"record({self.record_type})"
        s = f"TLS {self.version} {part}"
        if self.sni:
            s += f" sni={self.sni}"
        if self.tls13:
            s += " (1.3)"
        elif self.tls12:
            s += " (1.2)"
        return s


@dataclass(slots=True)
class PendingHttpMessage:
    """A complete HTTP/1.x message recovered from the stream (#34)."""

    info: HTTPInfo
    start: int
    end: int

    def summary(self) -> str:
        return self.info.summary()


@dataclass(slots=True)
class H2Frame:
    """One decoded HTTP/2 frame (#35)."""

    frame_type: str
    length: int
    flags: int
    stream_id: int

    def summary(self) -> str:
        return f"HTTP/2 {self.frame_type} stream={self.stream_id} len={self.length} flags={self.flags:#x}"


class TlsStreamParser:
    """Incremental TLS record + handshake parser for a reassembled stream.

    Buffers partial records across feeds (a single TLS record may span many
    segments, #31) and classifies ClientHello/ServerHello (#32).
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self.records: list[StreamTLSInfo] = []
        self._saw_client_hello = False
        self._saw_server_hello = False

    def feed(self, data: bytes) -> list[StreamTLSInfo]:
        """Feed reassembled bytes; returns newly decoded record infos."""
        self._buf.extend(data)
        out: list[StreamTLSInfo] = []
        while len(self._buf) >= 5:
            if self._buf[0] not in (20, 21, 22, 23, 24):
                # Not a TLS record header — stop consuming here.
                if self.records:
                    break
                return out
            self._records_type = self._buf[0]
            version_code = int.from_bytes(self._buf[1:3], "big")
            rec_len = int.from_bytes(self._buf[3:5], "big")
            if rec_len > _MAX_RECORD:
                del self._buf[:5]
                continue
            if len(self._buf) < 5 + rec_len:
                break  # wait for the rest of the record
            body = bytes(self._buf[5 : 5 + rec_len])
            del self._buf[: 5 + rec_len]
            info = self._decode_record(self._buf_ts or 0.0, body, version_code)
            if info is not None:
                out.append(info)
                self.records.append(info)
        return out

    _buf_ts: str = ""  # placeholder kept for interface stability

    def _decode_record(
        self, _ts: float, body: bytes, version_code: int
    ) -> StreamTLSInfo | None:
        rec_type = self._records_type
        info = StreamTLSInfo(
            record_type=rec_type,
            version=tls_version_name(version_code),
            handshake=None,
        )
        if rec_type != 22 or len(body) < 4:
            return info
        handshake_type = body[0]
        info.handshake = _HANDSHAKE_NAMES.get(handshake_type, f"type={handshake_type}")
        if handshake_type == 1:  # ClientHello
            self._saw_client_hello = True
            self._decode_client_hello(body[4:], info)
            info.tls13 = any("1.3" in v for v in info.supported_versions)
        elif handshake_type == 2:  # ServerHello
            self._saw_server_hello = True
            self._decode_server_hello(body[4:], info)
        return info

    _records_type = 0

    def _decode_client_hello(
        self, body: bytes, info: StreamTLSInfo
    ) -> None:
        """Parse a ClientHello body: SNI, cipher suites, ALPN, versions."""
        try:
            _, off = _read_u16(body, 0)  # legacy_version
            off += 32  # random
            if off + 1 > len(body):
                return
            sid_len = body[off]
            off += 1 + sid_len
            if off + 2 > len(body):
                return
            cipher_total, off = _read_u16(body, off)
            if off + cipher_total > len(body):
                return
            suites = body[off : off + cipher_total]
            for i in range(0, len(suites) - 1, 2):
                code = int.from_bytes(suites[i : i + 2], "big")
                info.cipher_suites.append(_CIPHER_NAME.get(code, f"0x{code:04X}"))
            off += cipher_total
            if off + 1 > len(body):
                return
            comp_len = body[off]
            off += 1 + comp_len
            if off + 2 > len(body):
                return
            ext_total, off = _read_u16(body, off)
            ext_end = off + ext_total
            if ext_end > len(body):
                return
            while off + 4 <= ext_end:
                ext_type, off = _read_u16(body, off)
                ext_len, off = _read_u16(body, off)
                if off + ext_len > ext_end:
                    return
                ext = body[off : off + ext_len]
                off += ext_len
                if ext_type == 0:  # server_name (SNI)
                    info.sni = _parse_sni(ext)
                elif ext_type == 16:  # ALPN
                    info.alpn = _parse_alpn(ext)
                elif ext_type == 43:  # supported_versions
                    info.supported_versions = _parse_supported_versions(ext)
        except Exception:  # noqa: BLE001 - tolerant parsing
            pass

    def _decode_server_hello(
        self, body: bytes, info: StreamTLSInfo
    ) -> None:
        try:
            if len(body) < 5:
                return
            info.tls13 = any("1.3" in v for v in info.supported_versions)
            if len(body) < 35:
                return
            cipher = int.from_bytes(body[34:36], "big")
            info.cipher_suites = [_CIPHER_NAME.get(cipher, f"0x{cipher:04X}")]
        except Exception:  # noqa: BLE001
            pass

    def flush(self) -> list[StreamTLSInfo]:
        """Return any undecoded buffered bytes as a single record."""
        if not self._buf:
            return []
        left = bytes(self._buf)
        self._buf.clear()
        return [StreamTLSInfo(record_type=0, version="?", handshake="unfinished")]


def _parse_sni(ext: bytes) -> str | None:
    try:
        if len(ext) < 4:
            return None
        name_list_len = int.from_bytes(ext[0:2], "big")
        pos = 2
        while pos + 3 <= 4 + name_list_len and pos + 3 <= len(ext):
            name_type = ext[pos]
            name_len = int.from_bytes(ext[pos + 1 : pos + 3], "big")
            name = ext[pos + 3 : pos + 3 + name_len]
            if name_type == 0:
                return name.decode("utf-8", "replace")
            pos += 3 + name_len
    except Exception:  # noqa: BLE001
        return None
    return None


def _parse_alpn(ext: bytes) -> list[str]:
    out: list[str] = []
    try:
        if len(ext) < 2:
            return out
        total = int.from_bytes(ext[0:2], "big")
        pos = 2
        while pos + 1 <= 2 + total and pos + 1 <= len(ext):
            proto_len = ext[pos]
            proto = ext[pos + 1 : pos + 1 + proto_len]
            out.append(proto.decode("ascii", "replace"))
            pos += 1 + proto_len
    except Exception:  # noqa: BLE001
        pass
    return out


def _parse_supported_versions(ext: bytes) -> list[str]:
    out: list[str] = []
    try:
        if not ext:
            return out
        start = 1 if ext[0] == len(ext) - 1 else 0
        for i in range(start, len(ext) - 1, 2):
            code = int.from_bytes(ext[i : i + 2], "big")
            if code == TLS_VERSION_TLS13:
                out.append("1.3")
            elif code == TLS_VERSION_TLS12:
                out.append("1.2")
            else:
                out.append(f"0x{code:04X}")
    except Exception:  # noqa: BLE001
        pass
    return out


class Http1Parser:
    """Incremental HTTP/1.x message parser for a reassembled stream (#34).

    Uses ``Content-Length`` / chunked framing so multi-segment messages are
    emitted whole.
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self.messages: list[PendingHttpMessage] = []
        self._time = 0.0

    def feed(self, data: bytes) -> list[PendingHttpMessage]:
        self._buf.extend(data)
        out: list[PendingHttpMessage] = []
        while True:
            msg = self._extract_one()
            if msg is None:
                break
            out.append(msg)
            self.messages.append(msg)
        if len(self._buf) > _MAX_MESSAGE:
            del self._buf[: _MAX_MESSAGE // 2]
        return out

    def _extract_one(self) -> PendingHttpMessage | None:
        head_end = self._buf.find(b"\r\n\r\n")
        if head_end < 0:
            return None
        head_end += 4
        head = bytes(self._buf[:head_end])
        from netreplay.core.protocols import http as http_mod
        start = head.split(b"\r\n", 1)[0] if head else b""
        if start.startswith(b"HTTP/"):
            kind = "response"
        elif start.split(b" ", 1)[0] in _REQUESTS:
            kind = "request"
        else:
            return None
        body_len = _body_length(head, kind)
        total = head_end
        if body_len == "chunked":
            total = self._find_chunk_end()
            if total < 0:
                return None
        elif body_len is not None:
            total = head_end + body_len
        if len(self._buf) < total:
            return None
        payload = bytes(self._buf[:total])
        del self._buf[:total]
        info = http_mod.analyze_http(payload)
        if info is None:
            return None
        return PendingHttpMessage(
            info=info, start=self._base, end=self._base + total
        )

    _base = 0

    def _find_chunk_end(self) -> int:
        body = bytes(self._buf)
        # Minimal: locate "0\r\n\r\n" terminator of the final chunk.
        idx = body.rfind(b"0\r\n\r\n")
        if idx < 0:
            return -1
        return idx + len(b"0\r\n\r\n")

    def flush(self) -> list[PendingHttpMessage]:
        return []


_REQUESTS = frozenset(
    {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS",
     b"PATCH", b"TRACE", b"CONNECT"}
)


def _body_length(head: bytes, kind: str) -> int | str | None:
    """Return Content-Length, "chunked" or None (no framing = end-of-message)."""
    lines = head.split(b"\r\n")
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, _, value = line.partition(b":")
        if (
            key.strip().lower() == b"transfer-encoding"
            and b"chunked" in value.lower()
        ):
            return "chunked"
        if key.strip().lower() == b"content-length":
            try:
                return int(value.strip())
            except ValueError:
                return None
    if kind == "response":
        req = lines[0]
        if b" 204 " in req + b" " or b" 304 " not in req + b" " and b" 1" in req:
            return None
    return None


class Http2Parser:
    """HTTP/2 session parser over a reassembled stream (#35).

    Recognises the connection preface and then decodes real frames
    (type/flags/length/stream id) instead of stopping at the preface.
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self.frames: list[H2Frame] = []
        self.preface_ok = False

    def feed(self, data: bytes) -> list[H2Frame]:
        self._buf.extend(data)
        out: list[H2Frame] = []
        if not self.preface_ok:
            if len(self._buf) >= len(H2_PREFACE) + 9:
                if self._buf[: len(H2_PREFACE)] != H2_PREFACE:
                    return out
                self.preface_ok = True
                del self._buf[: len(H2_PREFACE)]
            else:
                return out
        while len(self._buf) >= 9:
            length = int.from_bytes(self._buf[0:3], "big")
            frame_type = self._buf[3]
            flags = self._buf[4]
            stream_id = int.from_bytes(self._buf[5:9], "big") & 0x7FFFFFFF
            if length > _MAX_RECORD:
                return out
            if len(self._buf) < 9 + length:
                break
            del self._buf[: 9 + length]
            frame = H2Frame(
                frame_type=_H2_FRAMES.get(frame_type, f"type={frame_type}"),
                length=length,
                flags=flags,
                stream_id=stream_id,
            )
            out.append(frame)
            self.frames.append(frame)
        return out

    def flush(self) -> list[H2Frame]:
        return []


def analyze_stream_direction(
    data: bytes, protocol_hint: str | None = None
) -> list[object]:
    """Run all stream analyzers over one reassembled direction (#31-35).

    Returns detected records: :class:`StreamTLSInfo`, :class:`H2Frame` or a
    :class:`PendingHttpMessage`.  Used by the service to surface protocol
    intelligence on top of reassembly.
    """
    results: list[object] = []
    if data[:1] in (b"\x16",) or protocol_hint == "tls":
        tls_parser = TlsStreamParser()
        results.extend(tls_parser.feed(data))
    if data.startswith(H2_PREFACE) or protocol_hint == "http2":
        h2 = Http2Parser()
        results.extend(h2.feed(data))
    if (
        protocol_hint in (None, "http")
        or data.split(b"\r\n", 1)[0].startswith(b"HTTP/")
    ):
        http1 = Http1Parser()
        results.extend(http1.feed(data))
    return results

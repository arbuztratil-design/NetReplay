"""TLS metadata extraction (no decryption).

Only reads the unencrypted handshake metadata: record type, handshake
message type, TLS version and SNI when present in the ClientHello.
Parsing is intentionally tolerant - malformed TLS payloads simply yield
``None``.
"""
from __future__ import annotations

from dataclasses import dataclass

TLS_HANDSHAKE = 0x16

_HANDSHAKE_TYPES: dict[int, str] = {
    1: "ClientHello",
    2: "ServerHello",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
}

_TLS_VERSIONS: dict[int, str] = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0002: "SSL 2.0",
    0x0003: "SSL 3.0",
}


def tls_version_name(code: int) -> str:
    return _TLS_VERSIONS.get(code, hex(code))


@dataclass(slots=True)
class TLSInfo:
    record_type: int
    handshake_type: int
    handshake_name: str
    version: str
    sni: str | None

    def summary(self) -> str:
        s = f"TLS {self.handshake_name} {self.version}"
        if self.sni:
            s += f" sni={self.sni}"
        return s


def _read_u16(buf: bytes, off: int) -> tuple[int, int]:
    return int.from_bytes(buf[off : off + 2], "big"), off + 2


def _read_u24(buf: bytes, off: int) -> tuple[int, int]:
    return int.from_bytes(buf[off : off + 3], "big"), off + 3


def _parse_sni_from_client_hello(hello: bytes) -> str | None:
    """Best-effort SNI extraction from a TLS ClientHello body."""
    try:
        off = 0
        if len(hello) < 2:
            return None
        legacy_version, off = _read_u16(hello, off)
        if len(hello) < off + 32:
            return None
        off += 32
        sid_len = hello[off]
        off += 1 + sid_len
        if off + 2 > len(hello):
            return None
        cipher_len, off = _read_u16(hello, off)
        off += cipher_len
        if off + 1 > len(hello):
            return None
        comp_len = hello[off]
        off += 1 + comp_len
        if off + 2 > len(hello):
            return None
        ext_total, off = _read_u16(hello, off)
        ext_end = off + ext_total
        if ext_end > len(hello):
            return None
        while off + 4 <= ext_end:
            ext_type, off = _read_u16(hello, off)
            ext_len, off = _read_u16(hello, off)
            if off + ext_len > ext_end:
                return None
            data = hello[off : off + ext_len]
            off += ext_len
            if ext_type == 0x0000:  # server_name
                if len(data) < 3:
                    continue
                name_list_len = int.from_bytes(data[0:2], "big")
                if name_list_len + 2 > len(data):
                    continue
                name_pos = 2
                while name_pos + 3 <= 2 + name_list_len:
                    name_type = data[name_pos]
                    name_len = int.from_bytes(data[name_pos + 1 : name_pos + 3], "big")
                    name = data[name_pos + 3 : name_pos + 3 + name_len]
                    if name_type == 0:
                        return name.decode("utf-8", errors="replace")
                    name_pos += 3 + name_len
    except Exception:
        return None
    return None


def analyze(payload: bytes) -> TLSInfo | None:
    """Analyze a TLS record stream (only the first handshake record)."""
    if not payload or payload[0] != TLS_HANDSHAKE:
        return None
    try:
        rec_type = payload[0]
        if len(payload) < 3:
            return None
        version_code, _ = _read_u16(payload, 1)
        rec_len = int.from_bytes(payload[3:5], "big")
        body = payload[5 : 5 + rec_len]
        if len(body) < 4:
            return None
        h_msg_type = body[0]
        hs_len, _ = _read_u24(body, 1)
        hs_body = body[4 : 4 + hs_len]

        h_name = _HANDSHAKE_TYPES.get(h_msg_type, f"Handshake({h_msg_type})")
        sni = None
        if h_msg_type == 1:  # ClientHello
            sni = _parse_sni_from_client_hello(hs_body)
        return TLSInfo(
            record_type=rec_type,
            handshake_type=h_msg_type,
            handshake_name=h_name,
            version=tls_version_name(version_code),
            sni=sni,
        )
    except Exception:
        return None

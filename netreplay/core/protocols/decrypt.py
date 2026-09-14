"""TLS 1.2 AES-GCM offline decryption using an NSS keylog file.

Scope (MVP): TLS 1.2 AEAD suites (ECDHE-*-AES128/256-GCM-SHA*) resolved
with a ``CLIENT_RANDOM`` master-secret line. TLS 1.3 and CBC suites are
detected but not decrypted (roadmap). The parser is stream-based: it
consumes reassembled per-direction TCP byte streams.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TLS_HANDSHAKE = 22
TLS_APPLICATION_DATA = 23

SUPPORTED_SUITES = {
    # suite -> (name, key_bytes, prf_hash_name)
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 16, "sha256"),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 16, "sha256"),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 32, "sha384"),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 32, "sha384"),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", 16, "sha256"),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384", 32, "sha384"),
}


class ParseError(Exception):
    """Malformed TLS stream."""


@dataclasses.dataclass(slots=True)
class TlsStream:
    """One TCP direction carrying TLS records."""

    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    direction: str  # "client" or "server"
    data: bytes
    # offset ranges (start, end, ts) per captured packet feeding this stream
    segments: list[tuple[int, int, float]]


@dataclasses.dataclass(slots=True)
class DecryptedRecord:
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    direction: str
    ts: float
    data: bytes


def load_keylog(path: str) -> dict[str, bytes]:
    """Parse an NSS key log file -> {client_random_hex: master_secret}."""
    keys: dict[str, bytes] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "CLIENT_RANDOM":
                keys[parts[1]] = bytes.fromhex(parts[2])
    return keys


def _iter_records(data: bytes):
    """Yield (offset, rec_type, version, body) for TLS 1.2 records."""
    off = 0
    while off + 5 <= len(data):
        rec_type = data[off]
        version = int.from_bytes(data[off + 1 : off + 3], "big")
        rec_len = int.from_bytes(data[off + 3 : off + 5], "big")
        body = data[off + 5 : off + 5 + rec_len]
        if off + 5 + rec_len > len(data):
            raise ParseError("truncated TLS record")
        yield off, rec_type, version, body
        off += 5 + rec_len


def _iter_handshake_messages(body: bytes):
    """Yield handshake messages from a handshake record body."""
    off = 0
    while off + 4 <= len(body):
        length = int.from_bytes(body[off + 1 : off + 4], "big")
        msg = body[off : off + 4 + length]
        if len(msg) != 4 + length:
            return
        yield msg
        off += 4 + length


def _hello_random(handshake_msg: bytes) -> bytes | None:
    """32-byte client random from a ClientHello handshake message."""
    if len(handshake_msg) < 4 + 2 + 32:
        return None
    return handshake_msg[4:][2:34]


def _server_hello_fields(handshake_msg: bytes) -> tuple[bytes, int, int] | None:
    """(server_random, cipher_suite, legacy_version) from a ServerHello."""
    body = handshake_msg[4:]
    if len(body) < 2 + 32:
        return None
    version = int.from_bytes(body[0:2], "big")
    server_random = body[2:34]
    sid_len = body[34]
    suite_off = 35 + sid_len
    if suite_off + 2 > len(body):
        return None
    suite = int.from_bytes(body[suite_off : suite_off + 2], "big")
    return server_random, suite, version


def _prf(secret: bytes, label_seed: bytes, length: int, algo: str) -> bytes:
    digest = hashlib.sha384 if algo == "sha384" else hashlib.sha256
    out = b""
    a = label_seed
    while len(out) < length:
        a = hmac.new(secret, a, digest).digest()
        out += hmac.new(secret, a + label_seed, digest).digest()
    return out[:length]


@dataclasses.dataclass(slots=True)
class _DirectionKeys:
    key: bytes
    salt: bytes


class _Tls12GcmContext:
    def __init__(self, master: bytes, client_random: bytes) -> None:
        self._master = master
        self._client_random = client_random
        self._started = False
        self._client: _DirectionKeys | None = None
        self._server: _DirectionKeys | None = None

    def on_client_hello(self, handshake_msg: bytes) -> None:
        rnd = _hello_random(handshake_msg)
        if rnd and rnd != self._client_random:
            self._client_random = rnd

    def on_server_hello(self, handshake_msg: bytes) -> bool:
        fields = _server_hello_fields(handshake_msg)
        if fields is None:
            return False
        server_random, suite, version = fields
        if version != 0x0303:
            return False
        info = SUPPORTED_SUITES.get(suite)
        if info is None:
            raise ParseError(f"unsupported TLS 1.2 cipher suite 0x{suite:04x}")
        _, key_len, algo = info
        self._derive(server_random, key_len, algo)
        return True

    def _derive(self, server_random: bytes, key_len: int, algo: str) -> None:
        key_block = _prf(
            self._master,
            b"key expansion" + server_random + self._client_random,
            key_len * 2 + 4 + 4,
            algo,
        )
        self._client = _DirectionKeys(
            key=key_block[0:key_len], salt=key_block[key_len * 2 : key_len * 2 + 4]
        )
        self._server = _DirectionKeys(
            key=key_block[key_len : key_len * 2],
            salt=key_block[key_len * 2 + 4 : key_len * 2 + 8],
        )
        self._started = True

    def decrypt_app(self, direction: str, version: int, body: bytes, seq: int) -> bytes | None:
        if not self._started or version != 0x0303:
            return None
        keys = self._client if direction == "client" else self._server
        if keys is None or len(body) < 8 + 16:
            return None
        explicit_nonce = body[:8]
        ciphertext = body[8:-16]
        tag = body[-16:]
        nonce = keys.salt + explicit_nonce
        # TLS 1.2 AEAD additional data:
        # seq_num(8) | content_type(1) | version(2) | TLSCompressed.length(2)
        # where TLSCompressed.length == ciphertext length (explicit nonce and
        # tag are not part of it).
        aad = (
            seq.to_bytes(8, "big")
            + bytes([TLS_APPLICATION_DATA])
            + version.to_bytes(2, "big")
            + len(ciphertext).to_bytes(2, "big")
        )
        cipher = AESGCM(keys.key)
        try:
            return cipher.decrypt(nonce, ciphertext + tag, aad)
        except Exception:
            return None


def _segment_ts(segments: list[tuple[int, int, float]], offset: int) -> float:
    for start, end, ts in segments:
        if start <= offset < end:
            return ts
    if segments:
        return segments[-1][2]
    return 0.0


def _handshake_processor(stream: TlsStream, context: _Tls12GcmContext) -> list[DecryptedRecord]:
    """Scan one direction for handshake records feeding key material;
    returns app-data records once keys are established.

    The TLS 1.2 per-direction write sequence number used by the AEAD starts
    at 0 on the first record after ChangeCipherSpec and increments for every
    record (encrypted Finished included).
    """
    out: list[DecryptedRecord] = []
    seq_ready = False
    seq = 0
    for off, rec_type, version, body in _iter_records(stream.data):
        if seq_ready:
            if rec_type == TLS_APPLICATION_DATA:
                plain = context.decrypt_app(stream.direction, version, body, seq)
                if plain:
                    out.append(
                        DecryptedRecord(
                            client_ip=stream.client_ip,
                            server_ip=stream.server_ip,
                            client_port=stream.client_port,
                            server_port=stream.server_port,
                            direction=stream.direction,
                            ts=_segment_ts(stream.segments, off),
                            data=plain,
                        )
                    )
            seq += 1
        if rec_type == 20:
            seq_ready = True
        if rec_type == TLS_HANDSHAKE:
            for msg in _iter_handshake_messages(body):
                if context._client_random is None:
                    rnd = _hello_random(msg)
                    if rnd:
                        context._client_random = rnd
                if msg[:1] == b"\x02":
                    context.on_server_hello(msg)
            continue
    return out


def decrypt_stream_pair(
    client_stream: TlsStream, server_stream: TlsStream, keylog: dict[str, bytes]
) -> list[DecryptedRecord]:
    """Decrypt both directions of a TLS 1.2 connection using a keylog.

    The client direction must carry the ClientHello (its random is the
    keylog lookup key); whichever direction is processed first, the shared
    context collects the random and derives keys from the ServerHello.
    """
    master: bytes | None = None
    context = _Tls12GcmContext(b"", b"")
    for stream in (client_stream, server_stream):
        # collect ClientHello (master key lookup) and ServerHello (suite/keys)
        for off, rec_type, version, body in _iter_records(stream.data):
            if rec_type != TLS_HANDSHAKE:
                continue
            for msg in _iter_handshake_messages(body):
                if msg[:1] == b"\x01":
                    rnd = _hello_random(msg)
                    if rnd is not None and master is None:
                        candidate = keylog.get(rnd.hex())
                        if candidate is not None:
                            master = candidate
                            context._master = master
                            context._client_random = rnd
                elif msg[:1] == b"\x02":
                    try:
                        context.on_server_hello(msg)
                    except ParseError:
                        return []
        if master is not None and context._started:
            break
    if master is None or not context._started:
        return []
    return _handshake_processor(client_stream, context) + _handshake_processor(
        server_stream, context
    )
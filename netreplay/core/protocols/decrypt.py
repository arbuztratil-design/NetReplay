"""TLS offline decryption using an NSS keylog file.

Supported:
- TLS 1.2 AEAD suites (ECDHE-*-AES128/256-GCM-SHA*, RSA key-exchange suites)
  resolved with ``CLIENT_RANDOM`` master-secret lines.
- TLS 1.3 (AES-128/256-GCM and ChaCha20-Poly1305) via the traffic-secret
  keylog lines (``CLIENT/SERVER_HANDSHAKE_TRAFFIC_SECRET`` and
  ``CLIENT/SERVER_TRAFFIC_SECRET_0``).

The TLS 1.3 path needs no transcript replay: the keylog already carries the
handshake and application traffic secrets; per-record keys come from
HKDF-Expand-Label ("tls13 key"/"tls13 iv", RFC 8446 7.1) and the AEAD nonce is
the per-record sequence number XORed into the 12-byte IV (RFC 8446 5.3).
Records are decrypted per direction with an epoch switch: the handshake epoch
lasts until a record's inner content type leaves the handshake phase, then the
application epoch begins (sequence numbers restart from zero per epoch).

The parser is stream-based: it consumes reassembled per-direction TCP streams.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

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

TLS13_SUITES = {
    # suite -> (name, key_bytes, hash_name, aead_kind)
    0x1301: ("TLS_AES_128_GCM_SHA256", 16, "sha256", "aesgcm"),
    0x1302: ("TLS_AES_256_GCM_SHA384", 32, "sha384", "aesgcm"),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", 32, "sha256", "chacha20poly1305"),
}

TLS13_LABELS = (
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
)


class ParseError(Exception):
    """Malformed TLS stream."""


@dataclasses.dataclass(slots=True)
class Keylog:
    """Parsed NSS key log: per ClientHello-random HEX values.

    ``masters`` holds TLS 1.2 master secrets from ``CLIENT_RANDOM`` lines;
    ``traffic`` maps a client-random HEX to the TLS 1.3 traffic secrets.
    """

    masters: dict[str, bytes] = dataclasses.field(default_factory=dict)
    traffic: dict[str, dict[str, bytes]] = dataclasses.field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.masters or self.traffic)


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


def load_keylog(path: str) -> Keylog:
    """Parse an NSS key log file (CLIENT_RANDOM + TLS 1.3 traffic secrets)."""
    keys = Keylog()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 3:
                continue
            label = parts[0]
            if label == "CLIENT_RANDOM":
                keys.masters[parts[1]] = bytes.fromhex(parts[2])
            elif label in TLS13_LABELS:
                keys.traffic.setdefault(parts[1], {})[label] = bytes.fromhex(parts[2])
    return keys


def _iter_records(data: bytes):
    """Yield (offset, rec_type, version, body) for TLS records."""
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


# --------------------------------------------------------------------------- TLS 1.2

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
        return self.on_server_hello_fields(server_random, suite)

    def on_server_hello_fields(self, server_random: bytes, suite: int) -> bool:
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


# --------------------------------------------------------------------------- TLS 1.3

def _hkdf_extract(salt: bytes, ikm: bytes, algo: str) -> bytes:
    digest = hashlib.sha384 if algo == "sha384" else hashlib.sha256
    return hmac.new(salt, ikm, digest).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int, algo: str) -> bytes:
    digest = hashlib.sha384 if algo == "sha384" else hashlib.sha256
    out = b""
    last = b""
    counter = 1
    while len(out) < length:
        last = hmac.new(prk, last + info + bytes([counter]), digest).digest()
        out += last
        counter += 1
    return out[:length]


def _hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int, algo: str) -> bytes:
    label_b = b"tls13 " + label
    info = (
        length.to_bytes(2, "big")
        + bytes([len(label_b)])
        + label_b
        + bytes([len(context)])
        + context
    )
    return _hkdf_expand(secret, info, length, algo)


def _tls13_key_iv(secret: bytes, key_len: int, algo: str) -> tuple[bytes, bytes]:
    key = _hkdf_expand_label(secret, b"key", b"", key_len, algo)
    iv = _hkdf_expand_label(secret, b"iv", b"", 12, algo)
    return key, iv


@dataclasses.dataclass(slots=True)
class _Tls13Keys:
    name: str
    key_len: int
    algo: str
    kind: str
    client_hs: tuple[bytes, bytes] | None
    server_hs: tuple[bytes, bytes] | None
    client_app: tuple[bytes, bytes] | None
    server_app: tuple[bytes, bytes] | None


def _tls13_keys(suite: int, secrets: dict[str, bytes]) -> _Tls13Keys:
    name, key_len, algo, kind = TLS13_SUITES[suite]

    def key_iv(label: str) -> tuple[bytes, bytes] | None:
        secret = secrets.get(label)
        if secret is None:
            return None
        return _tls13_key_iv(secret, key_len, algo)

    return _Tls13Keys(
        name=name,
        key_len=key_len,
        algo=algo,
        kind=kind,
        client_hs=key_iv("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
        server_hs=key_iv("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
        client_app=key_iv("CLIENT_TRAFFIC_SECRET_0"),
        server_app=key_iv("SERVER_TRAFFIC_SECRET_0"),
    )


def _aead(kind: str, key: bytes):
    if kind == "chacha20poly1305":
        return ChaCha20Poly1305(key)
    return AESGCM(key)


def _tls13_decrypt(body: bytes, key_iv: tuple[bytes, bytes] | None, seq: int, kind: str) -> bytes | None:
    """Decrypt one TLS 1.3 protected record (ciphertext + tag in ``body``)."""
    if key_iv is None or len(body) < 16:
        return None
    key, iv = key_iv
    nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(len(iv), "big")))
    # TLSCiphertext header, TLS 1.3: content_type | legacy_version | length
    # where length == encrypted_record length == len(body).
    aad = (
        bytes([TLS_APPLICATION_DATA])
        + b"\x03\x03"
        + len(body).to_bytes(2, "big")
    )
    try:
        return _aead(kind, key).decrypt(nonce, body, aad)
    except Exception:
        return None


def _tls13_process_direction(
    stream: TlsStream,
    hs_keys: tuple[bytes, bytes] | None,
    app_keys: tuple[bytes, bytes] | None,
    kind: str,
) -> list[DecryptedRecord]:
    """Decrypt ascending per-direction records, switching handshake -> app epoch.

    Sequence numbers restart from zero in every epoch (RFC 8446 5.3). The
    handshake epoch ends on the first record whose decrypted inner content
    type is not handshake.
    """
    out: list[DecryptedRecord] = []
    seq_hs = 0
    seq_app = 0
    epoch = "hs"
    for off, rec_type, version, body in _iter_records(stream.data):
        if rec_type != TLS_APPLICATION_DATA:
            continue
        if epoch == "hs" and hs_keys is not None:
            plain = _tls13_decrypt(body, hs_keys, seq_hs, kind)
            if plain is not None:
                seq_hs += 1
                inner = plain[-1]
                content = plain[:-1].rstrip(b"\x00")
                if inner == TLS_APPLICATION_DATA:
                    out.append(
                        DecryptedRecord(
                            client_ip=stream.client_ip,
                            server_ip=stream.server_ip,
                            client_port=stream.client_port,
                            server_port=stream.server_port,
                            direction=stream.direction,
                            ts=_segment_ts(stream.segments, off),
                            data=content,
                        )
                    )
                if inner != TLS_HANDSHAKE:
                    epoch = "app"
                continue
            epoch = "app"  # handshake key does not fit -> application epoch
        if epoch == "app" and app_keys is not None:
            plain = _tls13_decrypt(body, app_keys, seq_app, kind)
            if plain is None:
                continue
            seq_app += 1
            inner = plain[-1]
            content = plain[:-1].rstrip(b"\x00")
            if inner == TLS_APPLICATION_DATA:
                out.append(
                    DecryptedRecord(
                        client_ip=stream.client_ip,
                        server_ip=stream.server_ip,
                        client_port=stream.client_port,
                        server_port=stream.server_port,
                        direction=stream.direction,
                        ts=_segment_ts(stream.segments, off),
                        data=content,
                    )
                )
    return out


# --------------------------------------------------------------------------- entry point

def decrypt_stream_pair(
    client_stream: TlsStream, server_stream: TlsStream, keylog: Keylog
) -> list[DecryptedRecord]:
    """Decrypt both directions of a TLS connection using a keylog.

    The client direction must carry the ClientHello (its random is the keylog
    lookup key). TLS 1.3 is detected by the negotiated cipher suite and uses
    the per-connection traffic secrets; TLS 1.2 uses the master-secret path.
    """
    client_random_hex: str | None = None
    server_hello = None
    for stream in (client_stream, server_stream):
        for off, rec_type, version, body in _iter_records(stream.data):
            if rec_type != TLS_HANDSHAKE:
                continue
            for msg in _iter_handshake_messages(body):
                if msg[:1] == b"\x01":  # ClientHello
                    rnd = _hello_random(msg)
                    if rnd is not None:
                        client_random_hex = rnd.hex()
                elif msg[:1] == b"\x02":  # ServerHello
                    fields = _server_hello_fields(msg)
                    if fields is not None:
                        server_hello = fields
    if client_random_hex is None or server_hello is None:
        return []
    _, suite, _ = server_hello

    if suite in TLS13_SUITES:
        secrets = keylog.traffic.get(client_random_hex, {})
        if not any(label in secrets for label in TLS13_LABELS):
            return []
        k = _tls13_keys(suite, secrets)
        return _tls13_process_direction(
            client_stream, k.client_hs, k.client_app, k.kind
        ) + _tls13_process_direction(server_stream, k.server_hs, k.server_app, k.kind)

    if suite not in SUPPORTED_SUITES:
        return []
    master = keylog.masters.get(client_random_hex)
    if master is None:
        return []
    context = _Tls12GcmContext(master, bytes.fromhex(client_random_hex))
    try:
        if not context.on_server_hello_fields(server_hello[0], suite):
            return []
    except ParseError:
        return []
    return _handshake_processor(client_stream, context) + _handshake_processor(
        server_stream, context
    )
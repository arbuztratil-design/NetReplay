"""Helper that produces a genuine TLS 1.2 capture (.pcap) + NSS keylog line.

Runs a client/server TLS handshake entirely in memory BIOs through OpenSSL
(:mod:`ctypes`), recording every raw byte travelling in each direction, then
reassembles those byte streams into a synthetic Ethernet/IP/TCP pcap.

Used by tests only - no network, no Npcap required.
"""
from __future__ import annotations

import ctypes
import dataclasses
import io
import os
import sys

import scapy.all as scapy
from scapy.utils import PcapWriter


def _ssl_lib_path(name: str) -> str:
    for base in (sys.base_prefix, sys.exec_prefix):
        cand = os.path.join(base, "DLLs", name)
        if os.path.isfile(cand):
            return cand
    return name


try:
    _LIB = ctypes.CDLL(_ssl_lib_path("libssl-3.dll"))
    _CRYPTO = ctypes.CDLL(_ssl_lib_path("libcrypto-3.dll"))
except OSError as exc:  # platforms without the OpenSSL 3 DLLs (non-Windows)
    raise ImportError(f"OpenSSL 3 DLLs required for TLS capture tests: {exc}") from exc

TLS1_2 = 0x0303
# legacy SSL_OP_NO_* option bitmask values
SSL_OP_NO_SSLv2 = 0x01000000
SSL_OP_NO_SSLv3 = 0x02000000
SSL_OP_NO_TLSv1 = 0x04000000
SSL_OP_NO_TLSv1_1 = 0x10000000
SSL_OP_NO_TLSv1_2 = 0x08000000
SSL_OP_NO_TLSv1_3 = 0x20000000
_TLS12_ONLY = (
    SSL_OP_NO_SSLv2
    | SSL_OP_NO_SSLv3
    | SSL_OP_NO_TLSv1
    | SSL_OP_NO_TLSv1_1
    | SSL_OP_NO_TLSv1_3
)
_TLS13_ONLY = (
    SSL_OP_NO_SSLv2
    | SSL_OP_NO_SSLv3
    | SSL_OP_NO_TLSv1
    | SSL_OP_NO_TLSv1_1
    | SSL_OP_NO_TLSv1_2
)

# --------------------------------------------------------------------------- glue

_PTR = ctypes.c_void_p
_CHARP = ctypes.c_char_p
_INT = ctypes.c_int
_SSIZE = ctypes.c_ssize_t
_CPTR = ctypes.POINTER(ctypes.c_char)


def _f(lib, name, restype, argtypes):
    fn = getattr(lib, name)
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


BIO_new = _f(_CRYPTO, "BIO_new", _PTR, [_PTR])
BIO_s_mem = _f(_CRYPTO, "BIO_s_mem", _PTR, [])
BIO_new_mem_buf = _f(_CRYPTO, "BIO_new_mem_buf", _PTR, [_CPTR, _INT])
BIO_read = _f(_CRYPTO, "BIO_read", _SSIZE, [_PTR, _PTR, _INT])
BIO_write = _f(_CRYPTO, "BIO_write", _SSIZE, [_PTR, _CPTR, _INT])
BIO_ctrl = _f(_CRYPTO, "BIO_ctrl", _SSIZE, [_PTR, _INT, _SSIZE, _PTR])

BIO_CTRL_PENDING = 10
BIO_free = _f(_CRYPTO, "BIO_free", _INT, [_PTR])

SSL_CTX_new = _f(_LIB, "SSL_CTX_new", _PTR, [_PTR])
SSL_CTX_free = _f(_LIB, "SSL_CTX_free", None, [_PTR])
SSL_CTX_use_certificate = _f(_LIB, "SSL_CTX_use_certificate", _INT, [_PTR, _PTR])
SSL_CTX_use_PrivateKey = _f(_LIB, "SSL_CTX_use_PrivateKey", _INT, [_PTR, _PTR])
SSL_CTX_check_private_key = _f(_LIB, "SSL_CTX_check_private_key", _INT, [_PTR])
SSL_CTX_set_cipher_list = _f(_LIB, "SSL_CTX_set_cipher_list", _INT, [_PTR, _CHARP])
SSL_CTX_set_ciphersuites = _f(_LIB, "SSL_CTX_set_ciphersuites", _INT, [_PTR, _CHARP])
SSL_CTX_set_options = _f(_LIB, "SSL_CTX_set_options", _INT, [_PTR, _INT])

_KEYLOG_CB = ctypes.CFUNCTYPE(None, _PTR, _CHARP)
SSL_CTX_set_keylog_callback = _f(_LIB, "SSL_CTX_set_keylog_callback", None, [_PTR, _KEYLOG_CB])

_keylog_lines: list[bytes] = []


def _py_keylog_cb(ssl_ptr, line: bytes | None) -> None:
    """NSS keylog callback: append emitted traffic-secret lines."""
    try:
        if line:
            _keylog_lines.append(line)
    except Exception:
        pass


_CB_FN = _KEYLOG_CB(_py_keylog_cb)

TLS_client_method = _f(_LIB, "TLS_client_method", _PTR, [])
TLS_server_method = _f(_LIB, "TLS_server_method", _PTR, [])
SSL_new = _f(_LIB, "SSL_new", _PTR, [_PTR])
SSL_free = _f(_LIB, "SSL_free", None, [_PTR])
SSL_set_bio = _f(_LIB, "SSL_set_bio", None, [_PTR, _PTR, _PTR])
SSL_set_connect_state = _f(_LIB, "SSL_set_connect_state", None, [_PTR])
SSL_set_accept_state = _f(_LIB, "SSL_set_accept_state", None, [_PTR])
SSL_connect = _f(_LIB, "SSL_connect", _INT, [_PTR])
SSL_accept = _f(_LIB, "SSL_accept", _INT, [_PTR])
SSL_write = _f(_LIB, "SSL_write", _INT, [_PTR, _CHARP, _INT])
SSL_read = _f(_LIB, "SSL_read", _INT, [_PTR, ctypes.c_void_p, _INT])
SSL_get_error = _f(_LIB, "SSL_get_error", _INT, [_PTR, _INT])
SSL_get_session = _f(_LIB, "SSL_get_session", _PTR, [_PTR])
SSL_get_client_random = _f(_LIB, "SSL_get_client_random", _SSIZE, [_PTR, ctypes.c_void_p, _SSIZE])
SSL_get_server_random = _f(_LIB, "SSL_get_server_random", _SSIZE, [_PTR, ctypes.c_void_p, _SSIZE])
SSL_SESSION_get_master_key = _f(
    _LIB, "SSL_SESSION_get_master_key", _SSIZE, [_PTR, ctypes.c_void_p, _SSIZE]
)

PEM_read_bio_X509 = _f(_CRYPTO, "PEM_read_bio_X509", _PTR, [_PTR, _PTR, _PTR, _PTR])
PEM_read_bio_PrivateKey = _f(_CRYPTO, "PEM_read_bio_PrivateKey", _PTR, [_PTR, _PTR, _PTR, _PTR])

SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3

CIPHER_TLS12 = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
CIPHER_TLS13 = (
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
)

CHUNK = 8192


def _make_ssl_ctx(
    pem_cert: bytes | None = None,
    pem_key: bytes | None = None,
    cipher_list: str | None = None,
    tls13: bool = False,
) -> int:
    method = TLS_server_method() if pem_cert else TLS_client_method()
    ctx = SSL_CTX_new(method)
    if not ctx:
        raise RuntimeError("SSL_CTX_new failed")
    if pem_cert:
        bio = BIO_new_mem_buf(ctypes.cast(pem_cert, _CPTR), len(pem_cert))
        x509 = PEM_read_bio_X509(bio, None, None, None)
        BIO_free(bio)
        if not x509 or SSL_CTX_use_certificate(ctx, x509) != 1:
            raise RuntimeError("cannot load server certificate")
        bio = BIO_new_mem_buf(ctypes.cast(pem_key, _CPTR), len(pem_key))
        priv = PEM_read_bio_PrivateKey(bio, None, None, None)
        BIO_free(bio)
        if not priv or SSL_CTX_use_PrivateKey(ctx, priv) != 1:
            raise RuntimeError("cannot load server private key")
        if SSL_CTX_check_private_key(ctx) != 1:
            raise RuntimeError("certificate/private key mismatch")
    SSL_CTX_set_options(ctx, _TLS13_ONLY if tls13 else _TLS12_ONLY)
    default_ciphers = CIPHER_TLS13 if tls13 else CIPHER_TLS12
    ciphers = cipher_list or default_ciphers
    if tls13:
        SSL_CTX_set_ciphersuites(ctx, ciphers.encode())
    else:
        SSL_CTX_set_cipher_list(ctx, ciphers.encode())
    return ctx


class _Conn:
    def __init__(self, ctx: int, name: str) -> None:
        self._ssl = SSL_new(ctx)
        self._rbio = BIO_new(BIO_s_mem())
        self._wbio = BIO_new(BIO_s_mem())
        if not self._ssl or not self._rbio or not self._wbio:
            raise RuntimeError(f"{name}: SSL_new/BIO_new failed")
        SSL_set_bio(self._ssl, self._rbio, self._wbio)
        self.name = name
        self.outgoing: list[bytes] = []
        self.wire: list[bytes] = []

    def drain(self) -> list[bytes]:
        self.read_outgoing()
        chunks, self.outgoing = self.outgoing, []
        self.wire.extend(chunks)
        return chunks

    def read_outgoing(self) -> None:
        """Append everything written by OpenSSL to ``outgoing`` (no clear)."""
        while True:
            pending = BIO_ctrl(self._wbio, BIO_CTRL_PENDING, 0, None)
            if pending <= 0:
                break
            buf = ctypes.create_string_buffer(pending)
            n = BIO_read(self._wbio, ctypes.cast(buf, ctypes.c_void_p), pending)
            if n <= 0:
                break
            self.outgoing.append(buf.raw[:n])

    def feed(self, data: bytes) -> None:
        if data:
            BIO_write(self._rbio, ctypes.cast(data, _CPTR), len(data))

    def ssl(self) -> int:
        return self._ssl


def _pump(conn_a: _Conn, conn_b: _Conn, until, flips: int = 64) -> int:
    """Pump data between memory BIOs, running ``until`` each pass."""
    rc = 1
    for _ in range(flips):
        a_chunks = conn_a.drain()
        b_chunks = conn_b.drain()
        for chunk in a_chunks:
            conn_b.feed(chunk)
        for chunk in b_chunks:
            conn_a.feed(chunk)
        rc = until(conn_a, conn_b)
        if rc == 0:
            break
    return rc


def _handshake(client: _Conn, server: _Conn) -> None:
    SSL_set_connect_state(client._ssl)
    SSL_set_accept_state(server._ssl)

    def step(c, s):
        cc = SSL_connect(c._ssl) if c._ssl else 0
        sa = SSL_accept(s._ssl) if s._ssl else 0
        if cc == 1 and sa == 1:
            return 0
        return -1

    _pump(client, server, step, flips=64)


def _read_app(conn: _Conn) -> bytes:
    out = io.BytesIO()
    while True:
        buf = ctypes.create_string_buffer(65536)
        n = SSL_read(conn._ssl, ctypes.cast(buf, ctypes.c_void_p), 65536)
        if n <= 0:
            break
        out.write(buf.raw[:n])
        conn.read_outgoing()
    return out.getvalue()


def _write_app(conn: _Conn, data: bytes) -> None:
    total = 0
    stalls = 0
    while total < len(data):
        n = SSL_write(conn._ssl, data[total:], len(data) - total)
        if n <= 0:
            err = SSL_get_error(conn._ssl, n)
            if err in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
                stalls += 1
                if stalls > 100:
                    raise RuntimeError(f"{conn.name}: SSL_write stuck")
                continue
            raise RuntimeError(f"{conn.name}: SSL_write failed ({err})")
        total += n
        stalls = 0
    conn.read_outgoing()


@dataclasses.dataclass
class TlsCaptureResult:
    client_bytes: bytes
    server_bytes: bytes
    keylog_line: str
    client_flow: tuple  # (src_ip, dst_ip, sport, dport)
    server_random: bytes | None = None
    client_random: bytes | None = None
    keylog_lines: list[str] = dataclasses.field(default_factory=list)


def _decode_master(ssl_ptr: int) -> bytes:
    max_len = 256
    buf = ctypes.create_string_buffer(max_len)
    n = SSL_SESSION_get_master_key(SSL_get_session(ssl_ptr), ctypes.cast(buf, ctypes.c_void_p), max_len)
    return buf.raw[:n]


def _decode_client_random(ssl_ptr: int) -> bytes:
    buf = ctypes.create_string_buffer(32)
    n = SSL_get_client_random(ssl_ptr, ctypes.cast(buf, ctypes.c_void_p), 32)
    return buf.raw[:n] if n else b""


def _decode_server_random(ssl_ptr: int) -> bytes:
    buf = ctypes.create_string_buffer(32)
    n = SSL_get_server_random(ssl_ptr, ctypes.cast(buf, ctypes.c_void_p), 32)
    return buf.raw[:n] if n else b""


def make_tls12_capture(
    cert_pem: bytes,
    key_pem: bytes,
    client_payload: bytes = b"GET /secret HTTP/1.1\r\nHost: example.test\r\n\r\n",
    server_payload: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nSOMETHING",
    cipher_list: str | None = None,
) -> TlsCaptureResult:
    """Perform a real TLS 1.2 handshake + app-data exchange in memory and
    return both raw direction byte streams plus the master-secret keylog line."""
    client_ctx = _make_ssl_ctx(cipher_list=cipher_list)
    server_ctx = _make_ssl_ctx(cert_pem, key_pem, cipher_list=cipher_list)
    try:
        client = _Conn(client_ctx, "client")
        server = _Conn(server_ctx, "server")
        _handshake(client, server)

        client.read_outgoing()
        server.read_outgoing()

        _write_app(client, client_payload)
        _pump(client, server, lambda c, s: -1, flips=16)
        got = _read_app(server)
        assert got == client_payload, "server received wrong payload: %r" % (got,)

        _write_app(server, server_payload)
        _pump(client, server, lambda c, s: -1, flips=16)
        ret = _read_app(client)
        assert ret == server_payload, "client received wrong payload"

        master = _decode_master(client._ssl)
        crandom = _decode_client_random(client._ssl)
        assert master and len(crandom) == 32, "could not extract TLS secrets"
        srandom = _decode_server_random(client._ssl)
        keylog = "CLIENT_RANDOM %s %s\n" % (
            crandom.hex(),
            master.hex(),
        )
        return TlsCaptureResult(
            client_bytes=b"".join(client.wire),
            server_bytes=b"".join(server.wire),
            keylog_line=keylog,
            client_flow=("192.0.2.10", "192.0.2.20", 41000, 443),
            server_random=srandom,
            client_random=crandom,
        )
    finally:
        SSL_CTX_free(client_ctx)
        SSL_CTX_free(server_ctx)


def make_tls13_capture(
    cert_pem: bytes,
    key_pem: bytes,
    client_payload: bytes = b"GET /secret HTTP/1.1\r\nHost: example.test\r\n\r\n",
    server_payload: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nSOMETHING",
    cipher_list: str | None = None,
) -> TlsCaptureResult:
    """Real TLS 1.3 handshake + app-data exchange with a traffic-secret keylog.

    The four TLS 1.3 traffic-secret lines (client/server handshake + app) are
    collected through OpenSSL's keylog callback on the client context.
    """
    client_ctx = _make_ssl_ctx(cipher_list=cipher_list, tls13=True)
    server_ctx = _make_ssl_ctx(cert_pem, key_pem, cipher_list=cipher_list, tls13=True)
    SSL_CTX_set_keylog_callback(client_ctx, _CB_FN)
    try:
        _keylog_lines.clear()
        client = _Conn(client_ctx, "client")
        server = _Conn(server_ctx, "server")
        _handshake(client, server)

        client.read_outgoing()
        server.read_outgoing()

        _write_app(client, client_payload)
        _pump(client, server, lambda c, s: -1, flips=16)
        got = _read_app(server)
        assert got == client_payload, "server received wrong payload: %r" % (got,)

        _write_app(server, server_payload)
        _pump(client, server, lambda c, s: -1, flips=16)
        ret = _read_app(client)
        assert ret == server_payload, "client received wrong payload"

        crandom = _decode_client_random(client._ssl)
        assert len(crandom) == 32, "could not extract client random"
        srandom = _decode_server_random(client._ssl)
        lines = [line.decode("utf-8", errors="replace").rstrip("\n") for line in _keylog_lines]
        for label in (
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
        ):
            if not any(line.startswith(label + " ") for line in lines):
                raise AssertionError(f"missing keylog line: {label}")
        return TlsCaptureResult(
            client_bytes=b"".join(client.wire),
            server_bytes=b"".join(server.wire),
            keylog_line="",
            client_flow=("192.0.2.10", "192.0.2.20", 41000, 443),
            server_random=srandom,
            client_random=crandom,
            keylog_lines=lines,
        )
    finally:
        SSL_CTX_free(client_ctx)
        SSL_CTX_free(server_ctx)


def write_pcap(path: str, client_bytes: bytes, server_bytes: bytes, flow) -> None:
    """Synthesize an Ethernet/IP/TCP pcap from the two direction byte streams."""
    scapy.conf.verb = 0
    c_ip, s_ip, c_port, s_port = flow
    client_mac = "00:11:22:33:44:55"
    server_mac = "66:77:88:99:aa:bb"
    client_seq = 1000
    server_seq = 9000

    def segs(data: bytes, mss: int = 512):
        return [data[i : i + mss] for i in range(0, len(data), mss)] if data else [b""]

    def frame(src_ip, dst_ip, sport, dport, s_seq, ack, flags, payload, smac, dmac, ts):
        return (
            scapy.Ether(src=smac, dst=dmac)
            / scapy.IP(src=src_ip, dst=dst_ip)
            / scapy.TCP(sport=sport, dport=dport, seq=s_seq, ack=ack, flags=flags, window=8192)
            / scapy.Raw(payload),
            ts,
        )

    frames = []
    t = 1000.0

    # Client direction: SYN, then data segments.
    for i, part in enumerate(segs(client_bytes)):
        ack = server_seq
        flags = "S" if i == 0 else "PA"
        f, tstamp = frame(c_ip, s_ip, c_port, s_port, client_seq, ack, flags, part, client_mac, server_mac, t)
        frames.append((f, tstamp))
        client_seq += len(part)
        t += 0.0001

    # Server direction: SYN/ACK, then data segments.
    for i, part in enumerate(segs(server_bytes)):
        ack = client_seq
        flags = "SA" if i == 0 else "PA"
        f, tstamp = frame(s_ip, c_ip, s_port, c_port, server_seq, ack, flags, part, server_mac, client_mac, t)
        frames.append((f, tstamp))
        server_seq += len(part)
        t += 0.0001

    with PcapWriter(path, sync=True, linktype=1) as w:
        for f, tstamp in sorted(frames, key=lambda pair: pair[1]):
            f.time = tstamp
            w.write(f)

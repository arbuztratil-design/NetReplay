"""Offline TLS 1.2/1.3 decryption from an NSS keylog + raw direction
streams. Broke out of _tls_capture: a real (OpenSSL-driven) TLS session
per cipher suite, decrypted back through decrypt_stream_pair()."""

import datetime
import pathlib

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

tc = pytest.importorskip("tests._tls_capture")
from netreplay.core.protocols.decrypt import (  # noqa: E402
    Keylog, TlsStream, load_keylog,
    _iter_records, _iter_handshake_messages, _server_hello_fields,
)
from netreplay.core.protocols.decrypt import decrypt_stream_pair  # noqa: E402

CLIENT_PAYLOAD = b"GET /secret HTTP/1.1\r\nHost: example.test\r\n\r\n"
SERVER_PAYLOAD = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nSOMETHING"

# (OpenSSL cipher string / TLS 1.3 suite name, expected suite id, readable name)
SUITES = [
    pytest.param("ECDHE-RSA-AES128-GCM-SHA256", 0xC02F, "ECDHE-RSA-AES128-GCM-SHA256", id="c02f-aes128-sha256"),
    pytest.param("ECDHE-RSA-AES256-GCM-SHA384", 0xC030, "ECDHE-RSA-AES256-GCM-SHA384", id="c030-aes256-sha384"),
]

# TLS 1.2 AES-CBC suites are not compiled into this OpenSSL build, so they are
# exercised with synthetic records built by tests/_tls12_cbc.py.
CBC_SUITES = [
    pytest.param(0xC013, id="c013-cbc-sha1"),
    pytest.param(0xC014, id="c014-cbc-sha1"),
    pytest.param(0xC027, id="c027-cbc-sha256"),
    pytest.param(0xC028, id="c028-cbc-sha256"),
    pytest.param(0x002F, id="002f-rsa-cbc-sha1"),
    pytest.param(0x003C, id="003c-rsa-cbc-sha256"),
]

TLS13_SUITES = [
    pytest.param("TLS_AES_128_GCM_SHA256", 0x1301, "TLS_AES_128_GCM_SHA256", id="tls13-aes128-gcm-sha256"),
    pytest.param("TLS_AES_256_GCM_SHA384", 0x1302, "TLS_AES_256_GCM_SHA384", id="tls13-aes256-gcm-sha384"),
    pytest.param("TLS_CHACHA20_POLY1305_SHA256", 0x1303, "TLS_CHACHA20_POLY1305_SHA256", id="tls13-chacha20-poly1305"),
]


def _make_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _stream(name, direction, blob, c_ip, s_ip, c_port, s_port):
    return TlsStream(c_ip, s_ip, c_port, s_port, direction, blob, [(0, len(blob), 1.5)])


def _decrypt_all(res: tc.TlsCaptureResult, keys: Keylog | None = None):
    if keys is None:
        line = res.keylog_line.strip().split()
        assert line[0] == "CLIENT_RANDOM"
        keys = Keylog(masters={line[1]: bytes.fromhex(line[2])})
    c_ip, s_ip, c_port, s_port = res.client_flow
    streams = [
        _stream("c", "client", res.client_bytes, c_ip, s_ip, c_port, s_port),
        _stream("s", "server", res.server_bytes, c_ip, s_ip, c_port, s_port),
    ]
    return decrypt_stream_pair(streams[0], streams[1], keys)


def _negotiated_suite(res: tc.TlsCaptureResult):
    for off, rec_type, version, body in _iter_records(res.server_bytes):
        if rec_type != 22:
            continue
        for msg in _iter_handshake_messages(body):
            if msg[:1] == b"\x02":
                fields = _server_hello_fields(msg)
                if fields:
                    return fields[1]
    raise AssertionError("ServerHello not found")


def _keylog_from_lines(res: tc.TlsCaptureResult) -> Keylog:
    keys = Keylog()
    for line in res.keylog_lines:
        parts = line.split()
        assert len(parts) == 3
        if parts[0] == "CLIENT_RANDOM":
            keys.masters[parts[1]] = bytes.fromhex(parts[2])
        else:
            keys.traffic.setdefault(parts[1], {})[parts[0]] = bytes.fromhex(parts[2])
    return keys


@pytest.mark.parametrize("cipher_str,expected_suite,name", SUITES)
def test_tls12_gcm_decrypts_both_directions(cipher_str, expected_suite, name):
    cert_pem, key_pem = _make_cert()
    res = tc.make_tls12_capture(
        cert_pem, key_pem, client_payload=CLIENT_PAYLOAD, server_payload=SERVER_PAYLOAD,
        cipher_list=cipher_str,
    )
    assert _negotiated_suite(res) == expected_suite, f"expected {name}"

    records = _decrypt_all(res)
    assert records, "no application records decrypted"
    datas = [(r.direction, r.data) for r in records]
    assert any(d == CLIENT_PAYLOAD for _, d in datas), datas
    assert any(d == SERVER_PAYLOAD for _, d in datas), datas

    # metadata sanity: timestamps and direction tags propagate
    for r in records:
        assert r.direction in ("client", "server")
        assert r.ts > 0
        assert r.client_ip == res.client_flow[0]
        assert r.server_ip == res.client_flow[1]


@pytest.mark.parametrize("expected_suite", CBC_SUITES)
def test_tls12_cbc_synthetic_decrypts_both_directions(expected_suite):
    cbc = pytest.importorskip("tests._tls12_cbc")
    res = cbc.make_tls12_cbc_session(expected_suite, CLIENT_PAYLOAD, SERVER_PAYLOAD)
    records = _decrypt_all(res)
    assert records, "no application records decrypted"
    datas = [(r.direction, r.data) for r in records]
    assert any(d == CLIENT_PAYLOAD for _, d in datas), datas
    assert any(d == SERVER_PAYLOAD for _, d in datas), datas


@pytest.mark.parametrize("cipher_str,expected_suite,name", TLS13_SUITES)
def test_tls13_decrypts_both_directions(cipher_str, expected_suite, name):
    cert_pem, key_pem = _make_cert()
    res = tc.make_tls13_capture(
        cert_pem, key_pem, client_payload=CLIENT_PAYLOAD, server_payload=SERVER_PAYLOAD,
        cipher_list=cipher_str,
    )
    assert _negotiated_suite(res) == expected_suite, f"expected {name}"

    keys = _keylog_from_lines(res)
    records = _decrypt_all(res, keys)
    assert records, "no application records decrypted"
    datas = [(r.direction, r.data) for r in records]
    assert any(d == CLIENT_PAYLOAD for _, d in datas), datas
    assert any(d == SERVER_PAYLOAD for _, d in datas), datas

    for r in records:
        assert r.direction in ("client", "server")
        assert r.ts > 0
        assert r.client_ip == res.client_flow[0]
        assert r.server_ip == res.client_flow[1]


def test_tls13_no_keylog_returns_empty():
    cert_pem, key_pem = _make_cert()
    res = tc.make_tls13_capture(cert_pem, key_pem, cipher_list="TLS_AES_128_GCM_SHA256")
    c_ip, s_ip, c_port, s_port = res.client_flow
    streams = [
        _stream("c", "client", res.client_bytes, c_ip, s_ip, c_port, s_port),
        _stream("s", "server", res.server_bytes, c_ip, s_ip, c_port, s_port),
    ]
    assert decrypt_stream_pair(streams[0], streams[1], Keylog()) == []


def test_load_keylog_skips_non_random_lines(tmp_path):
    log = tmp_path / "keys.log"
    log.write_text(
        "HEADER comment\n"
        "CLIENT_RANDOM aabb 0102030405\n"
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET aabb 9988776655\n"
        "SERVER_TRAFFIC_SECRET_0 cafebabe aabbccddeeff\n"
        "# nope\n",
        encoding="utf-8",
    )
    keys = load_keylog(str(log))
    assert keys.masters == {"aabb": bytes.fromhex("0102030405")}
    assert keys.traffic == {
        "aabb": {"CLIENT_HANDSHAKE_TRAFFIC_SECRET": bytes.fromhex("9988776655")},
        "cafebabe": {"SERVER_TRAFFIC_SECRET_0": bytes.fromhex("aabbccddeeff")},
    }


def test_decrypt_returns_empty_without_matching_key(tmp_path):
    cert_pem, key_pem = _make_cert()
    res = tc.make_tls12_capture(
        cert_pem, key_pem, client_payload=CLIENT_PAYLOAD, server_payload=SERVER_PAYLOAD,
        cipher_list="ECDHE-RSA-AES128-GCM-SHA256",
    )
    c_ip, s_ip, c_port, s_port = res.client_flow
    streams = [
        _stream("c", "client", res.client_bytes, c_ip, s_ip, c_port, s_port),
        _stream("s", "server", res.server_bytes, c_ip, s_ip, c_port, s_port),
    ]
    assert decrypt_stream_pair(streams[0], streams[1], Keylog()) == []
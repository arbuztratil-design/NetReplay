"""Offline TLS 1.2 AES-GCM decryption from an NSS keylog + raw direction
streams. Broke out of _tls_capture: a real (OpenSSL-driven) TLS 1.2 session
per cipher suite, decrypted back through decrypt_stream_pair()."""

import datetime
import pathlib

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

tc = pytest.importorskip("tests._tls_capture")
from netreplay.core.protocols.decrypt import (  # noqa: E402
    TlsStream, decrypt_stream_pair, load_keylog,
    _iter_records, _iter_handshake_messages, _server_hello_fields,
)

CLIENT_PAYLOAD = b"GET /secret HTTP/1.1\r\nHost: example.test\r\n\r\n"
SERVER_PAYLOAD = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nSOMETHING"

# OpenSSL cipher strings -> (expected suite id, readable name)
SUITES = [
    pytest.param("ECDHE-RSA-AES128-GCM-SHA256", 0xC02F, "ECDHE-RSA-AES128-GCM-SHA256", id="c02f-aes128-sha256"),
    pytest.param("ECDHE-RSA-AES256-GCM-SHA384", 0xC030, "ECDHE-RSA-AES256-GCM-SHA384", id="c030-aes256-sha384"),
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


def _decrypt_all(res: tc.TlsCaptureResult):
    keys = {}
    line = res.keylog_line.strip().split()
    assert line[0] == "CLIENT_RANDOM"
    keys[line[1]] = bytes.fromhex(line[2])
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


def test_load_keylog_skips_non_random_lines(tmp_path):
    log = tmp_path / "keys.log"
    log.write_text("HEADER comment\nCLIENT_RANDOM aabb 0102030405\n# nope\n", encoding="utf-8")
    keys = load_keylog(str(log))
    assert keys == {"aabb": bytes.fromhex("0102030405")}


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
    assert decrypt_stream_pair(streams[0], streams[1], {}) == []
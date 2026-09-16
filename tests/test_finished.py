"""Finished (verify_data) verification against genuine OpenSSL handshakes.

Real TLS 1.2/1.3 captures carry real Finished messages; verify_finished() must
resolve them to 'verified'. Tampering with a plaintext handshake message that
feeds the transcript must flip the verdict to MISMATCH.
"""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

tc = pytest.importorskip("tests._tls_capture")
from netreplay.core.protocols.decrypt import (  # noqa: E402
    Keylog,
    TlsStream,
    _iter_handshake_messages,
    _iter_records,
    verify_finished,
)

CIPHERS_TLS12 = [
    pytest.param("ECDHE-RSA-AES128-GCM-SHA256", 0xC02F, id="c02f-aes128-sha256"),
    pytest.param("ECDHE-RSA-AES256-GCM-SHA384", 0xC030, id="c030-aes256-sha384"),
]
CIPHERS_TLS13 = [
    pytest.param("TLS_AES_128_GCM_SHA256", 0x1301, id="tls13-aes128-gcm-sha256"),
    pytest.param("TLS_AES_256_GCM_SHA384", 0x1302, id="tls13-aes256-gcm-sha384"),
    pytest.param("TLS_CHACHA20_POLY1305_SHA256", 0x1303, id="tls13-chacha20-poly1305"),
]


def _make_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.test")])
    now = datetime.datetime.now(datetime.UTC)
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


def _keylog(res: tc.TlsCaptureResult) -> Keylog:
    keys = Keylog()
    for line in res.keylog_lines:
        parts = line.split()
        assert len(parts) == 3
        if parts[0] == "CLIENT_RANDOM":
            keys.masters[parts[1]] = bytes.fromhex(parts[2])
        else:
            keys.traffic.setdefault(parts[1], {})[parts[0]] = bytes.fromhex(parts[2])
    if res.keylog_line:
        parts = res.keylog_line.split()
        keys.masters[parts[1]] = bytes.fromhex(parts[2])
    return keys


def _streams(res: tc.TlsCaptureResult) -> tuple[TlsStream, TlsStream]:
    c_ip, s_ip, c_port, s_port = res.client_flow
    client = TlsStream(c_ip, s_ip, c_port, s_port, "client", res.client_bytes, [(0, len(res.client_bytes), 1.5)])
    server = TlsStream(c_ip, s_ip, c_port, s_port, "server", res.server_bytes, [(0, len(res.server_bytes), 2.5)])
    return client, server


def _flip_transcript_byte(blob: bytes, warning_note: str = "tampered") -> bytes:
    """Flip the last body byte of the FIRST plaintext handshake message. That
    byte feeds the Finished transcript but sits after the client random (so key
    derivation still works) and is not authenticated by any record MAC, so
    decryption stays intact while Finished verification must fail."""
    for off, rec_type, _ver, body in _iter_records(blob):
        if rec_type != 22:
            continue
        for msg in _iter_handshake_messages(body):
            if msg:
                target = off + 5 + len(msg) - 1
                if off + 5 < target < len(blob):
                    return blob[:target] + bytes([blob[target] ^ 0xFF]) + blob[target + 1 :]
    raise AssertionError(f"{warning_note}: no plaintext handshake message found")


@pytest.mark.parametrize("cipher,expected_suite", CIPHERS_TLS12)
def test_tls12_verify_finished_ok(cipher, expected_suite):
    cert_pem, key_pem = _make_cert()
    res = tc.make_tls12_capture(cert_pem, key_pem, cipher_list=cipher)
    client, server = _streams(res)
    reports = verify_finished(client, server, _keylog(res))
    assert len(reports) == 2, reports
    assert {r.direction for r in reports} == {"client", "server"}
    for r in reports:
        assert r.verified is True, r
        assert r.version == 2
        assert r.length == 12
        assert r.expected == r.actual
        assert r.ts > 0
        assert "verified" in r.summary()


@pytest.mark.parametrize("cipher,expected_suite", CIPHERS_TLS13)
def test_tls13_verify_finished_ok(cipher, expected_suite):
    cert_pem, key_pem = _make_cert()
    res = tc.make_tls13_capture(cert_pem, key_pem, cipher_list=cipher)
    client, server = _streams(res)
    reports = verify_finished(client, server, _keylog(res))
    assert len(reports) == 2, reports
    assert {r.direction for r in reports} == {"client", "server"}
    hash_len = 48 if expected_suite == 0x1302 else 32
    for r in reports:
        assert r.verified is True, r
        assert r.version == 3
        assert r.length == hash_len
        assert r.expected == r.actual


@pytest.mark.parametrize(
    "make,cipher",
    [
        pytest.param(lambda cp, kp, c: tc.make_tls12_capture(cp, kp, cipher_list=c), "ECDHE-RSA-AES128-GCM-SHA256", id="tls12"),
        pytest.param(lambda cp, kp, c: tc.make_tls13_capture(cp, kp, cipher_list=c), "TLS_AES_128_GCM_SHA256", id="tls13"),
    ],
)
def test_tampered_transcript_yields_mismatch(make, cipher):
    cert_pem, key_pem = _make_cert()
    res = make(cert_pem, key_pem, cipher)
    client, server = _streams(res)
    keys = _keylog(res)
    assert verify_finished(client, server, keys)
    client.data = _flip_transcript_byte(client.data)
    reports = verify_finished(client, server, keys)
    assert reports, "expected reports even on tampered transcript"
    assert all(r.verified is False for r in reports), reports
    for r in reports:
        assert r.expected != r.actual
        assert "MISMATCH" in r.summary()


def test_verify_finished_empty_without_keys():
    cert_pem, key_pem = _make_cert()
    res = tc.make_tls12_capture(cert_pem, key_pem, cipher_list="ECDHE-RSA-AES128-GCM-SHA256")
    client, server = _streams(res)
    assert verify_finished(client, server, Keylog()) == []

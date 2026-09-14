"""End-to-end: import a real TLS 1.2 pcap with --keylog and see DECRYPT events."""

import datetime
import pathlib

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

tc = pytest.importorskip("tests._tls_capture")
from netreplay.core.service import NetReplayService  # noqa: E402
from netreplay.core.storage import open_session  # noqa: E402
from netreplay.core.timeline.service import TimelineService  # noqa: E402

CLIENT_PAYLOAD = b"GET /very/secret HTTP/1.1\r\nHost: example.test\r\n\r\n"
SERVER_PAYLOAD = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nHELLO"


@pytest.fixture()
def keyed_tls():
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    res = tc.make_tls12_capture(
        cert_pem,
        key_pem,
        cipher_list="ECDHE-RSA-AES128-GCM-SHA256",
        client_payload=CLIENT_PAYLOAD,
        server_payload=SERVER_PAYLOAD,
    )
    return res


def test_import_pcap_with_keylog_decrypts(tmp_path, keyed_tls):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    pcap = tmp_path / "tls.pcap"
    log = tmp_path / "keys.log"
    tc.write_pcap(str(pcap), keyed_tls.client_bytes, keyed_tls.server_bytes, keyed_tls.client_flow)
    log.write_text(keyed_tls.keylog_line, encoding="utf-8")

    status = NetReplayService(workspace).import_pcap(pcap, workspace / "tls.nrp", keylog=log)

    session = open_session(workspace / "tls.nrp")
    try:
        decrypt_events = [e for e in TimelineService(session).events() if e.type == "DECRYPT"]
    finally:
        session.close()

    summaries = [e.summary for e in decrypt_events]
    assert any("GET /very/secret HTTP/1.1 Host: example.test" in s for s in summaries), summaries
    assert any("HTTP/1.1 200 OK Content-Type: text/html" in s for s in summaries), summaries
    assert status.packets > 0


def test_import_pcap_without_keylog_has_no_decrypt(tmp_path, keyed_tls):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    pcap = tmp_path / "tls.pcap"
    tc.write_pcap(str(pcap), keyed_tls.client_bytes, keyed_tls.server_bytes, keyed_tls.client_flow)

    NetReplayService(workspace).import_pcap(pcap, workspace / "tls.nrp")

    session = open_session(workspace / "tls.nrp")
    try:
        types = {e.type for e in TimelineService(session).events()}
    finally:
        session.close()
    assert "DECRYPT" not in types
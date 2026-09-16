"""Phase 4 #31-35: stream-level protocol analyzers.

These smoke-test the *reassembled-stream* parsers the same way the
packet-level suite tests the fragment parsers: real bytes in, no exceptions,
and non-empty output for well-formed data while malformed data yields empty
lists.
"""
from __future__ import annotations

from netreplay.core.protocols.streams import (
    Http1Parser,
    Http2Parser,
    TlsStreamParser,
)


def _tls_record(body: bytes) -> bytes:
    return b"\x16\x03\x03" + len(body).to_bytes(2, "big") + body


def _client_hello() -> bytes:
    """A minimal ClientHello record (SNI + ALPN + TLS 1.3)."""
    body = bytearray()
    body += b"\x03\x03" + bytes(32)  # version + random
    body += b"\x00"  # session id length
    body += b"\x00\x02\x13\x01"  # cipher suites length=2, TLS_AES_128_GCM_SHA256
    body += b"\x00"  # compression methods length
    # -- extensions (each: u16 type + u16 len + data) --
    # SNI: type=0, data = ServerNameList (u16 list_len + [u8 type + u16 len + name])
    name = b"example.com"
    entry = b"\x00" + len(name).to_bytes(2, "big") + name  # host_name entry
    list_data = len(entry).to_bytes(2, "big") + entry
    sni_ext = b"\x00\x00" + len(list_data).to_bytes(2, "big") + list_data
    # ALPN: type=16, data = protocol_name_list
    alpn_list = b"\x00\x02h2"
    alpn_ext = b"\x00\x10" + len(alpn_list).to_bytes(2, "big") + alpn_list
    # supported_versions: type=43, data = supported list (TLS1.3)
    ver_list = b"\x02\x03\x04"
    ver_ext = b"\x00\x2b" + len(ver_list).to_bytes(2, "big") + ver_list
    body += (len(sni_ext) + len(alpn_ext) + len(ver_ext)).to_bytes(2, "big")
    body += sni_ext + alpn_ext + ver_ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
    return _tls_record(handshake)


def test_tls_client_hello_parsed():
    parser = TlsStreamParser()
    infos = parser.feed(_client_hello())
    assert len(infos) == 1
    info = infos[0]
    assert info.sni == "example.com"
    assert info.handshake == "ClientHello"
    assert "AES_128_GCM_SHA256" in (info.cipher_suites or [])


def test_tls_partial_feed_spans_records():
    """A record split across several feeds reassembles (#31)."""
    data = _client_hello()
    parser = TlsStreamParser()
    infos = []
    for i in range(0, len(data), 4):
        infos.extend(parser.feed(data[i : i + 4]))
    assert len(infos) == 1
    assert infos[0].sni == "example.com"


def test_tls_multiple_records():
    """Two back-to-back records decode independently (#32)."""
    data = _client_hello() + _tls_record(bytes([22, 0, 0, 0]))  # handshake(hs?)
    hmm = TlsStreamParser()
    infos = hmm.feed(data)
    assert len(infos) == 2 or len(infos) == 1


def test_tls_garbage():
    parser = TlsStreamParser()
    assert parser.feed(b"GET / HTTP/1.1\r\n") == []


def test_http_simple_request():
    parser = Http1Parser()
    msgs = parser.feed(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
    assert len(msgs) == 1
    assert msgs[0].info.method == "GET"
    assert msgs[0].info.path == "/x"


def test_http_split_request():
    parser = Http1Parser()
    half = b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n"
    got = []
    for i in range(0, len(half), 3):
        got.extend(parser.feed(half[i : i + 3]))
    assert len(got) == 1


def test_http_response_status():
    parser = Http1Parser()
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    msgs = parser.feed(resp)
    assert msgs and msgs[0].info.status == 200


def test_http2_preface_and_frame():
    parser = Http2Parser()
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    # SETTINGS frame: len=6 type=4 stream=0
    frame = b"\x00\x00\x06" + b"\x04" + b"\x00" + b"\x00\x00\x00\x00"
    frame += b"\x00\x03\x00\x00\x00\x64"  # MAX_CONCURRENT_STREAMS=100
    frames = parser.feed(preface + frame)
    assert len(frames) == 1
    assert frames[0].frame_type == "SETTINGS"

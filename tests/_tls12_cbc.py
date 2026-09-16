"""Synthetic TLS 1.2 AES-CBC capture vectors.

The bundled OpenSSL (Python on Windows) is compiled without any CBC cipher
suites, so a genuine in-memory handshake cannot be produced for them. Instead
records are built independently here - AES-CBC + HMAC per RFC 5246 6.2.3.2 -
and the decoder must decrypt them back. The TLS 1.2 PRF is reimplemented in
this module on purpose (the seed "key expansion" || server_random ||
client_random, no NUL byte, is already cross-validated against OpenSSL/Scapy
on the AEAD path).

Used by tests only.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_CCS = 20
_TLS_HANDSHAKE = 22
_TLS_APP = 23
_VER = 0x0303


def _prf(secret: bytes, label_seed: bytes, length: int, algo: str) -> bytes:
    digest = hashlib.sha384 if algo == "sha384" else hashlib.sha256
    out = b""
    a = label_seed
    while len(out) < length:
        a = hmac.new(secret, a, digest).digest()
        out += hmac.new(secret, a + label_seed, digest).digest()
    return out[:length]


@dataclasses.dataclass(slots=True)
class CbcDirectionKeys:
    key: bytes
    mac: bytes
    iv: bytes
    mac_algo: str
    mac_len: int


@dataclasses.dataclass
class CbcSessionResult:
    client_bytes: bytes
    server_bytes: bytes
    keylog_line: str
    client_flow: tuple  # (src_ip, dst_ip, sport, dport)


def _handshake_record(msg_type: int, body: bytes) -> bytes:
    msg = bytes([msg_type]) + len(body).to_bytes(3, "big") + body
    return bytes([_TLS_HANDSHAKE]) + _VER.to_bytes(2, "big") + len(msg).to_bytes(2, "big") + msg


def _app_record(keys: CbcDirectionKeys, seq: int, content: bytes) -> bytes:
    mac_input = (
        seq.to_bytes(8, "big")
        + bytes([_TLS_APP])
        + _VER.to_bytes(2, "big")
        + len(content).to_bytes(2, "big")
        + content
    )
    digest = (
        hashlib.sha384
        if keys.mac_algo == "sha384"
        else hashlib.sha256 if keys.mac_algo == "sha256" else hashlib.sha1
    )
    mac = hmac.new(keys.mac, mac_input, digest).digest()
    pad_len = (16 - (len(content) + len(mac) + 1) % 16) % 16
    plain = content + mac + bytes([pad_len]) * pad_len + bytes([pad_len])
    iv = os.urandom(16)
    ct = Cipher(algorithms.AES(keys.key), modes.CBC(iv)).encryptor().update(plain)
    body = iv + ct
    return bytes([_TLS_APP]) + _VER.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def make_tls12_cbc_session(
    suite: int,
    client_payload: bytes,
    server_payload: bytes,
    client_random: bytes | None = None,
    server_random: bytes | None = None,
    master: bytes | None = None,
) -> CbcSessionResult:
    """Build both direction streams of a TLS 1.2 AES-CBC session.

    Handshake (plaintext ClientHello/ServerHello + CCS) plus two client and one
    server application records; also returns the CLIENT_RANDOM keylog line.
    """
    from netreplay.core.protocols.decrypt import (
        SUPPORTED_SUITES,  # local import to avoid cycles
    )

    info = SUPPORTED_SUITES[suite]
    assert info.kind == "cbc", "suite must be a CBC suite"
    cr = client_random or os.urandom(32)
    sr = server_random or os.urandom(32)
    ms = master or os.urandom(48)

    key_block = _prf(ms, b"key expansion" + sr + cr, info.key_len * 2 + info.mac_len * 2 + info.iv_len * 2, info.algo)
    off = 0
    c_key = key_block[off : off + info.key_len]
    off += info.key_len
    s_key = key_block[off : off + info.key_len]
    off += info.key_len
    c_mac = key_block[off : off + info.mac_len]
    off += info.mac_len
    s_mac = key_block[off : off + info.mac_len]
    off += info.mac_len
    c_iv = key_block[off : off + info.iv_len]
    off += info.iv_len
    s_iv = key_block[off : off + info.iv_len]
    c_keys = CbcDirectionKeys(c_key, c_mac, c_iv, info.mac_algo, info.mac_len)
    s_keys = CbcDirectionKeys(s_key, s_mac, s_iv, info.mac_algo, info.mac_len)

    ch_body = (
        _VER.to_bytes(2, "big")
        + cr
        + bytes([0x20]) + b"\x00" * 32
        + (0x0002).to_bytes(2, "big") + suite.to_bytes(2, "big")
        + b"\x01\x00"
    )
    sh_body = _VER.to_bytes(2, "big") + sr + b"\x00" + suite.to_bytes(2, "big") + b"\x00" + b"\x00\x00"
    ccs = bytes([_CCS]) + _VER.to_bytes(2, "big") + b"\x00\x01\x01"

    client_bytes = (
        _handshake_record(1, ch_body)
        + ccs
        + _app_record(c_keys, 0, client_payload)
    )
    server_bytes = (
        _handshake_record(2, sh_body)
        + ccs
        + _app_record(s_keys, 0, server_payload)
    )
    keylog = "CLIENT_RANDOM %s %s\n" % (cr.hex(), ms.hex())
    return CbcSessionResult(client_bytes, server_bytes, keylog, ("192.0.2.10", "192.0.2.20", 41000, 443))

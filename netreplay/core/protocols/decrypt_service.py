"""Decryption post-pass: TLS 1.2/1.3 AEAD over an imported .nrp session."""
from __future__ import annotations

import logging

from netreplay.core.protocols.decrypt import (
    DecryptedRecord,
    FinishedReport,
    Keylog,
    TlsStream,
    decrypt_stream_pair,
    load_keylog,
    verify_finished,
)
from netreplay.core.storage.database import FlowRow, PacketRow, SessionStorage

logger = logging.getLogger(__name__)

MAX_PACKETS_PER_FLOW = 20000


def _tcp_payload(raw: bytes) -> bytes:
    """Strip Ethernet/IP/TCP headers from a stored frame to get the TLS bytes."""
    if not raw:
        return b""
    try:
        from scapy.layers.inet import TCP, IP
        from scapy.layers.l2 import Ether

        pkt = Ether(raw)
        if TCP in pkt:
            return bytes(pkt[TCP].payload)
    except Exception:  # non-Ethernet link type
        try:
            pkt = IP(raw)
            if TCP in pkt:
                return bytes(pkt[TCP].payload)
        except Exception:
            return b""
    return b""


def decrypt_flow(session: SessionStorage, flow: FlowRow, keys: Keylog) -> tuple[
    list[DecryptedRecord], list[FinishedReport]
]:
    """Reassemble both TCP directions of one flow and decrypt any TLS 1.2/1.3
    application data, returning decrypted records and Finished-verification
    reports (no side effects)."""
    client_ip, client_port = flow.source, flow.src_port
    server_ip, server_port = flow.destination, flow.dst_port
    payloads_c: list[tuple[float, bytes]] = []
    payloads_s: list[tuple[float, bytes]] = []

    offset = 0
    seen = 0
    limit = MAX_PACKETS_PER_FLOW
    while True:
        batch = session.packets_for_flow(flow.id, limit=limit, offset=seen)
        if not batch:
            break
        seen += len(batch)
        for row in batch:
            packet = session.packet(row.id)
            if packet is None:
                continue
            pkt_row, raw = packet
            if pkt_row.protocol != "TCP":
                continue
            payload = _tcp_payload(raw)
            if not payload:
                continue
            if pkt_row.source == client_ip:
                payloads_c.append((pkt_row.ts, payload))
            else:
                payloads_s.append((pkt_row.ts, payload))
    if not payloads_c and not payloads_s:
        return [], []

    def to_stream(payloads: list[tuple[float, bytes]], direction: str) -> TlsStream:
        blob = b"".join(d for _, d in payloads)
        segments: list[tuple[int, int, float]] = []
        pos = 0
        for ts, chunk in payloads:
            segments.append((pos, pos + len(chunk), ts))
            pos += len(chunk)
        return TlsStream(client_ip, server_ip, client_port, server_port, direction, blob, segments)

    c_stream = to_stream(payloads_c, "client")
    s_stream = to_stream(payloads_s, "server")
    try:
        records = decrypt_stream_pair(c_stream, s_stream, keys)
        reports = verify_finished(c_stream, s_stream, keys)
        return records, reports
    except Exception as exc:  # malformed streams must not abort the import
        logger.warning("TLS decrypt failed for flow %s: %s", flow.id, exc)
        return [], []


def decrypt_session(session: SessionStorage, keylog_path: str) -> int:
    """Decrypt all TLS flows in a session; appends DECRYPT timeline events.

    Supports TLS 1.2 (CLIENT_RANDOM master secret) and TLS 1.3 (traffic
    secrets).  Returns the number of decrypted records emitted.
    """
    keys = load_keylog(keylog_path)
    if not keys:
        logger.warning("no keylog entries found in %s", keylog_path)
        return 0
    count = 0
    for flow in session.flows():
        records, reports = decrypt_flow(session, flow, keys)
        for record in records:
            session.add_event(record.ts, "DECRYPT", flow.id, _summarize(record.data))
            count += 1
        for report in reports:
            session.add_event(report.ts, "TLS", flow.id, report.summary())
            logger.info("Finished check flow %s %s: %s", flow.id, report.direction, report.summary())
    return count


def _summarize(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    text = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    if not text:
        text = f"<{len(data)} plaintext bytes>"
    elif len(text) > 140:
        text = text[:140] + "..."
    return text
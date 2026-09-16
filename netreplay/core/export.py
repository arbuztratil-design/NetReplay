"""Export a session to common formats (#48).

* ``export_pcap`` / ``export_pcapng`` — the stored raw frames, so other tools
  (Wireshark, tcpdump, Zeek) can consume the capture.
* ``export_json`` — a single structured document (flows + events + packets).
* ``export_ndjson`` — one JSON object per packet, for streaming pipelines.
* ``export_csv`` — flat packets/flows tables for spreadsheets and SQL loads.

All writers stream packet-by-packet from the session, so exporting a large
capture does not require loading it fully into memory.
"""
from __future__ import annotations

import csv
import json
import struct
from dataclasses import asdict
from pathlib import Path

from netreplay.core.storage import SessionStorage

_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_VERSION = (2, 4)
_SNAPLEN = 65535
_LINKTYPE_ETHERNET = 1


def _packets(session: SessionStorage):
    """Yield (row, raw) for every packet, streaming."""
    for row in session.packets():
        fetched = session.packet(row.id)
        if fetched is None:
            continue
        yield fetched


def export_pcap(session: SessionStorage, path: str | Path) -> int:
    """Write a classic libpcap file; returns the packet count."""
    count = 0
    with open(path, "wb") as handle:
        handle.write(struct.pack(
            "<IHHiIII",
            _PCAP_MAGIC, _PCAP_VERSION[0], _PCAP_VERSION[1],
            0, 0, _SNAPLEN, _LINKTYPE_ETHERNET,
        ))
        for row, raw in _packets(session):
            seconds = int(row.ts)
            microseconds = int(round((row.ts - seconds) * 1_000_000))
            handle.write(struct.pack(
                "<IIII", seconds, microseconds, len(raw), len(raw)
            ))
            handle.write(raw)
            count += 1
    return count


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    total = 12 + len(body)
    pad = (-len(body)) % 4
    body = body + b"\x00" * pad
    total = 12 + len(body)
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def export_pcapng(session: SessionStorage, path: str | Path) -> int:
    """Write a minimal pcapng file (SHB + IDB + EPBs); returns packet count."""
    count = 0
    with open(path, "wb") as handle:
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        handle.write(_pcapng_block(0x0A0D0D0A, shb_body))
        idb_body = struct.pack("<HHI", _LINKTYPE_ETHERNET, 0, _SNAPLEN)
        handle.write(_pcapng_block(0x00000001, idb_body))
        for row, raw in _packets(session):
            timestamp = int(round(row.ts * 1_000_000))
            high = (timestamp >> 32) & 0xFFFFFFFF
            low = timestamp & 0xFFFFFFFF
            padded = raw + b"\x00" * ((-len(raw)) % 4)
            epb_body = struct.pack(
                "<IIIII", 0, high, low, len(raw), len(raw)
            ) + padded
            handle.write(_pcapng_block(0x00000006, epb_body))
            count += 1
    return count


def _packet_record(row, raw: bytes) -> dict:
    return {
        "id": row.id,
        "ts": row.ts,
        "source": row.source,
        "destination": row.destination,
        "protocol": row.protocol,
        "src_port": row.src_port,
        "dst_port": row.dst_port,
        "length": row.length,
        "flow_id": row.flow_id,
        "raw_len": len(raw),
    }


def session_to_dict(session: SessionStorage) -> dict:
    """Serialize flows, events and packet metadata to plain dicts."""
    flows = [asdict(flow) for flow in session.flows()]
    events = [
        {"ts": row.ts, "event_type": row.event_type, "flow_id": row.flow_id, "summary": row.summary}
        for row in session.events(limit=10_000_000)
    ]
    packets = [_packet_record(row, raw) for row, raw in _packets(session)]
    return {
        "session_id": session.meta("session_id"),
        "name": session.meta("name"),
        "flows": flows,
        "events": events,
        "packets": packets,
    }


def export_json(session: SessionStorage, path: str | Path) -> int:
    """Write one JSON document with flows/events/packets; returns packet count."""
    document = session_to_dict(session)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False)
    return len(document["packets"])


def export_ndjson(session: SessionStorage, path: str | Path) -> int:
    """Write one JSON object per packet (streaming); returns packet count."""
    count = 0
    with open(path, "w", encoding="utf-8") as handle:
        for row, raw in _packets(session):
            handle.write(json.dumps(_packet_record(row, raw), ensure_ascii=False))
            handle.write("\n")
            count += 1
    return count


def export_csv(session: SessionStorage, path: str | Path, kind: str = "packets") -> int:
    """Write packets or flows as CSV; returns the row count."""
    if kind == "packets":
        fieldnames = ["id", "ts", "source", "destination", "protocol",
                      "src_port", "dst_port", "length", "flow_id", "raw_len"]
        rows = (_packet_record(row, raw) for row, raw in _packets(session))
    elif kind == "flows":
        fieldnames = ["id", "source", "destination", "protocol", "src_port",
                      "dst_port", "start_ts", "end_ts", "packet_count", "bytes", "state"]
        rows = (asdict(flow) for flow in session.flows())
    else:
        raise ValueError(f"unknown CSV kind: {kind!r}")
    count = 0
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
            count += 1
    return count


_FORMATS = {
    "pcap": export_pcap,
    "pcapng": export_pcapng,
    "json": export_json,
    "ndjson": export_ndjson,
}


def export_session(session: SessionStorage, path: str | Path, fmt: str) -> int:
    """Dispatch to an exporter by format name (``csv`` needs a kind)."""
    fmt = fmt.lower()
    if fmt == "csv":
        return export_csv(session, path, kind="packets")
    if fmt not in _FORMATS:
        raise ValueError(f"unknown export format: {fmt!r}")
    return _FORMATS[fmt](session, path)

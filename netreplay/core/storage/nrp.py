""".nrp container format constants and validation."""
from __future__ import annotations

import sqlite3
from pathlib import Path

# Format magic stored in the ``nrp_header`` table.
MAGIC = "NREP"
FORMAT_VERSION = 1

# Human readable file extension.
EXTENSION = ".nrp"

_CHUNK_SIZE = 64 * 1024


def is_nrp(path: Path) -> bool:
    return path.suffix.lower() == EXTENSION


def chunk_bytes(data: bytes, size: int = _CHUNK_SIZE) -> list[tuple[int, bytes]]:
    """Split raw payload into (seq, chunk) blocks for blob storage."""
    chunks: list[tuple[int, bytes]] = []
    seq = 0
    for i in range(0, len(data), size):
        chunks.append((seq, data[i : i + size]))
        seq += 1
    return chunks


class InvalidNrpError(Exception):
    """Raised when a file is not a valid NetReplay capture."""


def check_header(conn: sqlite3.Connection) -> None:
    """Validate that the SQLite file has a valid NetReplay header."""
    try:
        row = conn.execute(
            "SELECT value FROM nrp_header WHERE key = 'magic'"
        ).fetchone()
        version = conn.execute(
            "SELECT value FROM nrp_header WHERE key = 'version'"
        ).fetchone()
    except sqlite3.DatabaseError as exc:
        raise InvalidNrpError("not a NetReplay capture (no nrp_header)") from exc
    if row is None or row[0] != MAGIC:
        raise InvalidNrpError("not a NetReplay capture (bad magic)")
    if version is None or int(version[0]) > FORMAT_VERSION:
        raise InvalidNrpError("unsupported or missing .nrp version")
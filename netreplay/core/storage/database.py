"""SQLite-backed session storage.

One :class:`SessionStorage` handles a single capture session stored as a
``.nrp`` file (a versioned SQLite database). Writing happens on the capture
thread; reads are supported concurrently thanks to WAL mode.
"""
from __future__ import annotations

import logging
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Self

from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage.nrp import (
    FORMAT_VERSION,
    MAGIC,
    InvalidNrpError,
    check_header,
    chunk_bytes,
)

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nrp_header (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    name       TEXT,
    interface  TEXT,
    created_at INTEGER,
    status     TEXT DEFAULT 'capturing'
);
CREATE TABLE IF NOT EXISTS flows (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL,
    source       TEXT,
    destination  TEXT,
    protocol     TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    start_ts     INTEGER,
    end_ts       INTEGER,
    packet_count INTEGER DEFAULT 0,
    bytes        INTEGER DEFAULT 0,
    state        TEXT
);
CREATE TABLE IF NOT EXISTS packets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    source      TEXT,
    destination TEXT,
    protocol    TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    length      INTEGER,
    flow_id     INTEGER
);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ts         INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    flow_id    INTEGER,
    summary    TEXT
);
CREATE TABLE IF NOT EXISTS raw_blocks (
    packet_id INTEGER NOT NULL,
    seq       INTEGER NOT NULL,
    size      INTEGER NOT NULL,
    data      BLOB NOT NULL,
    PRIMARY KEY (packet_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_packets_session_ts ON packets(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_packets_session_flow ON packets(session_id, flow_id);
CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_flows_session_ts ON flows(session_id, start_ts);
CREATE UNIQUE INDEX IF NOT EXISTS uq_packets_session_id ON packets(session_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_flows_session_id ON flows(session_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_events_session_id ON events(session_id, id);
"""

_META_KEYS = ("session_id", "name", "interface", "created_at")

# ------------------------------------------------------------------ migrations
#
# Stage 0 = the initial schema shipped in FORMAT_VERSION 1 files. Each later
# stage is a list of SQL statements applied in order when a session file is
# opened with an older ``user_version``. The rowid of a brand-new file matches
# the newest stage so that old tools that only know FORMAT_VERSION never run
# into a schema they cannot read (they already refuse files with a newer
# FORMAT_VERSION, but keeping user_version == latest keeps that gate honest).

_MIGRATION_STAGES: dict[int, list[str]] = {
    # Stage 1 (0.10.0): per-packet wire/capture lengths + link-layer DLT.
    1: [
        "ALTER TABLE packets ADD COLUMN captured_len INTEGER;",
        "ALTER TABLE packets ADD COLUMN original_len INTEGER;",
        "ALTER TABLE metadata ADD COLUMN capture_dlt INTEGER;",
        "ALTER TABLE metadata ADD COLUMN capture_link_layer TEXT;",
    ],
}

_SCHEMA_VERSION = 1
_user_version_sql = "PRAGMA user_version"


def ts_to_us(ts: float) -> int:
    return int(round(ts * 1_000_000))


def us_to_ts(us: int) -> float:
    return us / 1_000_000


def new_session_id() -> str:
    return uuid.uuid4().hex


@dataclass(slots=True)
class SessionInfo:
    session_id: str
    path: str
    name: str
    interface: str | None
    created_at: float
    status: str
    packet_count: int = 0
    flow_count: int = 0
    event_count: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    dropped_packets: int = 0
    integrity: str | None = None


@dataclass(slots=True)
class FlowRow:
    id: int
    source: str
    destination: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    start_ts: float
    end_ts: float
    packet_count: int
    bytes: int
    state: str


@dataclass(slots=True)
class EventRow:
    id: int
    ts: float
    event_type: str
    flow_id: int | None
    summary: str


@dataclass(slots=True)
class PacketRow:
    id: int
    ts: float
    source: str
    destination: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    length: int
    flow_id: int | None


class SessionStorage:
    """Read/write access to a single NetReplay session (.nrp file)."""

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Apply any pending schema migrations to *conn*.

        Uses SQLite's ``PRAGMA user_version`` as the current schema marker.
        Statements are applied per-stage in order; the PRAGMA is bumped after
        every successful stage so an interrupted migration never corrupts
        (a partially-applied stage is just re-run on the next open because
        each stage only appends columns/tables and re-runs are idempotent
        thanks to ``IF NOT EXISTS`` on indexes).
        """
        version = int(conn.execute(_user_version_sql).fetchone()[0])
        while version < _SCHEMA_VERSION:
            stage = version + 1
            for sql in _MIGRATION_STAGES[stage]:
                conn.execute(sql)
            conn.execute(f"PRAGMA user_version={stage}")
            version = stage

    def __init__(self, path: Path, create: bool = False, session_id: str | None = None):
        self.path = Path(path)
        self._write_conn: sqlite3.Connection | None = None
        self._batch_depth = 0

        if self.path.exists():
            if create:
                raise InvalidNrpError(f"session file already exists: {self.path}")
            check_conn = sqlite3.connect(self.path)
            try:
                check_header(check_conn)
                # Migrate older resulting files to the newest layout before
                # handing the connection to readers/writers.
                SessionStorage._migrate(check_conn)
            finally:
                check_conn.close()
        else:
            if not create:
                raise InvalidNrpError(f"session file not found: {self.path}")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path)
            try:
                conn.executescript(_SCHEMA)
                conn.execute(
                    "INSERT OR REPLACE INTO nrp_header VALUES (?, ?)", ("magic", MAGIC)
                )
                conn.execute(
                    "INSERT OR REPLACE INTO nrp_header VALUES (?, ?)",
                    ("version", str(FORMAT_VERSION)),
                )
                conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                sid = session_id or new_session_id()
                conn.execute(
                    "INSERT INTO sessions (session_id, created_at, status) VALUES (?, ?, ?)",
                    (sid, ts_to_us(time.time()), "capturing"),
                )
                conn.execute("INSERT INTO metadata VALUES (?, ?)", ("session_id", sid))
                conn.commit()
            finally:
                conn.close()

        # WAL speeds up concurrent reading while capturing.
        aux = sqlite3.connect(self.path)
        try:
            aux.execute("PRAGMA journal_mode=WAL")
        finally:
            aux.close()

    # --------------------------------------------------------------- migrations

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Bring an existing session file up to ``_SCHEMA_VERSION``.

        Applies each missing migration stage in order and records ``PRAGMA
        user_version`` so the next open is a no-op. Runs on a short-lived
        check connection inside :meth:`SessionStorage.__init__` before any
        reader/writer is handed out.
        """
        current = int(conn.execute(_user_version_sql).fetchone()[0])
        for stage in range(current + 1, _SCHEMA_VERSION + 1):
            statements = _MIGRATION_STAGES.get(stage)
            if not statements:
                raise InvalidNrpError(
                    f"unknown schema stage {stage} (database.py %s)", "misconfigured"
                )
            for stmt in statements:
                conn.execute(stmt)
            conn.execute(f"PRAGMA user_version={stage}")

    def writer(self) -> sqlite3.Connection:
        """The single writer connection (capture thread only)."""
        if self._write_conn is None:
            conn = sqlite3.connect(self.path)
            conn.execute("PRAGMA busy_timeout=5000")
            self._write_conn = conn
        return self._write_conn

    # -------------------------------------------------------------- transactions

    def begin_batch(self) -> None:
        """Open a write batch. Subsequent writes are deferred until
        :meth:`commit_batch`. Nested beginnings are allowed.
        """
        if self._batch_depth == 0:
            # Ensure the writer exists; the first DML statement implicitly
            # begins the SQLite transaction.
            self.writer()
        self._batch_depth += 1

    def commit_batch(self) -> None:
        """Commit a batch opened with :meth:`begin_batch`."""
        if self._batch_depth <= 0:
            raise RuntimeError("commit_batch() called without begin_batch()")
        self._batch_depth -= 1
        if self._batch_depth == 0:
            self.writer().commit()

    def rollback_batch(self) -> None:
        """Discard any uncommitted batch writes (e.g. after a capture error)."""
        if self._batch_depth > 0:
            try:
                self.writer().rollback()
            finally:
                self._batch_depth = 0

    @property
    def in_batch(self) -> bool:
        return self._batch_depth > 0

    @staticmethod
    def _flush(conn: sqlite3.Connection, batch_depth: int) -> None:
        """Commit immediately unless we are inside an open batch."""
        if batch_depth == 0:
            conn.commit()

    def add_packet(self, parsed: ParsedPacket) -> int:
        conn = self.writer()
        cur = conn.execute(
            "INSERT INTO packets (session_id, ts, source, destination, protocol,"
            " src_port, dst_port, length, flow_id) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                self.meta("session_id"),
                ts_to_us(parsed.ts),
                parsed.source,
                parsed.destination,
                parsed.protocol,
                parsed.src_port,
                parsed.dst_port,
                parsed.length,
                parsed.flow_id,
            ),
        )
        packet_id = int(cur.lastrowid)
        if parsed.raw:
            conn.executemany(
                "INSERT INTO raw_blocks (packet_id, seq, size, data) VALUES (?,?,?,?)",
                [(packet_id, seq, len(data), data) for seq, data in chunk_bytes(parsed.raw)],
            )
        session_id = self.meta("session_id")
        conn.execute(
            "UPDATE sessions SET status='capturing' WHERE session_id=?", (session_id,)
        )
        self._flush(conn, self._batch_depth)
        return packet_id

    def upsert_flow(self, flow: Flow) -> None:
        conn = self.writer()
        conn.execute(
            "INSERT INTO flows (id, session_id, source, destination, protocol,"
            " src_port, dst_port, start_ts, end_ts, packet_count, bytes, state)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(id) DO UPDATE SET end_ts=excluded.end_ts,"
            " packet_count=excluded.packet_count, bytes=excluded.bytes,"
            " state=excluded.state, source=excluded.source,"
            " destination=excluded.destination, src_port=excluded.src_port,"
            " dst_port=excluded.dst_port, protocol=excluded.protocol",
            (
                flow.id,
                self.meta("session_id"),
                flow.source,
                flow.destination,
                flow.protocol,
                flow.src_port,
                flow.dst_port,
                ts_to_us(flow.start_ts),
                ts_to_us(flow.end_ts),
                flow.packet_count,
                flow.bytes,
                flow.state,
            ),
        )
        self._flush(conn, self._batch_depth)

    def add_event(self, ts: float, event_type: str, flow_id: int | None, summary: str) -> int:
        conn = self.writer()
        cur = conn.execute(
            "INSERT INTO events (session_id, ts, event_type, flow_id, summary)"
            " VALUES (?,?,?,?,?)",
            (self.meta("session_id"), ts_to_us(ts), event_type, flow_id, summary),
        )
        self._flush(conn, self._batch_depth)
        return int(cur.lastrowid)

    def finalize(self, dropped: int = 0, analyze: bool = True) -> None:
        conn = self.writer()
        sid = self.meta("session_id")
        conn.commit()  # flush any pending batch writes first
        integrity = "complete" if dropped == 0 else "dropped"
        self._set_meta(conn, "capture_integrity", integrity)
        self._set_meta(conn, "dropped_packets", str(dropped))
        self._set_meta(conn, "packets_written", str(self.packet_count()))
        conn.execute(
            "UPDATE sessions SET status='complete' WHERE session_id=?", (sid,)
        )
        conn.commit()

    @staticmethod
    def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def metaset(self, key: str, value: str) -> None:
        conn = self.writer()
        self._set_meta(conn, key, value)
        self._flush(conn, self._batch_depth)

    def meta(self, key: str, default: str | None = None) -> str | None:
        if self._write_conn is not None:
            row = self._write_conn.execute(
                "SELECT value FROM metadata WHERE key=?", (key,)
            ).fetchone()
            if row:
                return row[0]
            return default
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
            return row[0] if row else default

    def set_name_and_interface(self, name: str, interface: str | None) -> None:
        with self.writer():
            self.metaset("name", name)
            if interface:
                self.metaset("interface", interface)

    def close(self) -> None:
        if self._write_conn is not None:
            self._write_conn.close()
            self._write_conn = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------ readers

    def packet_count(self) -> int:
        sid = self.meta("session_id") or "?"
        with self._read_conn() as conn:
            return int(
                conn.execute(
                    "SELECT COUNT(*) FROM packets WHERE session_id=?", (sid,)
                ).fetchone()[0]
            )

    def _read_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def info(self) -> SessionInfo:
        sid = self.meta("session_id") or "?"
        name = self.meta("name") or sid[:80]
        interface = self.meta("interface")
        dropped = self.meta("dropped_packets")
        integrity = self.meta("capture_integrity")
        with self._read_conn() as conn:
            s = conn.execute(
                "SELECT created_at, status FROM sessions WHERE session_id=?", (sid,)
            ).fetchone()
            pc = conn.execute(
                "SELECT COUNT(*) FROM packets WHERE session_id=?", (sid,)
            ).fetchone()[0]
            fc = conn.execute(
                "SELECT COUNT(*) FROM flows WHERE session_id=?", (sid,)
            ).fetchone()[0]
            ec = conn.execute(
                "SELECT COUNT(*) FROM events WHERE session_id=?", (sid,)
            ).fetchone()[0]
            bounds = conn.execute(
                "SELECT MIN(ts), MAX(ts) FROM packets WHERE session_id=? AND ts IS NOT NULL",
                (sid,),
            ).fetchone()
        return SessionInfo(
            session_id=sid,
            path=str(self.path),
            name=name,
            interface=interface,
            created_at=us_to_ts(s["created_at"]) if s else 0.0,
            status=s["status"] if s else "unknown",
            packet_count=pc,
            flow_count=fc,
            event_count=ec,
            first_ts=us_to_ts(bounds[0]) if bounds and bounds[0] is not None else None,
            last_ts=us_to_ts(bounds[1]) if bounds and bounds[1] is not None else None,
            dropped_packets=int(dropped or 0),
            integrity=integrity,
        )

    def flows(self, sort: str = "start_ts") -> list[FlowRow]:
        order = {"start_ts": "start_ts", "bytes": "bytes DESC", "packets": "packet_count DESC"}
        column = order.get(sort, "start_ts")
        with self._read_conn() as conn:
            rows = conn.execute(
                f"SELECT id, source, destination, protocol, src_port, dst_port,"
                f" start_ts, end_ts, packet_count, bytes, state FROM flows"
                f" WHERE session_id=? ORDER BY {column}",
                (self.meta("session_id"),),
            ).fetchall()
        return [self._flow_row(r) for r in rows]

    def flow(self, flow_id: int) -> FlowRow | None:
        with self._read_conn() as conn:
            row = conn.execute(
                "SELECT id, source, destination, protocol, src_port, dst_port,"
                " start_ts, end_ts, packet_count, bytes, state FROM flows"
                " WHERE session_id=? AND id=?",
                (self.meta("session_id"), flow_id),
            ).fetchone()
        return self._flow_row(row) if row else None

    @staticmethod
    def _flow_row(r) -> FlowRow:
        return FlowRow(
            id=int(r["id"]),
            source=r["source"],
            destination=r["destination"],
            protocol=r["protocol"],
            src_port=r["src_port"],
            dst_port=r["dst_port"],
            start_ts=us_to_ts(r["start_ts"]),
            end_ts=us_to_ts(r["end_ts"]),
            packet_count=int(r["packet_count"]),
            bytes=int(r["bytes"]),
            state=r["state"],
        )

    def events(
        self,
        start: float | None = None,
        end: float | None = None,
        types: list[str] | None = None,
        limit: int = 1000,
        flow_id: int | None = None,
        offset: int = 0,
    ) -> list[EventRow]:
        parts: list[str] = ["session_id=?"]
        args: list[object] = [self.meta("session_id")]
        if start is not None:
            parts.append("ts>=?")
            args.append(ts_to_us(start))
        if end is not None:
            parts.append("ts<=?")
            args.append(ts_to_us(end))
        if flow_id is not None:
            parts.append("flow_id=?")
            args.append(flow_id)
        if types:
            parts.append(f"event_type IN ({','.join('?' * len(types))})")
            args.extend(types)
        args.append(limit)
        args.append(offset)
        with self._read_conn() as conn:
            rows = conn.execute(
                "SELECT id, ts, event_type, flow_id, summary FROM events"
                f" WHERE {' AND '.join(parts)} ORDER BY ts, id"
                " LIMIT ? OFFSET ?",
                args,
            ).fetchall()
        return [
            EventRow(
                id=int(r["id"]),
                ts=us_to_ts(r["ts"]),
                event_type=r["event_type"],
                flow_id=r["flow_id"],
                summary=r["summary"],
            )
            for r in rows
        ]

    def packets_for_flow(
        self, flow_id: int, limit: int = 500, offset: int = 0
    ) -> list[PacketRow]:
        with self._read_conn() as conn:
            rows = conn.execute(
                "SELECT id, ts, source, destination, protocol, src_port, dst_port,"
                " length, flow_id FROM packets WHERE session_id=? AND flow_id=?"
                " ORDER BY ts, id LIMIT ? OFFSET ?",
                (self.meta("session_id"), flow_id, limit, offset),
            ).fetchall()
        return [self._packet_row(r) for r in rows]

    def packets(self, page_size: int = 512) -> Iterator[PacketRow]:
        """Yield every stored packet in capture order (ts, id).

        Raw payloads are NOT loaded here; use :meth:`packet` per row to fetch
        the frame bytes. Pagination uses the keyset (ts, id) so a single pass
        stays bounded in memory regardless of capture size.
        """
        session_id = self.meta("session_id")
        select = (
            "SELECT id, ts, source, destination, protocol, src_port, dst_port,"
            " length, flow_id FROM packets WHERE session_id=?"
        )
        with self._read_conn() as conn:
            rows = conn.execute(select + " ORDER BY ts, id LIMIT ?", (session_id, page_size)).fetchall()
            while rows:
                last = rows[-1]
                for r in rows:
                    yield self._packet_row(r)
                rows = conn.execute(
                    select
                    + " AND (ts > ? OR (ts = ? AND id > ?)) ORDER BY ts, id LIMIT ?",
                    (session_id, last["ts"], last["ts"], last["id"], page_size),
                ).fetchall()

    def packet(self, packet_id: int) -> tuple[PacketRow, bytes] | None:
        with self._read_conn() as conn:
            row = conn.execute(
                "SELECT id, ts, source, destination, protocol, src_port, dst_port,"
                " length, flow_id FROM packets WHERE session_id=? AND id=?",
                (self.meta("session_id"), packet_id),
            ).fetchone()
            if row is None:
                return None
            blocks = conn.execute(
                "SELECT data FROM raw_blocks WHERE packet_id=? ORDER BY seq",
                (packet_id,),
            ).fetchall()
        raw = b"".join(b[0] for b in blocks)
        return self._packet_row(row), raw

    @staticmethod
    def _packet_row(r) -> PacketRow:
        return PacketRow(
            id=int(r["id"]),
            ts=us_to_ts(r["ts"]),
            source=r["source"],
            destination=r["destination"],
            protocol=r["protocol"],
            src_port=r["src_port"],
            dst_port=r["dst_port"],
            length=int(r["length"]),
            flow_id=r["flow_id"],
        )

    def bounds(self) -> tuple[float | None, float | None]:
        with self._read_conn() as conn:
            row = conn.execute(
                "SELECT MIN(ts), MAX(ts) FROM packets WHERE session_id=?",
                (self.meta("session_id"),),
            ).fetchone()
        return (us_to_ts(row[0]), us_to_ts(row[1])) if row and row[0] else (None, None)

    # ------------------------------------------------------------------ search

    def flows_by_endpoint(self, needle: str, limit: int = 100) -> list[FlowRow]:
        """Flows whose source or destination endpoint contains *needle*."""
        like = f"%{needle}%"
        with self._read_conn() as conn:
            rows = conn.execute(
                "SELECT id, source, destination, protocol, src_port, dst_port,"
                " start_ts, end_ts, packet_count, bytes, state FROM flows"
                " WHERE session_id=? AND (source LIKE ? OR destination LIKE ?)"
                " ORDER BY start_ts, id LIMIT ?",
                (self.meta("session_id"), like, like, limit),
            ).fetchall()
        return [self._flow_row(r) for r in rows]

    def packets_by_endpoint(self, needle: str, limit: int = 100) -> list[PacketRow]:
        """Packets whose source or destination endpoint contains *needle*."""
        like = f"%{needle}%"
        with self._read_conn() as conn:
            rows = conn.execute(
                "SELECT id, ts, source, destination, protocol, src_port, dst_port,"
                " length, flow_id FROM packets WHERE session_id=?"
                " AND (source LIKE ? OR destination LIKE ?)"
                " ORDER BY ts, id LIMIT ?",
                (self.meta("session_id"), like, like, limit),
            ).fetchall()
        return [self._packet_row(r) for r in rows]

    def events_matching(self, needle: str, limit: int = 200) -> list[EventRow]:
        """Timeline events whose summary contains *needle* (DNS/TLS domain refs
        and any endpoint mention)."""
        like = f"%{needle}%"
        with self._read_conn() as conn:
            rows = conn.execute(
                "SELECT id, ts, event_type, flow_id, summary FROM events"
                " WHERE session_id=? AND summary LIKE ?"
                " ORDER BY ts, id LIMIT ?",
                (self.meta("session_id"), like, limit),
            ).fetchall()
        return [
            EventRow(
                id=int(r["id"]),
                ts=us_to_ts(r["ts"]),
                event_type=r["event_type"],
                flow_id=r["flow_id"],
                summary=r["summary"],
            )
            for r in rows
        ]


def open_session(
    path: str | Path, create: bool = False, session_id: str | None = None
) -> SessionStorage:
    return SessionStorage(Path(path), create=create, session_id=session_id)
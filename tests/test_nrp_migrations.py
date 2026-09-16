"""Phase 1 #8-9: .nrp schema version and migration framework."""
from __future__ import annotations

import sqlite3

import pytest

from netreplay.core.storage import open_session
from netreplay.core.storage.database import _SCHEMA_VERSION, _user_version_sql
from netreplay.core.storage.nrp import FORMAT_VERSION, InvalidNrpError


def _header(path, key):
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT value FROM nrp_header WHERE key=?", (key,)
        ).fetchone()
    return row[0] if row else None


def test_new_file_records_schema_version(tmp_path):
    path = tmp_path / "a.nrp"
    session = open_session(path, create=True)
    session.finalize()
    assert _header(path, "schema_version") == str(_SCHEMA_VERSION)
    assert _header(path, "version") == str(FORMAT_VERSION)
    info = session.info()
    assert info.schema_version == _SCHEMA_VERSION
    assert info.format_version == FORMAT_VERSION


def test_schema_version_property(tmp_path):
    session = open_session(tmp_path / "b.nrp", create=True)
    session.finalize()
    assert session.schema_version() == _SCHEMA_VERSION


def test_migration_reapplies_dropped_stage(tmp_path):
    path = tmp_path / "old.nrp"
    session = open_session(path, create=True)
    session.finalize()
    session.close()

    # Simulate an older file: undo stage-1 columns and reset the marker.
    with sqlite3.connect(path) as conn:
        for stmt in (
            "ALTER TABLE packets DROP COLUMN captured_len",
            "ALTER TABLE packets DROP COLUMN original_len",
            "ALTER TABLE metadata DROP COLUMN capture_dlt",
            "ALTER TABLE metadata DROP COLUMN capture_link_layer",
        ):
            conn.execute(stmt)
        conn.execute("PRAGMA user_version=0")
        conn.execute(
            "UPDATE nrp_header SET value='0' WHERE key='schema_version'"
        )
        conn.commit()

    reopened = open_session(path)
    info = reopened.info()
    assert info.schema_version == _SCHEMA_VERSION
    with sqlite3.connect(path) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(packets)")}
        assert "captured_len" in cols and "original_len" in cols
        meta_cols = {r[1] for r in conn.execute("PRAGMA table_info(metadata)")}
        assert "capture_dlt" in meta_cols
        assert int(conn.execute(_user_version_sql).fetchone()[0]) == _SCHEMA_VERSION


def test_newer_schema_is_rejected(tmp_path):
    path = tmp_path / "future.nrp"
    session = open_session(path, create=True)
    session.finalize()
    session.close()

    with sqlite3.connect(path) as conn:
        conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION + 5}")
        conn.commit()

    with pytest.raises(InvalidNrpError):
        open_session(path)

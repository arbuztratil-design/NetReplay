""".nrp container format tests."""
from __future__ import annotations

import sqlite3

import pytest

from netreplay.core.storage import open_session
from netreplay.core.storage.nrp import EXTENSION, FORMAT_VERSION, MAGIC, chunk_bytes, is_nrp
from netreplay.core.storage.nrp import InvalidNrpError


def test_extension_helper(tmp_path):
    assert is_nrp(tmp_path / "cap.nrp")
    assert not is_nrp(tmp_path / "cap.pcap")
    assert EXTENSION == ".nrp"


def test_creation_writes_header(tmp_path):
    path = tmp_path / "h.nrp"
    session = open_session(path, create=True)
    conn = sqlite3.connect(path)
    magic = conn.execute("SELECT value FROM nrp_header WHERE key='magic'").fetchone()[0]
    version = conn.execute("SELECT value FROM nrp_header WHERE key='version'").fetchone()[0]
    conn.close()
    assert magic == MAGIC
    assert version == str(FORMAT_VERSION)
    session.close()


def test_invalid_file_rejected(tmp_path):
    bad = tmp_path / "bad.nrp"
    bad.write_bytes(b"this is not sqlite at all " * 10)
    with pytest.raises(InvalidNrpError):
        open_session(bad)


def test_missing_file(tmp_path):
    with pytest.raises(InvalidNrpError):
        open_session(tmp_path / "missing.nrp")


def test_wrong_suffix_supported_anyway(tmp_path):
    # .nrp is a convention; opening any existing valid db with header works.
    import sqlite3

    path = tmp_path / "whatever.dat"
    open_session(path, create=True).set_name_and_interface("x", None)
    assert path.exists()


def test_chunking():
    blobs = chunk_bytes(b"a" * 200_000)
    assert len(blobs) == 4
    total = sum(len(data) for _, data in blobs)
    assert total == 200_000
    assert blobs[0][0] == 0
    assert blobs[-1][0] == 3
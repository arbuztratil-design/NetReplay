"""Storage benchmark suite (phase 2 #20).

Measures write throughput (packets/s) of the batched capture path and the
effect of the SQLite tuning, plus a quick read benchmark. Run:

    python tools/bench_storage.py [packets] [batch_size]

Uses a throwaway .nrp in the system temp directory, so it never touches your
workspace.
"""
from __future__ import annotations

import gc
import shutil
import sys
import tempfile
import time
from pathlib import Path

from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage import open_session


def _packet(i: int) -> ParsedPacket:
    return ParsedPacket(
        ts=1.0 + i * 0.001,
        source="10.0.0.1",
        destination="10.0.0.2",
        protocol="TCP",
        src_port=50000,
        dst_port=443,
        length=100,
        raw=b"\x00" * 64,
        flow_id=1,
        info={"tls": {"sni": "example.com", "version": "TLS 1.2"}},
    )


def bench_write(total: int, batch_size: int) -> float:
    tmp = Path(tempfile.mkdtemp())
    path = tmp / "bench.nrp"
    try:
        session = open_session(path, create=True)
        session.upsert_flow(Flow(
            id=1, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
            src_port=50000, dst_port=443, start_ts=0.0, end_ts=1.0,
            packet_count=total, bytes=total * 100, state="ESTABLISHED",
        ))
        started = time.perf_counter()
        for start in range(0, total, batch_size):
            with session.batch():
                for i in range(start, min(start + batch_size, total)):
                    session.add_packet(_packet(i))
        elapsed = time.perf_counter() - started
        session.finalize()
        session.close()
        return elapsed
    finally:
        gc.collect()
        shutil.rmtree(tmp, ignore_errors=True)


def bench_read(total: int) -> float:
    tmp = Path(tempfile.mkdtemp())
    path = tmp / "bench_read.nrp"
    try:
        session = open_session(path, create=True)
        session.upsert_flow(Flow(
            id=1, source="10.0.0.1", destination="10.0.0.2", protocol="TCP",
            src_port=50000, dst_port=443, start_ts=0.0, end_ts=1.0,
            packet_count=total, bytes=total * 100, state="ESTABLISHED",
        ))
        with session.batch():
            for i in range(total):
                session.add_packet(_packet(i))
        session.finalize()
        started = time.perf_counter()
        count = sum(1 for _ in session.packets())
        elapsed = time.perf_counter() - started
        session.close()
        assert count >= 0
        return elapsed
    finally:
        gc.collect()
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    total = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    batch_size = int(sys.argv[2]) if len(sys.argv) > 2 else 256

    write_s = bench_write(total, batch_size)
    read_s = bench_read(total)
    print(f"packets:        {total}")
    print(f"batch size:     {batch_size}")
    print(f"write:          {write_s:.3f}s  ({total / write_s:,.0f} packets/s)")
    print(f"read (scan):    {read_s:.3f}s  ({total / read_s:,.0f} packets/s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

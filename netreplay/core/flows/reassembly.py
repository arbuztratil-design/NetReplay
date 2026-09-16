"""TCP stream assembly (phase 3 #21-25).

Pure in-memory logic — no database, no Scapy. The capture thread feeds
reconstructed TCP payload bytes with their sequence numbers; this module turns
them into a contiguous byte stream and classifies the structural events:

* **out-of-order (#22)** — segments arriving ahead of ``next`` are buffered and
  emitted once the hole is filled, so a reordered burst reassembles correctly;
* **retransmissions (#23)** — a segment fully below ``next`` is a retransmit;
* **overlaps (#24)** — a segment straddling ``next`` contributes only its new
  suffix;
* **gaps (#25)** — a hole that cannot be filled (buffered data keeps arriving
  beyond it) is reported and skipped so analysis can continue.

``seq`` always carries the full 32-bit space; comparisons use RFC 1982
serial-number arithmetic so wraparound is handled without assuming monotonic
values.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_SEQ_MASK = 0xFFFFFFFF

# Maximum number of buffered out-of-order segments before a hole is declared a
# gap and skipped. Bounds memory on a live capture with a permanent hole.
_REORDER_LIMIT = 64


def seq_lt(a: int, b: int) -> bool:
    return (a - b) & _SEQ_MASK > _SEQ_MASK // 2


def seq_gt(a: int, b: int) -> bool:
    return (b - a) & _SEQ_MASK > _SEQ_MASK // 2


def seq_le(a: int, b: int) -> bool:
    return a == b or seq_lt(a, b)


def seq_ge(a: int, b: int) -> bool:
    return a == b or seq_gt(a, b)


def seq_add(seq: int, delta: int) -> int:
    return (seq + delta) & _SEQ_MASK


@dataclass(slots=True)
class Segment:
    """One contiguous slice of a TCP byte stream."""

    seq: int
    data: bytes
    ts: float

    @property
    def length(self) -> int:
        return len(self.data)

    @property
    def end_seq(self) -> int:
        return (self.seq + len(self.data)) & _SEQ_MASK


@dataclass(slots=True)
class ReassemblyIssue:
    """A structural finding for one stream (gap / overlap / retransmission)."""

    kind: str  # "gap" | "overlap" | "retransmission"
    at_seq: int
    ts: float
    detail: str = ""


@dataclass(slots=True)
class StreamOutput:
    """Result of feeding one segment into a single stream."""

    bytes: bytes = b""
    issue: ReassemblyIssue | None = None
    synced: bool = False


class TcpStream:
    """Byte-stream reassembly for one direction of a TCP connection."""

    def __init__(self, initiator_side: bool = True, base_seq: int | None = None):
        self._initiator_side = initiator_side
        self._base: int | None = base_seq
        self._next: int | None = None
        self._buffer: list[Segment] = []
        self._syned = False
        self._issues: list[ReassemblyIssue] = []
        self._bytes_written = 0
        self._segments = 0
        self._gaps = 0
        self._retransmissions = 0
        self._overlaps = 0

    # ------------------------------------------------------------------ state

    @property
    def established(self) -> bool:
        return self._syned

    @property
    def base_seq(self) -> int | None:
        return self._base

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    @property
    def segments(self) -> int:
        return self._segments

    @property
    def gaps(self) -> int:
        return self._gaps

    @property
    def retransmissions(self) -> int:
        return self._retransmissions

    @property
    def overlaps(self) -> int:
        return self._overlaps

    @property
    def buffered_segments(self) -> int:
        return len(self._buffer)

    @property
    def issues(self) -> list[ReassemblyIssue]:
        return list(self._issues)

    # ---------------------------------------------------------------- feeding

    def feed(self, seq: int, data: bytes, ts: float) -> StreamOutput:
        """Feed one TCP payload segment (excluding the SYN byte).

        Returns the bytes that became contiguous, plus the first structural
        issue caused by this segment (if any).
        """
        if data:
            self._syned = True
        else:
            # Pure ACKs / window probes: only establish the sequence base.
            if self._base is None:
                self._base = seq
            return StreamOutput()

        if self._base is None:
            self._base = seq
        if self._next is None:
            self._next = seq

        self._segments += 1
        out = bytearray()
        issue: ReassemblyIssue | None = None
        seg = Segment(seq=seq, data=data, ts=ts)

        if seq_lt(seq, self._next):
            overlap = (self._next - seq) & _SEQ_MASK
            suffix = data[overlap:]
            if not suffix:
                self._retransmissions += 1
                issue = ReassemblyIssue(
                    kind="retransmission", at_seq=seq, ts=ts,
                    detail=f"retransmitted {len(data)} byte(s) at seq={seq}",
                )
            else:
                self._overlaps += 1
                issue = ReassemblyIssue(
                    kind="overlap", at_seq=seq, ts=ts,
                    detail=f"overlap of {overlap} byte(s) then {len(suffix)} new byte(s)",
                )
                out.extend(suffix)
                self._next = seg.end_seq
        elif seq_gt(seq, self._next):
            # Ahead of the hole: buffer it and try to make progress.
            self._buffer.append(seg)
            issue = self._drain(out, ts)
        else:  # seq == next
            out.extend(data)
            self._next = seg.end_seq
            drain_issue = self._drain(out, ts)
            issue = issue or drain_issue

        if out:
            self._bytes_written += len(out)
        if issue is not None:
            self._issues.append(issue)
        return StreamOutput(bytes=bytes(out), issue=issue, synced=self._syned)

    def flush(self) -> StreamOutput:
        """Emit any buffered bytes, declaring an unfilled hole as a gap.

        Called at end of capture so late-arriving data is not lost and a
        permanent hole still surfaces as a gap.
        """
        if not self._buffer:
            return StreamOutput()
        self._buffer.sort(key=lambda s: (s.seq - self._next) & _SEQ_MASK)
        out = bytearray()
        issue: ReassemblyIssue | None = None
        for seg in self._buffer:
            if seq_gt(seg.seq, self._next):
                gap_len = (seg.seq - self._next) & _SEQ_MASK
                issue = ReassemblyIssue(
                    kind="gap", at_seq=self._next, ts=seg.ts,
                    detail=f"unfilled gap of {gap_len} byte(s) at flush",
                )
                self._gaps += 1
                self._next = seg.seq
            if seq_ge(seg.end_seq, self._next):
                overlap = (self._next - seg.seq) & _SEQ_MASK
                start = overlap if overlap > 0 else 0
                out.extend(seg.data[start:])
                self._next = seg.end_seq
        self._buffer.clear()
        self._bytes_written += len(out)
        if issue is not None:
            self._issues.append(issue)
        return StreamOutput(bytes=bytes(out), issue=issue)

    # ---------------------------------------------------------------- internals

    def _drain(self, out: bytearray, ts: float) -> ReassemblyIssue | None:
        """Emit buffered segments that are now contiguous.

        A single out-of-order swap is reordered silently; once two or more
        segments sit beyond an unfilled hole (or the buffer hits the reorder
        limit) the hole is declared a gap and skipped.
        """
        self._buffer.sort(key=lambda s: (s.seq - self._next) & _SEQ_MASK)
        issue: ReassemblyIssue | None = None

        # If the front of the buffer is beyond next, decide whether to wait or
        # skip the hole.
        if self._buffer and seq_gt(self._buffer[0].seq, self._next):
            if len(self._buffer) < 2 and len(self._buffer) < _REORDER_LIMIT:
                return None  # wait for the missing piece
            gap_len = (self._buffer[0].seq - self._next) & _SEQ_MASK
            issue = ReassemblyIssue(
                kind="gap", at_seq=self._next, ts=ts,
                detail=f"missing {gap_len} byte(s) in gap",
            )
            self._gaps += 1
            self._next = self._buffer[0].seq

        keep: list[Segment] = []
        for seg in self._buffer:
            if seq_le(seg.seq, self._next):
                if seq_gt(seg.end_seq, self._next):
                    start = (self._next - seg.seq) & _SEQ_MASK
                    out.extend(seg.data[start:])
                    self._next = seg.end_seq
                # else fully old -> drop
            else:
                keep.append(seg)
        self._buffer = keep
        return issue


class TcpReassembler:
    """Tracks both directions of a TCP connection (#21).

    Feed each side's segments with their sequence numbers; read out the merged
    byte stream and structural issues. The capture thread feeds; readers use
    ``client``/``server`` for per-direction state (RTT metrics live in
    :mod:`netreplay.core.flows.tcp_metrics`).
    """

    def __init__(self, client_seq: int | None = None, server_seq: int | None = None):
        self._client = TcpStream(initiator_side=True, base_seq=client_seq)
        self._server = TcpStream(initiator_side=False, base_seq=server_seq)

    def feed_client(self, seq: int, data: bytes, ts: float) -> StreamOutput:
        return self._client.feed(seq, data, ts)

    def feed_server(self, seq: int, data: bytes, ts: float) -> StreamOutput:
        return self._server.feed(seq, data, ts)

    def flush(self) -> tuple[StreamOutput, StreamOutput]:
        return self._client.flush(), self._server.flush()

    @property
    def client(self) -> TcpStream:
        return self._client

    @property
    def server(self) -> TcpStream:
        return self._server

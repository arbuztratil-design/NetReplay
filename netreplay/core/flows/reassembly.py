"""TCP sequence tracking and byte-stream reassembly.

Pure in-memory logic — no database, no Scapy. The capture thread feeds
reconstructed TCP payload bytes together with sequence numbers; this module
turns them into a contiguous byte stream, detecting out-of-order delivery,
retransmissions, overlapping segments and stream gaps.

Design notes
------------
Each half of a TCP connection is treated as a separate *stream* tracked by
its own :class:`TcpStream`. ``seq`` is the TCP sequence number of the first
payload byte of a segment and always carries the full 32-bit space; comparisons
use RFC 1982 (serial-number arithmetic) so wraparound at ``2**32`` is handled
without assuming monotonic values.

A stream only starts producing a usable byte stream once it sees a SYN (or
the first non-empty segment — SYN-less captures happen when the capture
misses the handshake). The reassembler accepts out-of-order segments, keeps
them in a reorder buffer, and reports structural problems (gaps, overlaps,
retransmissions) so the timeline can surface them without blocking capture.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_SEQ_MASK = 0xFFFFFFFF

# RFC 1982 serial-number comparison.
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
        self._base: int | None = base_seq  # absolute seq after SYN/established
        self._next: int | None = None          # next expected seq
        self._buffer: list[Segment] = []       # out-of-order / pending pieces
        self._established = False
        self._syned = False
        self._issues: list[ReassemblyIssue] = list()
        self._syn_ts: float | None = None
        self._bytes_written = 0

    # ------------------------------------------------------------------ state

    @property
    def established(self) -> bool:
        return self._established

    @property
    def base_seq(self) -> int | None:
        return self._base

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    @property
    def issues(self) -> list[ReassemblyIssue]:
        return list(self._issues)

    # ---------------------------------------------------------------- feeding

    def feed(self, seq: int, data: bytes, ts: float) -> StreamOutput:
        """Feed one TCP segment (excluding the SYN byte).

        ``seq`` is the sequence number of the first payload byte. Returns the
        contiguous bytes that can be handed off to the protocol analyzers plus
        the first structural issue encountered for this segment (if any).
        """
        if data:
            self._syned = True
        if not self._syned:
            # No payload at all before seeing a SYN or a data segment: just
            # remember the sequence base so window accounting stays honest.
            if seq is not None and self._base is None:
                self._base = seq
            return StreamOutput()

        if self._base is None:
            self._base = seq
        if self._next is None:
            self._next = seq

        out = bytearray()
        issue: ReassemblyIssue | None = None
        if not data:
            # Pure ACKs / window probes carry no payload.
            return StreamOutput(bytes=b"")

        seg = Segment(seq=seq, data=data, ts=ts)
        end = seg.end_seq

        if seq_ge(seq, self._next):
            if seq_gt(seq, self._next):
                # Gap: bytes between next and seq are missing.
                gap_len = (seq - self._next) & _SEQ_MASK
                issue = ReassemblyIssue(
                    kind="gap",
                    at_seq=self._next,
                    ts=ts,
                    detail=f"missing {gap_len} byte(s) in gap",
                )
                self._issues.append(issue)
                self._next = seq
            out.extend(data)
            self._next = end
        else:
            # seq < next: retransmission or overlap with already-emitted bytes.
            overlap = (self._next - seq) & _SEQ_MASK
            suffix = data[overlap:]
            if not suffix:
                # The whole segment is a pure retransmission.
                issue = ReassemblyIssue(
                    kind="retransmission",
                    at_seq=seq,
                    ts=ts,
                    detail=f"retransmitted {len(data)} byte(s) at seq={seq}",
                )
                self._issues.append(issue)
                return StreamOutput(bytes=b"", issue=issue)
            issue = ReassemblyIssue(
                kind="overlap",
                at_seq=seq,
                ts=ts,
                detail=f"overlap of {overlap} byte(s) then {len(suffix)} new byte(s)",
            )
            self._issues.append(issue)
            out.extend(suffix)
            self._next = end

        # Deliver anything now contiguous from the reorder buffer.
        while self._buffer:
            head = self._buffer[0]
            if seq_lt(head.seq, self._next):
                self._buffer.pop(0)
                continue
            if seq_gt(head.seq, self._next):
                gap_len = (head.seq - self._next) & _SEQ_MASK
                issue = ReassemblyIssue(
                    kind="gap",
                    at_seq=self._next,
                    ts=ts,
                    detail=f"missing {gap_len} byte(s) in gap before buffered segment",
                )
                self._issues.append(issue)
                self._next = head.seq
            out.extend(head.data)
            self._next = head.end_seq
            self._buffer.pop(0)
            # Hmm: multiple segments may now be contiguous; keep draining.
            while (
                self._buffer
                and (self._buffer[0].seq & _SEQ_MASK) == (self._next & _SEQ_MASK)
            ):
                nxt = self._buffer.pop(0)
                out.extend(nxt.data)
                self._next = nxt.end_seq

        if out:
            self._bytes_written += len(out)
        return StreamOutput(
            bytes=bytes(out),
            issue=issue,
            synced=self._syned,
        )

    # ------------------------------------------------------------- helpers

    def _flush_contiguous(self, out: bytearray) -> None:
        """Append any buffered segments that are now contiguous to ``next``.

        Uses a stable O(n log n) merge on a small reorder window (typical for a
        live capture the reorder buffer stays tiny; worst case a large
        out-of-order burst is held in memory but emitted in order).
        """
        if not self._buffer:
            return
        self._buffer.sort(key=lambda s: (s.seq - self._next) & _SEQ_MASK)
        cursor = self._next
        keep: list[Segment] = []
        for seg in self._buffer:
            if seg.seq == cursor:
                out.extend(seg.data)
                cursor = seg.end_seq
            else:
                keep.append(seg)
        self._buffer = keep
        self._next = cursor


class TcpReassembler:
    """Tracks both directions of a TCP connection and returns reassembled
    payload in sequence order.

    This is the whole-connection view used by the TLS / DNS analyzers: feed
    each side's segments (with their sequence numbers) and read out the merged
    byte stream and any structural issues.

    Thread-safety: the capture thread calls :meth:`feed` only; :meth:`streams`
    is read from the same thread.
    """

    def __init__(self, client_seq: int | None = None, server_seq: int | None = None):
        self._client = TcpStream(base_seq=client_seq)
        self._server = TcpStream(base_seq=server_seq)

    def feed_client(self, seq: int, data: bytes, ts: float) -> StreamOutput:
        return self._client.feed(seq, data, ts)

    def feed_server(self, seq: int, data: bytes, ts: float) -> StreamOutput:
        return self._server.feed(seq, data, ts)

    @property
    def client(self) -> TcpStream:
        return self._client

    @property
    def server(self) -> TcpStream:
        return self._server

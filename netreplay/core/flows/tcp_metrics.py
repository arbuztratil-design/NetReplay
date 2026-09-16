"""TCP performance and health metrics (phase 3 #26, #27).

Pure in-memory analysis for one TCP conversation:

* **RTT (#26)** — handshake RTT (SYN -> SYN/ACK) and ACK-based RTT samples
  (time from sending data to the ACK that acknowledges it), reported as
  min/avg/max plus the sample count.
* **Duplicate ACKs / window analysis (#27)** — counts duplicate ACKs, tracks
  the advertised receive window (min/max) and how often the window was zero
  (a stalled peer), and records retransmissions seen at the sequence level.

The class never blocks and holds only per-conversation state, so it can run on
the capture thread.
"""
from __future__ import annotations

from dataclasses import dataclass, field

FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10

_SEQ_MASK = 0xFFFFFFFF


def _ack_covers(ack: int, end_seq: int) -> bool:
    """True when ``ack`` acknowledges the byte at ``end_seq-1`` (RFC 1982)."""
    return ((end_seq - ack) & _SEQ_MASK) <= (_SEQ_MASK // 2)


@dataclass(slots=True)
class _Outstanding:
    end_seq: int
    ts: float


@dataclass(slots=True)
class TcpMetrics:
    """Accumulates RTT, duplicate-ACK and window statistics for one flow."""

    handshake_rtt: float | None = None
    rtt_samples: list[float] = field(default_factory=list)
    duplicate_acks: int = 0
    retransmissions: int = 0
    window_min: int | None = None
    window_max: int | None = None
    zero_window_count: int = 0

    _syn_ts: float | None = None
    _synack_seen: bool = False
    _ack_ts: float | None = None
    _outstanding: dict[bool, list[_Outstanding]] = field(default_factory=dict)
    _last_ack: dict[bool, int | None] = field(default_factory=dict)
    _last_window: dict[bool, int | None] = field(default_factory=dict)

    # ------------------------------------------------------------------ input

    def on_segment(
        self,
        ts: float,
        seq: int,
        ack: int,
        flags: int,
        window: int | None,
        payload_len: int,
        from_responder: bool,
    ) -> None:
        """Feed one TCP segment (payload_len excludes the SYN/FIN control bits)."""
        if window is not None:
            self._record_window(window)

        is_syn = bool(flags & FLAG_SYN)
        is_ack = bool(flags & FLAG_ACK)

        # Handshake RTT: SYN (initiator) -> SYN/ACK (responder).
        if is_syn and not is_ack and not from_responder:
            self._syn_ts = ts
        elif is_syn and is_ack and from_responder:
            self._synack_seen = True
            if self._syn_ts is not None and self.handshake_rtt is None:
                self.handshake_rtt = max(0.0, ts - self._syn_ts)
        elif is_ack and not is_syn and not from_responder and self._synack_seen:
            self._ack_ts = ts

        # Duplicate ACK: pure ACK (no payload) repeating the previous ack
        # number from the same side.
        previous_ack = self._last_ack.get(from_responder)
        if is_ack and payload_len == 0 and not is_syn:
            if previous_ack is not None and ack == previous_ack:
                self.duplicate_acks += 1
            self._last_ack[from_responder] = ack
        elif payload_len > 0 and is_ack:
            self._last_ack[from_responder] = ack

        # ACK-based RTT: acknowledge outstanding data from the other side.
        if is_ack and not is_syn and payload_len == 0:
            self._acknowledge(ack, ts, from_responder)

        # Track newly sent data as outstanding.
        if payload_len > 0:
            self._outstanding.setdefault(from_responder, []).append(
                _Outstanding(end_seq=(seq + payload_len) & _SEQ_MASK, ts=ts)
            )

        # Retransmission at sequence level is detected by the reassembler; a
        # segment reusing a sequence already acknowledged is a retransmission.
        if payload_len > 0:
            outstanding = self._outstanding.get(from_responder, [])
            if any(o.end_seq == (seq + payload_len) & _SEQ_MASK and o.ts < ts
                   for o in outstanding[:-1]):
                self.retransmissions += 1

    # ----------------------------------------------------------------- output

    @property
    def rtt_count(self) -> int:
        return len(self.rtt_samples)

    @property
    def rtt_min(self) -> float | None:
        return min(self.rtt_samples) if self.rtt_samples else None

    @property
    def rtt_max(self) -> float | None:
        return max(self.rtt_samples) if self.rtt_samples else None

    @property
    def rtt_avg(self) -> float | None:
        return sum(self.rtt_samples) / len(self.rtt_samples) if self.rtt_samples else None

    def to_facts(self) -> dict[str, float | int]:
        """Flat, JSON/DB-friendly summary for storage (#17)."""
        facts: dict[str, float | int] = {
            "dup_acks": self.duplicate_acks,
            "retransmissions": self.retransmissions,
            "zero_window": self.zero_window_count,
        }
        if self.handshake_rtt is not None:
            facts["handshake_rtt"] = round(self.handshake_rtt, 6)
        if self.rtt_count:
            facts["rtt_count"] = self.rtt_count
            facts["rtt_min"] = round(self.rtt_min or 0.0, 6)
            facts["rtt_avg"] = round(self.rtt_avg or 0.0, 6)
            facts["rtt_max"] = round(self.rtt_max or 0.0, 6)
        if self.window_min is not None:
            facts["window_min"] = self.window_min
        if self.window_max is not None:
            facts["window_max"] = self.window_max
        return facts

    # ---------------------------------------------------------------- internals

    def _record_window(self, window: int) -> None:
        if window == 0:
            self.zero_window_count += 1
        self.window_min = window if self.window_min is None else min(self.window_min, window)
        self.window_max = window if self.window_max is None else max(self.window_max, window)

    def _acknowledge(self, ack: int, ts: float, from_responder: bool) -> None:
        # The ACK from one side acknowledges the *other* side's outstanding data.
        sender_side = not from_responder
        outstanding = self._outstanding.get(sender_side)
        if not outstanding:
            return
        remaining: list[_Outstanding] = []
        for item in outstanding:
            if _ack_covers(ack, item.end_seq):
                self.rtt_samples.append(max(0.0, ts - item.ts))
            else:
                remaining.append(item)
        self._outstanding[sender_side] = remaining

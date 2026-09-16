"""Replay-out: inject stored .nrp frames back into a live interface.

Replays the recorded L2 frames with their original inter-packet gaps (scaled
by ``speed``), so a session can be sent back onto the wire at a chosen pace.
Graceful interruption is supported; a dry-run mode validates the sources
without touching the network. Sending is routed through an injectable sender
so the timing/ordering logic can be tested without Scapy or Npcap.

P1 additions:
* ``mode`` separates story replay (long gaps capped) from faithful replay
  (exact timing) — #31/#32.
* ``selection`` replays only part of the capture — #34.
* ``remap``/``pipeline`` adapt and mutate frames before they are sent — #35/#36.
* ``validate`` checks each frame structurally before sending — #37.
* ``skipped``/``failed``/``timing_drift`` are reported in the status — #38.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import threading
import time
from typing import Callable, Protocol

from netreplay.core.replay.mutation import MutationPipeline
from netreplay.core.replay.remap import RemapConfig, remap_frame
from netreplay.core.replay.selection import ReplaySelection
from netreplay.core.replay.timing import ReplayMode, ReplaySpeed, gap_policy
from netreplay.core.replay.validate import validate_frame
from netreplay.core.storage.database import PacketRow, SessionStorage


@dataclass(slots=True)
class ReplayOutStatus:
    packets: int = 0
    bytes: int = 0
    duration: float = 0.0
    stopped: bool = False
    error: str | None = None
    skipped: int = 0
    failed: int = 0
    timing_drift: float = 0.0
    mode: str = ReplayMode.STORY.value


class Sender(Protocol):
    """Sends a raw L2 frame to the wire."""

    def send(self, raw: bytes) -> None: ...

    def close(self) -> None: ...


class _L2Sender:
    """Scapy/raw-socket sender: byte-exact Ethernet frames via L2Socket.

    The socket is opened lazily and reused across packets so pacing is not
    disturbed by per-frame socket setup.
    """

    def __init__(self, interface: str) -> None:
        self._interface = interface
        self._socket = None

    def send(self, raw: bytes) -> None:
        from scapy.all import Ether, L2Socket

        if self._socket is None:
            self._socket = L2Socket(iface=self._interface)
        self._socket.send(Ether(raw))

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None


class ReplayOutService:
    """Play a stored session back onto an interface at ``speed`` rate."""

    def __init__(
        self,
        session: SessionStorage,
        interface: str,
        speed: float = 1.0,
        max_gap: float = 5.0,
        dry_run: bool = False,
        offset: int = 0,
        limit: int | None = None,
        sender_factory=None,
        on_progress: Callable[[ReplayOutStatus], None] | None = None,
        mode: ReplayMode = ReplayMode.STORY,
        selection: ReplaySelection | None = None,
        remap: RemapConfig | None = None,
        pipeline: MutationPipeline | None = None,
        validate: bool = False,
    ) -> None:
        self._session = session
        self.interface = interface
        self.speed = ReplaySpeed(speed).factor
        self.max_gap = max_gap
        self.dry_run = dry_run
        self._offset = max(0, offset)
        self._limit = limit
        self._sender_factory = sender_factory or (lambda _iface: _L2Sender(_iface))
        self._on_progress = on_progress
        self._stop_flag = threading.Event()
        self.mode = mode if isinstance(mode, ReplayMode) else ReplayMode(mode)
        self.selection = selection
        self.remap = remap
        self.pipeline = pipeline
        self.validate = validate

    def stop(self) -> None:
        """Request a graceful stop before the next packet (thread-safe)."""
        self._stop_flag.set()

    def run(self) -> ReplayOutStatus:
        status = ReplayOutStatus(mode=self.mode.value)
        started = time.monotonic()
        sender: Sender | None = None
        prev_ts: float | None = None
        sent = 0
        last_progress = 0.0
        scheduled_sleep = 0.0
        # Faithful replay preserves exact timing; story replay caps long gaps.
        cap = None if self.mode is ReplayMode.FAITHFUL else self.max_gap
        rate = ReplaySpeed(self.speed)
        try:
            if not self.dry_run:
                sender = self._sender_factory(self.interface)
            for row in self._session.packets():
                if self._stop_flag.is_set():
                    status.stopped = True
                    break
                if sent < self._offset:
                    sent += 1
                    status.skipped += 1
                    continue
                if self._limit is not None and status.packets >= self._limit:
                    break
                if self.selection is not None and not self.selection.matches(row):
                    status.skipped += 1
                    continue
                if prev_ts is not None:
                    gap = rate.scale(max(0.0, row.ts - prev_ts))
                    if cap is not None:
                        gap = min(gap, cap)
                else:
                    gap = 0.0
                prev_ts = row.ts
                if gap > 0:
                    scheduled_sleep += gap
                    time.sleep(gap)
                    if self._stop_flag.is_set():
                        status.stopped = True
                        break
                frame = self._prepare(row)
                if frame is None:
                    status.failed += 1
                    continue
                if sender is not None:
                    sender.send(frame)
                status.packets += 1
                status.bytes += row.length
                sent += 1
                if self._on_progress is not None:
                    now = time.monotonic()
                    if status.packets % 10 == 0 or now - last_progress >= 0.3:
                        status.duration = now - started
                        self._on_progress(replace(status))
                        last_progress = now
        except KeyboardInterrupt:
            status.stopped = True
        except Exception as exc:  # noqa: BLE001 - surfaced in status
            status.error = f"{type(exc).__name__}: {exc}"
        finally:
            if sender is not None:
                try:
                    sender.close()
                except Exception:  # noqa: BLE001
                    pass
            status.duration = time.monotonic() - started
            status.timing_drift = status.duration - scheduled_sleep
        return status

    def _prepare(self, row: PacketRow) -> bytes | None:
        """Fetch a frame and apply mutation/remap/validation, if configured."""
        frame = self._frames(row)
        if self.pipeline is not None and not self.pipeline.is_empty:
            frame = self.pipeline.apply(frame)
        if self.remap is not None and not self.remap.is_empty:
            frame = remap_frame(frame, self.remap)
        if self.validate:
            result = validate_frame(frame)
            if not result.valid:
                return None
        return frame

    def _frames(self, row: PacketRow) -> bytes:
        fetched = self._session.packet(row.id)
        if fetched is None:
            raise RuntimeError(f"packet {row.id} not found in the session")
        return fetched[1]

"""L2 live bridge: sniff on one interface, forward to the other.

Bidirectional by default.  ``stop()`` may be called from any thread for
graceful shutdown.  The sniffer and sender factories make the bridge fully
testable without Scapy or Npcap.
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, Protocol


class Sniffer(Protocol):
    """Wraps one capture thread that delivers raw packets via ``start``/``packets``/``stop``."""

    @property
    def running(self) -> bool: ...

    def start(self) -> None: ...

    def packets(self): ...  # yields CapturedPacket; None sentinel at the end

    def stop(self) -> None: ...


class Sender(Protocol):
    def send(self, raw: bytes) -> None: ...
    def close(self) -> None: ...


@dataclass(slots=True)
class BridgeStatus:
    left_forwarded: int = 0
    right_forwarded: int = 0
    left_bytes: int = 0
    right_bytes: int = 0
    errors: int = 0
    stopped: bool = False
    error: str | None = None
    duration: float = 0.0

    @property
    def total_forwarded(self) -> int:
        return self.left_forwarded + self.right_forwarded

    @property
    def total_bytes(self) -> int:
        return self.left_bytes + self.right_bytes

    @property
    def running(self) -> bool:
        return not self.stopped and self.error is None


class BridgeService:
    """Sniff on two interfaces and forward each frame to the other.

    Parameters
    ----------
    iface_left, iface_right:
        Interface names.
    sniffer_factory, sender_factory:
        Factories called with the interface name; return a :class:`Sniffer`
        and a :class:`Sender` respectively.  Defaults use Scapy.
    on_progress:
        Optional callback invoked periodically with a snapshot of the status.
    """

    def __init__(
        self,
        iface_left: str,
        iface_right: str,
        *,
        sniffer_factory: Any | None = None,
        sender_factory: Any | None = None,
        on_progress: Callable[[BridgeStatus], None] | None = None,
    ) -> None:
        self.iface_left = iface_left
        self.iface_right = iface_right
        self._sniffer_factory = sniffer_factory or _default_sniffer
        self._sender_factory = sender_factory or _default_sender
        self._on_progress = on_progress
        self._stop_flag = threading.Event()
        self._status = BridgeStatus()

    def stop(self) -> None:
        """Request a graceful stop (thread-safe)."""
        self._stop_flag.set()

    @property
    def status(self) -> BridgeStatus:
        return replace(self._status)

    def run(self) -> BridgeStatus:
        sniffer_left = self._sniffer_factory(self.iface_left)
        sniffer_right = self._sniffer_factory(self.iface_right)
        sender_left = self._sender_factory(self.iface_left)
        sender_right = self._sender_factory(self.iface_right)
        started = time.monotonic()
        last_progress = 0.0
        left_done = right_done = False
        try:
            sniffer_left.start()
            sniffer_right.start()
            while not self._stop_flag.is_set():
                flushed = False
                if not left_done:
                    f, left_done = self._drain_queue(
                        sniffer_left, sender_right, "left_forwarded", "left_bytes"
                    )
                    flushed = flushed or f
                if not right_done:
                    f, right_done = self._drain_queue(
                        sniffer_right, sender_left, "right_forwarded", "right_bytes"
                    )
                    flushed = flushed or f
                if left_done and right_done:
                    break
                now = time.monotonic()
                if flushed or now - last_progress >= 0.5:
                    self._status.duration = now - started
                    if self._on_progress is not None:
                        self._on_progress(replace(self._status))
                    last_progress = now
                if not flushed:
                    time.sleep(0.02)
        except Exception as exc:  # noqa: BLE001 - surfaced in status
            self._status.error = f"{type(exc).__name__}: {exc}"
        finally:
            self._status.stopped = self._stop_flag.is_set()
            self._status.duration = time.monotonic() - started
            _close(sniffer_left, sniffer_right)
            _close(sender_left, sender_right)
        return replace(self._status)

    def _drain_queue(
        self,
        sniffer: Sniffer,
        sender: Sender,
        fwd_field: str,
        bytes_field: str,
    ) -> tuple[bool, bool]:
        """Forward all buffered frames from *sniffer* to *sender*.

        Returns (forwarded, done) where *done* is True when the backend's None
        sentinel is received (meaning no more frames will arrive).
        """
        forwarded = False
        done = False
        while not self._stop_flag.is_set():
            try:
                pkt = sniffer._queue.get(timeout=0.03)  # noqa: SLF001
            except queue.Empty:
                break
            if pkt is None:
                done = True
                break
            raw = bytes(pkt)
            try:
                sender.send(raw)
            except Exception:  # noqa: BLE001
                self._status.errors += 1
                continue
            setattr(self._status, fwd_field, getattr(self._status, fwd_field) + 1)
            setattr(self._status, bytes_field, getattr(self._status, bytes_field) + len(raw))
            forwarded = True
        return forwarded, done


def _close(*items):
    for item in items:
        try:
            item.close()
        except Exception:  # noqa: BLE001
            pass


def _default_sniffer(iface: str) -> Sniffer:
    from netreplay.core.capture.scapy_backend import ScapyBackend

    return ScapyBackend(iface)


def _default_sender(iface: str) -> Sender:
    from netreplay.core.replay.inject import _L2Sender

    return _L2Sender(iface)

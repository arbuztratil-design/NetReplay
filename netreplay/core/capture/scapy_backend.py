"""Scapy-based capture backend (uses Npcap on Windows)."""
from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Iterator

from netreplay.core.capture.base import CaptureBackend, CaptureError, InterfaceInfo
from netreplay.core.packets.models import CapturedPacket

logger = logging.getLogger(__name__)

_QUEUE_SIZE = 4096


def list_interfaces() -> list[InterfaceInfo]:
    """List capture interfaces with friendly descriptions where available."""
    from scapy.all import get_if_list

    ifaces: dict[str, InterfaceInfo] = {}
    try:
        from scapy.arch.windows import get_windows_if_list

        for item in get_windows_if_list():
            name = item.get("name") or ""
            if not name:
                continue
            desc = item.get("description") or ""
            ifaces[name] = InterfaceInfo(name=name, description=desc)
    except Exception:
        logger.debug("get_windows_if_list unavailable", exc_info=True)
    for name in get_if_list():
        ifaces.setdefault(name, InterfaceInfo(name=name))
    return list(ifaces.values())


class ScapyBackend(CaptureBackend):
    """Capture packets using Scapy's ``sniff`` on a background thread."""

    def __init__(self, interface: str):
        super().__init__(interface)
        self._queue: queue.Queue = queue.Queue(maxsize=_QUEUE_SIZE)
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self._error: Exception | None = None
        self._drops = 0

    @property
    def running(self) -> bool:
        return self._running.is_set()

    @property
    def drops(self) -> int:
        return self._drops

    def start(self) -> None:
        if self.running:
            return
        self._error = None
        self._drops = 0
        self._running.set()
        self._thread = threading.Thread(target=self._sniff, name="scapy-sniff", daemon=True)
        self._thread.start()

    def _sniff(self) -> None:
        from scapy.all import conf, sniff

        tr = None
        try:
            # Use Npcap/WinPcap via wpcap on Windows; native L2 sockets
            # do not exist there, so forcing use_pcap=False breaks capture.
            conf.use_pcap = True
            tr = sniff(
                iface=self.interface,
                store=False,
                prn=self._enqueue,
                stop_filter=lambda _pkt: not self._running.is_set(),
                count=0,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller
            logger.warning("sniff failed on %s: %s", self.interface, exc)
            logger.debug("sniff traceback", exc_info=True)
            self._error = exc
        finally:
            self._running.clear()
            self._queue.put(None)

    def _enqueue(self, pkt) -> None:
        ts = float(getattr(pkt, "time", time.time()))
        data = bytes(pkt)
        try:
            self._queue.put(CapturedPacket(ts=ts, data=data), timeout=0.5)
        except queue.Full:
            self._drops += 1
            logger.warning("capture queue full; dropping packet (%d dropped)", self._drops)

    def packets(self) -> Iterator[CapturedPacket]:
        while True:
            item = self._queue.get()
            if item is None:
                break
            yield item
        if self._error is not None:
            exc = self._error
            self._error = None
            raise CaptureError(
                f"capture on {self.interface} failed: {exc}.\n"
                "On Windows install Npcap (https://npcap.com) and make sure the "
                "interface name is correct."
            ) from exc

    def stop(self) -> None:
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=5.0)
        if self._error is not None:
            exc = self._error
            self._error = None
            raise CaptureError(
                f"capture on {self.interface} failed: {exc}.\n"
                "On Windows install Npcap (https://npcap.com) and make sure the "
                "interface name is correct."
            ) from exc
        self._thread = None
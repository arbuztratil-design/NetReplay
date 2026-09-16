"""Offline packet source for PCAP and PCAPNG files."""
from __future__ import annotations

import threading
from collections.abc import Iterator
from pathlib import Path

from netreplay.core.capture.base import CaptureBackend, CaptureError
from netreplay.core.packets.models import CapturedPacket


class PcapBackend(CaptureBackend):
    """Read stored packets through Scapy without requiring a live interface."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        super().__init__(str(self.path))
        self._running = threading.Event()

    @property
    def running(self) -> bool:
        return self._running.is_set()

    def start(self) -> None:
        if not self.path.is_file():
            raise CaptureError(f"PCAP file not found: {self.path}")
        if self.path.suffix.lower() not in {".pcap", ".pcapng"}:
            raise CaptureError(f"unsupported capture file: {self.path}")
        self._running.set()

    def stop(self) -> None:
        self._running.clear()

    def packets(self) -> Iterator[CapturedPacket]:
        from scapy.utils import PcapReader

        try:
            with PcapReader(str(self.path)) as reader:
                for packet in reader:
                    if not self.running:
                        break
                    yield CapturedPacket(
                        ts=float(getattr(packet, "time", 0.0)), data=bytes(packet)
                    )
        except CaptureError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CaptureError(f"cannot read {self.path}: {exc}") from exc
        finally:
            self._running.clear()

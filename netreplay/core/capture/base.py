"""Capture backend abstraction."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass

from netreplay.core.packets.models import CapturedPacket


class CaptureError(Exception):
    """Raised when capture cannot start (e.g. missing Npcap, bad interface)."""


@dataclass(slots=True)
class InterfaceInfo:
    name: str
    description: str = ""


class CaptureBackend(ABC):
    """Abstract packet capture engine."""

    def __init__(self, interface: str, bpf_filter: str = ""):
        self.interface = interface
        self.bpf_filter = bpf_filter

    @property
    def running(self) -> bool:
        raise NotImplementedError

    @property
    def drops(self) -> int:
        """Number of packets dropped by the backend (full queue, buffer overrun)."""
        return 0

    @abstractmethod
    def start(self) -> None:
        """Begin capturing (non-blocking)."""

    @abstractmethod
    def stop(self) -> None:
        """Stop capturing."""

    @abstractmethod
    def packets(self) -> Iterator[CapturedPacket]:
        """Stream captured packets. Blocks until a packet or stop."""

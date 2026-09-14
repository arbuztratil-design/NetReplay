"""Capture backend abstraction."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator

from netreplay.core.packets.models import CapturedPacket


class CaptureError(Exception):
    """Raised when capture cannot start (e.g. missing Npcap, bad interface)."""


@dataclass(slots=True)
class InterfaceInfo:
    name: str
    description: str = ""


class CaptureBackend(ABC):
    """Abstract packet capture engine."""

    def __init__(self, interface: str):
        self.interface = interface

    @property
    def running(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def start(self) -> None:
        """Begin capturing (non-blocking)."""

    @abstractmethod
    def stop(self) -> None:
        """Stop capturing."""

    @abstractmethod
    def packets(self) -> Iterator[CapturedPacket]:
        """Stream captured packets. Blocks until a packet or stop."""
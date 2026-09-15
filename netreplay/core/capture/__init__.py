"""Capture backends.

A backend yields raw captured packets via :meth:`CaptureBackend.packets`.
The default MVP backend wraps Scapy, but the abstraction allows swapping the
underlying capture engine without touching the rest of NetReplay.
"""
from netreplay.core.capture.base import CaptureBackend, CaptureError, InterfaceInfo
from netreplay.core.capture.mock_backend import MockBackend
from netreplay.core.capture.pcap_backend import PcapBackend

__all__ = [
    "CaptureBackend",
    "CaptureError",
    "InterfaceInfo",
    "MockBackend",
    "PcapBackend",
]

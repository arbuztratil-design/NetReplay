"""Flet GUI - the NetReplay desktop client.

The GUI is a pure API client: it does not parse packets, capture traffic or
touch the store. All data comes from the NetReplay REST API + WebSocket.
"""
import netreplay  # noqa: F401  (ensure package is on path)
from gui.main import main

__all__ = ["main"]

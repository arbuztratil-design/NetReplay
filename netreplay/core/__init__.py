"""NetReplay core package.

The core is the main component of the project. It contains packet parsing,
flow tracking, storage and timeline logic. GUI and CLI must not reimplement
any of this - they use the core directly (CLI) or through the API (GUI).
"""

from netreplay.core.service import NetReplayService

__all__ = ["NetReplayService"]
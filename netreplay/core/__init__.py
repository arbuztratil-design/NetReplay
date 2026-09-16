"""NetReplay core package.

The core is the main component of the project. It contains packet parsing,
flow tracking, storage and timeline logic. GUI and CLI must not reimplement
any of this - they use the core directly (CLI) or through the API (GUI).

Frozen public API (phase 1 #3): the canonical core models and the stable
building blocks other layers may import are exported here. Everything not in
``__all__`` is internal and may change without notice.
"""

from netreplay.core.events.models import EventGraph, EventKind, NetworkEvent
from netreplay.core.flows.models import Flow, TcpStateMachine
from netreplay.core.ids import EventId, FlowId, PacketId, SessionId
from netreplay.core.packets.models import Packet, ParsedPacket
from netreplay.core.replay.config import ReplayConfig
from netreplay.core.replay.timing import ReplayMode, ReplaySpeed
from netreplay.core.service import NetReplayService
from netreplay.core.storage.database import (
    SessionInfo,
    SessionStatus,
    SessionStorage,
)
from netreplay.core.timebase import (
    from_us,
    now_epoch,
    now_monotonic,
    to_us,
    utc_iso,
)

# Canonical aliases: the public names callers should use for core models.
Event = NetworkEvent
Session = SessionStorage

__all__ = [
    # service
    "NetReplayService",
    # models
    "Packet",
    "ParsedPacket",
    "Flow",
    "TcpStateMachine",
    "Event",
    "NetworkEvent",
    "EventGraph",
    "EventKind",
    "Session",
    "SessionStorage",
    "SessionInfo",
    "SessionStatus",
    # ids (#6)
    "PacketId",
    "FlowId",
    "EventId",
    "SessionId",
    # replay
    "ReplayConfig",
    "ReplayMode",
    "ReplaySpeed",
    # time base (#7)
    "now_epoch",
    "now_monotonic",
    "to_us",
    "from_us",
    "utc_iso",
]

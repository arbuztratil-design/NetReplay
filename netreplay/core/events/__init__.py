"""Event graph — DNS/TLS/HTTP/errors as one unified event graph (#19).

The event graph is the single source of truth for the timeline: packets,
flows, flows' protocol info and capture errors all become ``NetworkEvent``
nodes with parent/flow/packet links, and the timeline (#20) is just the
topological projection ``EventGraph.timeline()``.
"""
from netreplay.core.events.models import EventGraph, EventKind, NetworkEvent

__all__ = ["EventGraph", "EventKind", "NetworkEvent"]

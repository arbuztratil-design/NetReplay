"""Typed identifiers (phase 1 #6).

Storage uses plain integers for row ids; this module gives them names so the
type checker (and readers) can tell a packet id from a flow id or an event id.
``NewType`` is zero-cost at runtime, so this is purely a static-typing layer.
"""
from __future__ import annotations

from typing import NewType

# Row ids in the .nrp SQLite store.
PacketId = NewType("PacketId", int)
FlowId = NewType("FlowId", int)
EventId = NewType("EventId", int)

# Session ids are opaque strings (uuid4 hex).
SessionId = NewType("SessionId", str)


def packet_id(value: int) -> PacketId:
    return PacketId(int(value))


def flow_id(value: int) -> FlowId:
    return FlowId(int(value))


def event_id(value: int) -> EventId:
    return EventId(int(value))


def session_id(value: str) -> SessionId:
    return SessionId(str(value))


__all__ = [
    "PacketId",
    "FlowId",
    "EventId",
    "SessionId",
    "packet_id",
    "flow_id",
    "event_id",
    "session_id",
]

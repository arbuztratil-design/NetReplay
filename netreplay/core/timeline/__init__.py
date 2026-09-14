"""Timeline: converts raw packet streams into ordered, human readable events.

Events are generated while packets are processed (flow starts, TCP state
transitions, DNS queries, TLS handshakes) and stored in the session so the
timeline can be queried by time range later.
"""
from netreplay.core.timeline.service import (
    EventGenerator,
    ReplayService,
    TimelineEvent,
    TimelineService,
)

__all__ = ["EventGenerator", "ReplayService", "TimelineEvent", "TimelineService"]
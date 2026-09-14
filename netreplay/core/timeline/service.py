"""Timeline service and event generation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from netreplay.core.flows.models import FeedResult
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.storage.database import SessionStorage


@dataclass(slots=True)
class TimelineEvent:
    timestamp: float
    type: str
    flow_id: int | None
    summary: str


class EventGenerator:
    """Produces timeline events for each processed packet."""

    def feed(self, parsed: ParsedPacket, result: FeedResult) -> list[TimelineEvent]:
        """Return the events that a single packet gives rise to."""
        events: list[TimelineEvent] = []
        flow = result.flow
        if result.flow_started:
            endpoint_src = _endpoint(flow.source, flow.src_port)
            endpoint_dst = _endpoint(flow.destination, flow.dst_port)
            events.append(
                TimelineEvent(
                    timestamp=parsed.ts,
                    type=flow.protocol,
                    flow_id=flow.id,
                    summary=f"{flow.protocol} flow {endpoint_src} -> {endpoint_dst}",
                )
            )
        if (
            result.transition is not None
            and parsed.protocol == "TCP"
            and result.state not in ("NONE",)
        ):
            endpoint_src = _endpoint(flow.source, flow.src_port)
            endpoint_dst = _endpoint(flow.destination, flow.dst_port)
            events.append(
                TimelineEvent(
                    timestamp=parsed.ts,
                    type="TCP",
                    flow_id=flow.id,
                    summary=f"TCP {endpoint_src} -> {endpoint_dst} [{result.state}]",
                )
            )
        dns_info = parsed.info.get("dns")
        if dns_info is not None:
            events.append(
                TimelineEvent(
                    timestamp=parsed.ts,
                    type="DNS",
                    flow_id=flow.id,
                    summary=dns_info.summary(),
                )
            )
        tls_info = parsed.info.get("tls")
        if tls_info is not None:
            events.append(
                TimelineEvent(
                    timestamp=parsed.ts,
                    type="TLS",
                    flow_id=flow.id,
                    summary=tls_info.summary(),
                )
            )
        return events


def _endpoint(host: str, port: int | None) -> str:
    return f"{host}:{port}" if port is not None else host


class TimelineService:
    """Read-only timeline queries over a stored session."""

    def __init__(self, session: SessionStorage):
        self._session = session

    def events(
        self,
        start: float | None = None,
        end: float | None = None,
        types: list[str] | None = None,
        limit: int = 1000,
        flow_id: int | None = None,
        offset: int = 0,
    ) -> list[TimelineEvent]:
        rows = self._session.events(
            start=start, end=end, types=types, limit=limit, flow_id=flow_id, offset=offset
        )
        return [
            TimelineEvent(
                timestamp=r.ts,
                type=r.event_type,
                flow_id=r.flow_id,
                summary=r.summary,
            )
            for r in rows
        ]


class ReplayService:
    """Historical replay for MVP: emits stored events in original order with
    realistic gaps, so a consumer can show the session as a story.

    Active re-injection of captured traffic into the network is intentionally
    out of scope for the MVP.
    """

    def __init__(self, session: SessionStorage, speed: float = 1.0):
        self._session = session
        self.speed = speed

    def events(self, start: float | None = None, end: float | None = None) -> Iterator[
        tuple[float, TimelineEvent]
    ]:
        rows = self._session.events(start=start, end=end, limit=10_000_000)
        prev_ts: float | None = None
        for r in rows:
            if prev_ts is not None:
                gap = max(0.0, (r.ts - prev_ts) / self.speed)
            else:
                gap = 0.0
            prev_ts = r.ts
            yield gap, TimelineEvent(timestamp=r.ts, type=r.event_type, flow_id=r.flow_id, summary=r.summary)
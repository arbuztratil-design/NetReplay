"""Flow engine: groups packets into bidirectional flows and tracks basic
TCP connection state."""
from __future__ import annotations

from dataclasses import dataclass, field

from netreplay.core.flows.models import FeedResult, Flow, TcpStateMachine
from netreplay.core.packets.models import ParsedPacket


def _endpoint(parsed: ParsedPacket) -> tuple[str, int | None]:
    return (parsed.source, parsed.src_port)


def flow_key(parsed: ParsedPacket) -> tuple[str, str, int, str, int]:
    """Direction-independent flow key for a packet.

    Ordering of the two endpoints is normalised so that packets in both
    directions map to the same flow.
    """
    if parsed.src_port is None:
        a = (parsed.source, 0)
        b = (parsed.destination, 0)
    else:
        a = (parsed.source, parsed.src_port or 0)
        b = (parsed.destination, parsed.dst_port or 0)
    if a > b:
        a, b = b, a
    return (parsed.protocol, a[0], int(a[1]), b[0], int(b[1]))


@dataclass(slots=True)
class FlowTracker:
    """Tracks flows for a single capture run.

    ``feed`` must be called in increasing timestamp order.
    """

    _flows: dict = field(default_factory=dict)  # key -> Flow
    _tcp: dict = field(default_factory=dict)  # key -> TcpStateMachine
    _counter: int = 0

    def feed(self, parsed: ParsedPacket) -> FeedResult:
        key = flow_key(parsed)
        flow = self._flows.get(key)
        flow_started = flow is None
        if flow is None:
            self._counter += 1
            # The initiator is whoever was seen first.
            flow = Flow(
                id=self._counter,
                source=parsed.source,
                destination=parsed.destination,
                protocol=parsed.protocol,
                src_port=parsed.src_port,
                dst_port=parsed.dst_port,
                start_ts=parsed.ts,
                end_ts=parsed.ts,
                packet_count=0,
                bytes=0,
                state="NONE",
            )
            self._flows[key] = flow

        flow.end_ts = parsed.ts
        flow.packet_count += 1
        flow.bytes += parsed.length

        transition = None
        if parsed.protocol == "TCP":
            sm = self._tcp.setdefault(key, TcpStateMachine())
            from_responder = self._is_responder(key, parsed)
            sm.add(parsed.info.get("tcp_flags", 0), from_responder=from_responder)
            new_state = sm.state()
            if new_state != flow.state:
                transition = new_state
            flow.state = new_state
        parsed.flow_id = flow.id
        parsed.info["flow_started"] = flow_started
        return FeedResult(
            flow=flow, flow_started=flow_started, transition=transition, state=flow.state
        )

    def _is_responder(self, key, parsed: ParsedPacket) -> bool:
        flow = self._flows[key]
        return (
            parsed.source == flow.destination
            and (parsed.src_port or 0) == (flow.dst_port or 0)
        )

    def clear(self) -> None:
        self._flows.clear()
        self._tcp.clear()
        self._counter = 0

    def flows(self) -> list[Flow]:
        return list(self._flows.values())

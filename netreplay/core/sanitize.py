"""Capture sanitization / redaction (#47).

Produces a shareable copy of a session with identifying data replaced by
stable pseudonyms: IPs become ``10.255.x.y``, MACs become ``02:00:...`` and
hostnames become ``host-N.example``. The mapping is deterministic within a run,
so repeated references collapse to the same token and the capture stays
internally consistent (flows still line up with their packets).

Both metadata (flows, packet endpoints, event summaries) and the stored raw
frames are rewritten, so the exported ``.nrp`` leaks no original identifiers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import ParsedPacket
from netreplay.core.replay.remap import RemapConfig, remap_frame
from netreplay.core.storage import open_session

_HOST_RE = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z]{2,})\b")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


@dataclass(slots=True)
class RedactionPolicy:
    redact_ips: bool = True
    redact_macs: bool = True
    redact_domains: bool = True


@dataclass(slots=True)
class SanitizeReport:
    flows: int = 0
    packets: int = 0
    events: int = 0
    ips_redacted: int = 0
    macs_redacted: int = 0
    domains_redacted: int = 0

    def mapping_summary(self) -> dict[str, int]:
        return {
            "ips": self.ips_redacted,
            "macs": self.macs_redacted,
            "domains": self.domains_redacted,
        }


class Redactor:
    """Deterministic pseudonym generator for one sanitization run."""

    def __init__(self, policy: RedactionPolicy):
        self.policy = policy
        self._ips: dict[str, str] = {}
        self._macs: dict[str, str] = {}
        self._domains: dict[str, str] = {}

    def ip(self, value: str | None) -> str | None:
        if not value or not self.policy.redact_ips:
            return value
        if value not in self._ips:
            index = len(self._ips)
            self._ips[value] = f"10.255.{index // 256}.{index % 256}"
        return self._ips[value]

    def mac(self, raw: bytes) -> bytes:
        if not self.policy.redact_macs:
            return raw
        key = raw.hex()
        if key not in self._macs:
            index = len(self._macs)
            self._macs[key] = f"02:00:00:00:{index // 256:02x}:{index % 256:02x}"
        from netreplay.core.replay.remap import MacAddress

        return MacAddress.parse(self._macs[key]).raw

    def domain(self, value: str) -> str:
        if not self.policy.redact_domains:
            return value
        if value not in self._domains:
            self._domains[value] = f"host-{len(self._domains)}.example"
        return self._domains[value]

    def text(self, value: str | None) -> str | None:
        if value is None:
            return value
        result = value
        if self.policy.redact_domains:
            result = _HOST_RE.sub(lambda m: self.domain(m.group(1)), result)
        if self.policy.redact_ips:
            result = _IP_RE.sub(lambda m: self.ip(m.group(1)) or m.group(1), result)
        return result

    def remap_config(self) -> RemapConfig:
        ip_map = {self._raw_ip(k): self._raw_ip(v) for k, v in self._ips.items()}
        mac_map = {}
        for key, token in self._macs.items():
            from netreplay.core.replay.remap import MacAddress

            mac_map[bytes.fromhex(key)] = MacAddress.parse(token).raw
        return RemapConfig(mac_map=mac_map, ip_map=ip_map)

    @staticmethod
    def _raw_ip(text: str) -> bytes:
        from netreplay.core.replay.remap import Ipv4Address

        return Ipv4Address.parse(text).raw

    @property
    def counts(self) -> tuple[int, int, int]:
        return len(self._ips), len(self._macs), len(self._domains)


def _observe_frame(redactor: Redactor, raw: bytes) -> None:
    """Register IPs/MACs found in a raw frame so remapping covers them."""
    if len(raw) < 14:
        return
    if redactor.policy.redact_macs:
        redactor.mac(raw[0:6])
        redactor.mac(raw[6:12])
    if len(raw) >= 34 and raw[12:14] == b"\x08\x00" and redactor.policy.redact_ips:
        redactor.ip(".".join(str(b) for b in raw[26:30]))
        redactor.ip(".".join(str(b) for b in raw[30:34]))


def sanitize_session(
    src_path: str | Path,
    dst_path: str | Path,
    policy: RedactionPolicy | None = None,
) -> SanitizeReport:
    """Write a redacted copy of *src_path* to *dst_path* (#47)."""
    policy = policy or RedactionPolicy()
    try:
        source = open_session(src_path)
    except Exception as exc:  # noqa: BLE001 - normalize to FileNotFoundError
        raise FileNotFoundError(f"session not found: {src_path}") from exc
    if source is None:
        raise FileNotFoundError(f"session not found: {src_path}")
    dst = Path(dst_path)
    if dst.exists():
        dst.unlink()

    redactor = Redactor(policy)
    report = SanitizeReport()

    # First pass: discover every identifier and the raw frames.
    frames: list[tuple[ParsedPacket, bytes]] = []
    for row in source.packets():
        fetched = source.packet(row.id)
        if fetched is None:
            continue
        _row, raw = fetched
        _observe_frame(redactor, raw)
        redactor.ip(_row.source)
        redactor.ip(_row.destination)
        frames.append((ParsedPacket(
            ts=_row.ts,
            source=redactor.ip(_row.source) or "",
            destination=redactor.ip(_row.destination) or "",
            protocol=_row.protocol,
            src_port=_row.src_port,
            dst_port=_row.dst_port,
            length=_row.length,
            raw=raw,
            flow_id=_row.flow_id,
        ), raw))

    target = open_session(dst, create=True)
    if target is None:
        raise RuntimeError(f"could not create sanitized session at {dst}")
    name = source.meta("name") or "session"
    target.set_name_and_interface(f"sanitized {name}", source.meta("interface"))

    for flow in source.flows():
        target.upsert_flow(Flow(
            id=flow.id,
            source=redactor.ip(flow.source) or "",
            destination=redactor.ip(flow.destination) or "",
            protocol=flow.protocol,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            start_ts=flow.start_ts,
            end_ts=flow.end_ts,
            packet_count=flow.packet_count,
            bytes=flow.bytes,
            state=flow.state,
        ))
        report.flows += 1

    remap_cfg = redactor.remap_config()
    for packet, raw in frames:
        packet.raw = remap_frame(raw, remap_cfg)
        target.add_packet(packet)
        report.packets += 1

    for event in source.events(limit=10_000_000):
        target.add_event(
            event.ts, event.event_type, event.flow_id, redactor.text(event.summary) or ""
        )
        report.events += 1

    target.finalize()

    ips, macs, domains = redactor.counts
    report.ips_redacted = ips
    report.macs_redacted = macs
    report.domains_redacted = domains
    return report

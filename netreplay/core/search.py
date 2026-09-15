"""Search and similarity over stored NetReplay sessions.

Read-only helpers built on top of the storage layer:

* ``search_session`` - find flows / packets / events matching an IP or a
  domain (DNS names and TLS SNI, including resolved addresses).
* ``Fingerprint`` + ``similarity`` - cosine similarity over weighted feature
  vectors (domains, IPs, protocol/port pairs).
* ``similar_sessions`` - rank other ``.nrp`` sessions in a workspace against
  a target session.
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from netreplay.core.storage import SessionStorage
from netreplay.core.storage.database import EventRow, FlowRow, PacketRow
from netreplay.core.storage.nrp import InvalidNrpError

_DOMAIN_RE = re.compile(r"DNS (?:QUERY|RESPONSE) ([^\s(]+)")
_SNI_RE = re.compile(r"sni=([^\s]+)")

_WEIGHTS: dict[str, float] = {"domain": 3.0, "ip": 1.0, "port": 0.5}


@dataclass(slots=True)
class SearchResult:
    query: str
    flows: list[FlowRow]
    events: list[EventRow]
    packets: list[PacketRow]

    @property
    def total(self) -> int:
        return len(self.flows) + len(self.events) + len(self.packets)


def search_session(
    session: SessionStorage,
    query: str,
    *,
    max_flows: int = 100,
    max_events: int = 200,
    max_packets: int = 100,
) -> SearchResult:
    """Search flows/packets by endpoint and events by summary substring."""
    needle = query.strip()
    if not needle:
        return SearchResult(query="", flows=[], events=[], packets=[])
    return SearchResult(
        query=needle,
        flows=session.flows_by_endpoint(needle, limit=max_flows),
        events=session.events_matching(needle, limit=max_events),
        packets=session.packets_by_endpoint(needle, limit=max_packets),
    )


@dataclass(slots=True)
class Fingerprint:
    """Weighted feature counts describing a session's traffic profile."""

    domains: Counter[str] = field(default_factory=Counter)
    ips: Counter[str] = field(default_factory=Counter)
    ports: Counter[str] = field(default_factory=Counter)

    @property
    def total(self) -> int:
        return sum(self.domains.values()) + sum(self.ips.values()) + sum(self.ports.values())


def fingerprint(
    session: SessionStorage, *, max_events: int = 50_000, max_flows: int | None = None
) -> Fingerprint:
    """Collect domains (DNS names + TLS SNI), endpoint IPs and (protocol, port)
    pairs from a session."""
    fp = Fingerprint()
    for row in session.events(limit=max_events):
        if row.event_type not in ("DNS", "TLS"):
            continue
        sni = _SNI_RE.search(row.summary)
        if sni is not None:
            fp.domains[sni.group(1).lower()] += 1
        domain = _DOMAIN_RE.search(row.summary)
        if domain is not None:
            fp.domains[domain.group(1).lower()] += 1
    flows = session.flows()[:max_flows] if max_flows is not None else session.flows()
    for flow in flows:
        if flow.source:
            fp.ips[flow.source] += 1
        if flow.destination:
            fp.ips[flow.destination] += 1
        if flow.protocol and flow.dst_port:
            fp.ports[f"{flow.protocol}:{flow.dst_port}"] += 1
    return fp


def similarity(a: Fingerprint, b: Fingerprint) -> float:
    """Cosine similarity between two fingerprints in [0, 1] (0 if either is empty)."""
    va = _vector(a)
    vb = _vector(b)
    return _cosine(va, vb)


@dataclass(slots=True)
class SimilarSession:
    session_id: str
    name: str
    score: float
    shared_domains: list[str]
    shared_ips: list[str]
    shared_ports: list[str]


def similar_sessions(
    target_path: str | Path,
    workspace: str | Path | None = None,
    *,
    top: int = 5,
    _open: Callable[[Path], SessionStorage] | None = None,
) -> list[SimilarSession]:
    """Rank sessions inside *workspace* by similarity to the session at *target_path*.

    The target session itself is excluded. Only sessions with a non-zero
    similarity score are returned, sorted descending.
    """
    opener = _open or _make_default_opener()
    target_path = Path(target_path)
    target = opener(target_path)
    try:
        target_id = target.meta("session_id") or ""
        target_fp = fingerprint(target)
    finally:
        target.close()
    if not target_fp.total:
        return []

    workdir = Path(workspace) if workspace else target_path.parent
    results: list[SimilarSession] = []
    for path in sorted(workdir.glob("*.nrp")):
        try:
            other = opener(path)
        except InvalidNrpError:
            continue
        try:
            other_id = other.meta("session_id") or ""
            if other_id == target_id:
                continue
            other_fp = fingerprint(other)
            score = similarity(target_fp, other_fp)
            if score <= 0.0:
                continue
            results.append(
                SimilarSession(
                    session_id=other_id,
                    name=other.meta("name") or other_id,
                    score=score,
                    shared_domains=[d for d in target_fp.domains if d in other_fp.domains],
                    shared_ips=[ip for ip in target_fp.ips if ip in other_fp.ips],
                    shared_ports=[p for p in target_fp.ports if p in other_fp.ports],
                )
            )
        finally:
            other.close()
    results.sort(key=lambda s: s.score, reverse=True)
    return results[:top]


def _make_default_opener() -> Callable[[Path], SessionStorage]:
    from netreplay.core.storage import open_session

    return lambda path: open_session(path)


def _vector(fp: Fingerprint) -> Counter[str]:
    v: Counter[str] = Counter()
    for key, count in fp.domains.items():
        v[f"d:{key}"] += count * _WEIGHTS["domain"]
    for key, count in fp.ips.items():
        v[f"i:{key}"] += count * _WEIGHTS["ip"]
    for key, count in fp.ports.items():
        v[f"p:{key}"] += count * _WEIGHTS["port"]
    return v


def _cosine(a: Counter[str], b: Counter[str]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(count * b[k] for k, count in a.items())
    norm_a = sum(c * c for c in a.values()) ** 0.5
    norm_b = sum(c * c for c in b.values()) ** 0.5
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)
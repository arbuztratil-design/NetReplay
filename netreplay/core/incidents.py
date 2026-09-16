"""Similarity fingerprints and incident search (#45-46).

Unlike :mod:`netreplay.core.search` — which looks for concrete IPs, domains and
ports — these helpers describe a capture by *behaviour*: the mix of protocol
events, port categories and flow-size buckets. Two captures with completely
different addresses can still be "the same kind of incident", and a saved
:class:`IncidentProbe` can find such captures across a workspace.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from netreplay.core.storage import SessionStorage, open_session

# Port *categories*, so fingerprints do not depend on exact port numbers.
_PORT_CATEGORIES: dict[str, range] = {
    "web": range(80, 81),
    "web-alt": range(443, 444),
    "web-alt2": range(8080, 8081),
    "dns": range(53, 54),
    "mail": range(25, 26),
    "mail-alt": range(587, 588),
}

_PROTOCOL_WEIGHTS = 1.0
_EVENT_WEIGHTS = 1.5
_PORT_WEIGHTS = 0.75


def port_category(port: int | None) -> str:
    if port is None:
        return "none"
    for name, rng in _PORT_CATEGORIES.items():
        if port in rng:
            return name
    if port < 1024:
        return "well-known"
    return "ephemeral"


@dataclass(slots=True)
class PatternFingerprint:
    """Behavioural feature counts (address independent)."""

    protocols: Counter[str] = field(default_factory=Counter)
    events: Counter[str] = field(default_factory=Counter)
    port_categories: Counter[str] = field(default_factory=Counter)

    @property
    def total(self) -> int:
        return sum(self.protocols.values()) + sum(self.events.values()) + sum(
            self.port_categories.values()
        )

    def vector(self) -> dict[str, float]:
        """Weighted, namespaced feature vector for cosine similarity."""
        vec: dict[str, float] = {}
        for name, count in self.protocols.items():
            vec[f"proto:{name}"] = count * _PROTOCOL_WEIGHTS
        for name, count in self.events.items():
            vec[f"event:{name}"] = count * _EVENT_WEIGHTS
        for name, count in self.port_categories.items():
            vec[f"port:{name}"] = count * _PORT_WEIGHTS
        return vec


def build_fingerprint(session: SessionStorage) -> PatternFingerprint:
    """Build a behavioural fingerprint from a stored session (#45)."""
    fp = PatternFingerprint()
    for flow in session.flows():
        if flow.protocol:
            fp.protocols[flow.protocol.upper()] += 1
        fp.port_categories[port_category(flow.dst_port)] += 1
    for row in session.events(limit=1_000_000):
        fp.events[row.event_type.upper()] += 1
    return fp


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    common = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in common)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return max(0.0, min(1.0, dot / (na * nb)))


def fingerprint_similarity(a: PatternFingerprint, b: PatternFingerprint) -> float:
    """Cosine similarity of two behavioural fingerprints in [0, 1]."""
    return _cosine(a.vector(), b.vector())


@dataclass(slots=True)
class IncidentMatch:
    session_id: str
    name: str
    path: str
    score: float


@dataclass(slots=True)
class IncidentProbe:
    """A reusable pattern describing the kind of incident to look for (#46)."""

    name: str = ""
    event_types: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    min_score: float = 0.0

    @classmethod
    def from_session(cls, session: SessionStorage, name: str = "") -> IncidentProbe:
        fp = build_fingerprint(session)
        return cls(
            name=name or (session.meta("name") or "probe"),
            event_types=set(fp.events),
            protocols=set(fp.protocols),
        )

    def matches(self, fingerprint: PatternFingerprint) -> bool:
        if self.event_types and not (self.event_types & set(fingerprint.events)):
            return False
        if self.protocols and not (self.protocols & set(fingerprint.protocols)):
            return False
        return True


def _iter_session_paths(workspace: str | Path):
    root = Path(workspace)
    yield from sorted(root.glob("*.nrp"))


def find_similar_incidents(
    target_path: str | Path,
    workspace: str | Path | None = None,
    top: int = 5,
) -> list[IncidentMatch]:
    """Rank other captures in a workspace by behavioural similarity (#46)."""
    target_session = open_session(target_path)
    if target_session is None:
        raise FileNotFoundError(f"session not found: {target_path}")
    target = build_fingerprint(target_session)
    target_id = target_session.meta("session_id")

    root = Path(workspace) if workspace is not None else Path(target_path).parent
    matches: list[IncidentMatch] = []
    for path in _iter_session_paths(root):
        try:
            session = open_session(path)
        except Exception:  # noqa: BLE001 - skip unreadable files
            continue
        if session is None:
            continue
        if session.meta("session_id") == target_id:
            continue
        score = fingerprint_similarity(target, build_fingerprint(session))
        matches.append(IncidentMatch(
            session_id=session.meta("session_id") or path.stem,
            name=session.meta("name") or path.stem,
            path=str(path),
            score=score,
        ))
    matches.sort(key=lambda m: m.score, reverse=True)
    return matches[:top] if top else matches


def search_by_probe(
    probe: IncidentProbe,
    workspace: str | Path,
    top: int = 5,
) -> list[IncidentMatch]:
    """Find captures matching a stored incident probe (#46)."""
    root = Path(workspace)
    matches: list[IncidentMatch] = []
    for path in _iter_session_paths(root):
        try:
            session = open_session(path)
        except Exception:  # noqa: BLE001
            continue
        if session is None:
            continue
        fp = build_fingerprint(session)
        if not probe.matches(fp):
            continue
        matches.append(IncidentMatch(
            session_id=session.meta("session_id") or path.stem,
            name=session.meta("name") or path.stem,
            path=str(path),
            score=build_fingerprint(session).total,
        ))
    matches.sort(key=lambda m: m.score, reverse=True)
    return matches[:top] if top else matches

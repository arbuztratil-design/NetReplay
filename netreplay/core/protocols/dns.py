"""Minimal DNS analysis: query/response metadata only.

Uses the Scapy ``DNS`` layer parser. No content inspection beyond the
metadata needed to describe a DNS exchange.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_QTYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "SSHFP",
    47: "ANY",
    99: "SPF",
    255: "ANY",
}


def qtype_name(qtype: int) -> str:
    return _QTYPES.get(qtype, str(qtype))


@dataclass(slots=True)
class DNSInfo:
    is_query: bool
    qname: str
    qtype: str
    rcode: int
    answers: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.is_query:
            return f"DNS QUERY {self.qname} ({self.qtype})"
        parts = [f"DNS RESPONSE {self.qname} rcode={self.rcode}"]
        if self.answers:
            parts.append(f"answers={','.join(x for x in self.answers[:6])}")
        return " ".join(parts)


def _first(field):
    """Return the first element of a PacketListField, or the field itself."""
    if field is None:
        return None
    try:
        return field[0]
    except (TypeError, IndexError):
        return field


def _iter(field):
    """Iterate over a PacketListField or a single record."""
    if field is None:
        return []
    try:
        return list(field)
    except TypeError:
        return [field]


def analyze(dns_layer: object) -> DNSInfo | None:
    """Extract basic DNS metadata from a Scapy ``DNS`` layer.

    Returns ``None`` if the layer does not look like a usable DNS message.
    """
    dns = dns_layer
    qname = ""
    qtype = 0
    try:
        qd = _first(getattr(dns, "qd", None))
        if qd is not None and qd.qname:
            qname = qd.qname.decode(errors="replace").rstrip(".")
            qtype = int(qd.qtype)
    except Exception:
        return None

    if not qname and not getattr(dns, "qr", 0):
        return None

    answers: list[str] = []
    try:
        for an in _iter(getattr(dns, "an", None))[:8]:
            answers.append(str(getattr(an, "rdata", "")))
    except Exception:
        answers = []

    return DNSInfo(
        is_query=bool(getattr(dns, "qr", 0) == 0),
        qname=qname,
        qtype=qtype_name(qtype),
        rcode=int(getattr(dns, "rcode", 0)),
        answers=answers,
    )

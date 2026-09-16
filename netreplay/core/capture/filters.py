"""BPF / libpcap capture filters (#26).

Capture-time filtering keeps irrelevant traffic inside the kernel so it never
reaches the Python capture loop. This module validates a BPF expression and
attaches it to a :class:`CaptureBackend`; backends that support libpcap use the
attached expression, while backends without kernel filtering can emulate it.
"""
from __future__ import annotations

from dataclasses import dataclass

from netreplay.core.capture.base import CaptureBackend


class BpfFilterError(ValueError):
    """Raised when a BPF expression is malformed."""


@dataclass(frozen=True, slots=True)
class BpfFilter:
    expression: str

    def __post_init__(self) -> None:
        _validate(self.expression)

    @property
    def is_empty(self) -> bool:
        return not self.expression.strip()

    def to_libpcap_args(self) -> list[str]:
        """Arguments to hand to libpcap/pyshark-style capture APIs."""
        if self.is_empty:
            return []
        return ["-f", self.expression]


def _validate(expression: str) -> None:
    if not isinstance(expression, str):
        raise BpfFilterError("BPF expression must be a string")
    text = expression.strip()
    if not text:
        return
    if text.count("(") != text.count(")"):
        raise BpfFilterError("unbalanced parentheses in BPF expression")
    if text.count("'") % 2 or text.count('"') % 2:
        raise BpfFilterError("unbalanced quotes in BPF expression")
    # Reject obvious shell/injection metacharacters; BPF has no use for them.
    for bad in (";", "&&", "||", "`", "$(", "|"):
        if bad in text:
            raise BpfFilterError(f"illegal token {bad!r} in BPF expression")


def parse_bpf(expression: str) -> BpfFilter:
    """Validate and wrap a BPF expression (empty is allowed = capture all)."""
    return BpfFilter(expression)


def attach_bpf_filter(backend: CaptureBackend, expression: str) -> BpfFilter:
    """Validate *expression* and attach it to *backend* for capture time."""
    bpf = parse_bpf(expression)
    backend.bpf_filter = bpf.expression
    return bpf

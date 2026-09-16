"""Packet mutation pipeline (#36): transform frames before replay.

Mutators are small, composable, pure ``bytes -> bytes`` functions. A
:class:`MutationPipeline` applies them in order so an analyst can, e.g., strip
payloads and bump the TTL while replaying into a test network.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class Mutation(Protocol):
    """A single frame transformation."""

    def apply(self, raw: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class TruncatePayload:
    """Keep at most ``max_length`` bytes of the frame."""

    max_length: int

    def __post_init__(self) -> None:
        if self.max_length <= 0:
            raise ValueError("max_length must be positive")

    def apply(self, raw: bytes) -> bytes:
        return raw[: self.max_length]


@dataclass(frozen=True, slots=True)
class ReplacePattern:
    """Replace every occurrence of ``old`` with ``new`` in the frame."""

    old: bytes
    new: bytes

    def __post_init__(self) -> None:
        if not self.old:
            raise ValueError("old pattern must not be empty")

    def apply(self, raw: bytes) -> bytes:
        return raw.replace(self.old, self.new)


@dataclass(frozen=True, slots=True)
class PadToLength:
    """Zero-pad the frame to at least ``length`` bytes."""

    length: int

    def __post_init__(self) -> None:
        if self.length < 0:
            raise ValueError("length must be non-negative")

    def apply(self, raw: bytes) -> bytes:
        if len(raw) >= self.length:
            return raw
        return raw + bytes(self.length - len(raw))


@dataclass(slots=True)
class MutationPipeline:
    """Applies mutators in order to each frame."""

    mutations: list[Mutation] = field(default_factory=list)

    def add(self, mutation: Mutation) -> "MutationPipeline":
        self.mutations.append(mutation)
        return self

    @property
    def is_empty(self) -> bool:
        return not self.mutations

    def apply(self, raw: bytes) -> bytes:
        result = raw
        for mutation in self.mutations:
            result = mutation.apply(result)
        return result

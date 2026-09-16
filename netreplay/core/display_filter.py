"""Display-filter language (#25).

A small, dependency-free expression language an analyst uses to filter a
capture without touching SQL::

    protocol == tcp and port == 443
    ip == 10.0.0.1 or (dns and not length > 500)

Supported fields: ``ip`` (either endpoint), ``src``/``dst``, ``port`` (either
side), ``sport``/``dport``, ``protocol``, ``length``, ``flow`` (flow id) and
``summary`` (event text). Supported operators: ``== != < <= > >= contains``.
Booleans: ``and``/``or``/``not`` plus parentheses. Bare protocol words such as
``tcp`` or ``dns`` are shorthand for ``protocol == tcp``.

The compiled :class:`Filter` is evaluated in Python against row objects from
the storage layer (``PacketRow``/``FlowRow``/``EventRow``), so the same filter
works for live previews and stored sessions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

_FIELDS = {
    "ip",
    "src",
    "dst",
    "port",
    "sport",
    "dport",
    "protocol",
    "type",
    "length",
    "flow",
    "summary",
}

_OPERATORS = {"==", "!=", "<", "<=", ">", ">=", "contains"}

_BOOLEAN_WORDS = {"and", "or", "not"}

_PROTOCOL_WORDS = {"tcp", "udp", "dns", "tls", "http", "icmp", "arp", "ssl"}


class FilterError(ValueError):
    """Raised when a display filter cannot be parsed."""


class _Row(Protocol):  # pragma: no cover - structural typing only
    def __getattr__(self, name: str) -> Any: ...


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            tokens.append(ch)
            i += 1
            continue
        if ch in "<>=!":
            j = i
            while j < n and text[j] in "<>=!":
                j += 1
            op = text[i:j]
            if op not in _OPERATORS:
                raise FilterError(f"unknown operator {op!r}")
            tokens.append(op)
            i = j
            continue
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch:
                j += 1
            if j >= n:
                raise FilterError("unterminated string literal")
            tokens.append(text[i : j + 1])
            i = j + 1
            continue
        j = i
        while j < n and (not text[j].isspace()) and text[j] not in "()<>=!\"'":
            j += 1
        tokens.append(text[i:j])
        i = j
    return tokens


@dataclass(frozen=True, slots=True)
class _Comparison:
    field: str
    operator: str
    value: str

    def evaluate(self, row: Any) -> bool:
        return _compare(_field_value(self.field, row), self.operator, self.value)


@dataclass(frozen=True, slots=True)
class _And:
    left: Any
    right: Any

    def evaluate(self, row: Any) -> bool:
        return self.left.evaluate(row) and self.right.evaluate(row)


@dataclass(frozen=True, slots=True)
class _Or:
    left: Any
    right: Any

    def evaluate(self, row: Any) -> bool:
        return self.left.evaluate(row) or self.right.evaluate(row)


@dataclass(frozen=True, slots=True)
class _Not:
    node: Any

    def evaluate(self, row: Any) -> bool:
        return not self.node.evaluate(row)


class _Parser:
    def __init__(self, tokens: list[str]):
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> str:
        token = self._peek()
        if token is None:
            raise FilterError("unexpected end of filter")
        self._pos += 1
        return token

    def parse(self) -> Any:
        node = self._or_expr()
        if self._pos != len(self._tokens):
            raise FilterError(f"unexpected token {self._peek()!r}")
        return node

    def _or_expr(self) -> Any:
        node = self._and_expr()
        while self._peek() == "or":
            self._next()
            node = _Or(node, self._and_expr())
        return node

    def _and_expr(self) -> Any:
        node = self._not_expr()
        while self._peek() == "and":
            self._next()
            node = _And(node, self._not_expr())
        return node

    def _not_expr(self) -> Any:
        if self._peek() == "not":
            self._next()
            return _Not(self._not_expr())
        return self._primary()

    def _primary(self) -> Any:
        token = self._peek()
        if token == "(":
            self._next()
            node = self._or_expr()
            if self._next() != ")":
                raise FilterError("missing closing parenthesis")
            return node
        return self._comparison()

    def _comparison(self) -> Any:
        token = self._next()
        if token in _PROTOCOL_WORDS:
            return _Comparison("protocol", "==", token)
        if token not in _FIELDS:
            raise FilterError(f"unknown field {token!r}")
        operator = self._next()
        if operator not in _OPERATORS:
            raise FilterError(f"expected an operator after {token!r}, got {operator!r}")
        value = self._next()
        return _Comparison(token, operator, _unquote(value))


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        return value[1:-1]
    return value


def _field_value(field: str, row: Any) -> Any:
    if field == "ip":
        return [getattr(row, "source", None), getattr(row, "destination", None)]
    if field == "port":
        return [getattr(row, "src_port", None), getattr(row, "dst_port", None)]
    if field == "src":
        return getattr(row, "source", None)
    if field == "dst":
        return getattr(row, "destination", None)
    if field == "sport":
        return getattr(row, "src_port", None)
    if field == "dport":
        return getattr(row, "dst_port", None)
    if field == "flow":
        return getattr(row, "flow_id", None)
    if field == "summary":
        return getattr(row, "summary", None)
    if field == "protocol":
        value = getattr(row, "protocol", None)
        if value is None:
            value = getattr(row, "event_type", None)
        return value
    if field == "type":
        return getattr(row, "event_type", None)
    return getattr(row, field, None)


def _as_number(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compare(actual: Any, operator: str, expected: str) -> bool:
    if isinstance(actual, list):
        return any(_compare(item, operator, expected) for item in actual)
    if actual is None:
        return False
    if operator == "contains":
        return expected.lower() in str(actual).lower()
    if operator in ("==", "!="):
        actual_str = str(actual).lower()
        expected_lower = expected.lower()
        same = actual_str == expected_lower
        expected_num = _as_number(expected)
        actual_num = _as_number(str(actual))
        if expected_num is not None and actual_num is not None:
            same = actual_num == expected_num
        return same if operator == "==" else not same
    left = _as_number(str(actual))
    right = _as_number(expected)
    if left is None or right is None:
        return False
    if operator == "<":
        return left < right
    if operator == "<=":
        return left <= right
    if operator == ">":
        return left > right
    if operator == ">=":
        return left >= right
    raise FilterError(f"unsupported operator {operator!r}")


@dataclass(slots=True)
class Filter:
    """A compiled display filter, reusable across many rows."""

    source: str
    _root: Any

    def matches(self, row: Any) -> bool:
        return bool(self._root.evaluate(row))

    def __call__(self, row: Any) -> bool:
        return self.matches(row)

    def select(self, rows: Any) -> list[Any]:
        return [row for row in rows if self.matches(row)]


def compile_filter(text: str) -> Filter:
    """Compile a display-filter expression. Empty text matches everything."""
    tokens = _tokenize(text)
    if not tokens:
        return Filter(source="", _root=_Comparison("protocol", "contains", ""))
    root = _Parser(tokens).parse()
    return Filter(source=text, _root=root)

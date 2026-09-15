# -*- coding: utf-8 -*-
"""Add for_packet/ancestors/descendants to EventGraph right after the
timeline() method (disk-truth insertion by AST line numbers)."""
import ast, io

P = "netreplay/core/events/models.py"
s = io.open(P, encoding="utf-8").read()
m = ast.parse(s)

cls = next(n for n in m.body if isinstance(n, ast.ClassDef) and n.name == "EventGraph")
tl = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "timeline")
insert_at = tl.end_lineno

block = """

    def for_packet(self, packet_id: int, session_id: str | None = None) -> list[NetworkEvent]:
        \"\"\"Portrait of one packet: every event whose packet_id matches (#21).\"\"\"
        if session_id is None:
            return [e for e in self.events if e.packet_id == packet_id]
        return [e for e in self.events
                if e.packet_id == packet_id and e.session_id == session_id]

    def ancestors(self, event_id: str) -> list[NetworkEvent]:
        \"\"\"Parent chain (oldest first): the events that produced this one.\"\"\"
        chain: list[NetworkEvent] = []
        cur = self.by_id.get(event_id)
        seen: set[str] = set()
        while cur is not None and cur.parent_id is not None:
            if cur.parent_id in seen:
                break
            seen.add(cur.parent_id)
            parent = self.by_id.get(cur.parent_id)
            if parent is None:
                break
            chain.append(parent)
            cur = parent
        chain.reverse()
        return chain

    def descendants(self, event_id: str) -> list[NetworkEvent]:
        \"\"\"Recursive children, depth-first, ts-ordered (#20 projection base).\"\"\"
        out: list[NetworkEvent] = []
        stack = list(reversed(self.children(event_id)))
        seen: set[str] = set()
        while stack:
            ev = stack.pop()
            if ev.id in seen:
                continue
            seen.add(ev.id)
            out.append(ev)
            stack.extend(reversed(self.children(ev.id)))
        out.sort(key=lambda e: e.ts)
        return out
"""

lines = s.splitlines(keepends=True)
lines.insert(insert_at, block)
io.open(P, "w", encoding="utf-8", newline="\n").write("".join(lines))
print("inserted 3 methods after line", insert_at)

# sanity re-parse
src = io.open(P, encoding="utf-8").read()
ast.parse(src)
print("re-parse OK,", len(src), "bytes")

# -*- coding: utf-8 -*-
"""Inject EventGraph.get right after flow_params (verbatim anchor, AST line)."""
import ast, io

P = "netreplay/core/events/models.py"
s = io.open(P, encoding="utf-8").read()
m = ast.parse(s)
g = next(n for n in m.body if isinstance(n, ast.ClassDef) and n.name == "EventGraph")
fp = next(n for n in g.body if isinstance(n, ast.FunctionDef) and n.name == "flow_params")
pos = fp.end_lineno

block = '''    def get(self, event_id: str) -> NetworkEvent | None:
        """One event by id, or None (detail upstream/downstream anchor, #21)."""
        return self.by_id.get(event_id)

'''
lines = s.splitlines(keepends=True)
ins = sum(len(l) for l in lines[:pos])
s2 = s[:ins] + block + s[ins:]
ast.parse(s2)
io.open(P, "w", encoding="utf-8", newline="\n").write(s2)
print("get injected after line", pos)

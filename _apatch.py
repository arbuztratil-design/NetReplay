# -*- coding: utf-8 -*-
"""Inject EventGraph.flow_params right after for_flow (AST-anchored, verbatim)."""
import ast, io

P = "netreplay/core/events/models.py"
s = io.open(P, encoding="utf-8").read()
m = ast.parse(s)
g = next(n for n in m.body if isinstance(n, ast.ClassDef) and n.name == "EventGraph")
ff = next(n for n in g.body if isinstance(n, ast.FunctionDef) and n.name == "for_flow")
pos = ff.end_lineno

block = '''    def flow_params(self, flow_id: str) -> dict:
        """Aggregate params across all events of one flow (detail viewer, #21)."""
        out: dict = {}
        for e in self.by_flow.get(flow_id, []):
            out.update(e.params or {})
        return out
'''
lines = s.splitlines(keepends=True)
ins = sum(len(l) for l in lines[:pos])
s2 = s[:ins] + block + s[ins:]
ast.parse(s2)
io.open(P, "w", encoding="utf-8", newline="\n").write(s2)
print("injected flow_params after line", pos)

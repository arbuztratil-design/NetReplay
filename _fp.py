# -*- coding: utf-8 -*-
"""Add EventGraph.flow_params (merge params over one flow's events, #21)
right before the kinds() method. AST-anchored, verbatim channel."""
import ast
import io

P = "netreplay/core/events/models.py"
s = io.open(P, encoding="utf-8").read()
m = ast.parse(s)
g = next(n for n in m.body if isinstance(n, ast.ClassDef) and n.name == "EventGraph")
kinds = next(n for n in g.body if isinstance(n, ast.FunctionDef) and n.name == "kinds")
pos = kinds.lineno

block = '''    def flow_params(self, flow_id: str) -> dict:
        """Params merged across one flow's events (detail upstream feed, #21)."""
        merged: dict = {}
        for e in self.for_flow(flow_id):
            merged.update(e.params or {})
        return merged

'''
lines = s.splitlines(keepends=True)
ins = sum(len(l) for l in lines[: pos - 1])
s2 = s[:ins] + block + s[ins:]
ast.parse(s2)
io.open(P, "w", encoding="utf-8", newline="\n").write(s2)
print("flow_params injected before kinds at line", pos)

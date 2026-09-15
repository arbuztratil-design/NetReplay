# -*- coding: utf-8 -*-
"""Inject two missing helpers into EventGraph: get() and flow_params().

AST-anchored after the existing for_flow() method; verbatim block write.
Channel used: write-tool -> disk (verbatim), bash only runs it.
"""
import ast
import io
import os

P = "netreplay/core/events/models.py"
s = io.open(P, encoding="utf-8").read()
m = ast.parse(s)

g = next(n for n in m.body if isinstance(n, ast.ClassDef) and n.name == "EventGraph")
ff = next(n for n in g.body if isinstance(n, ast.FunctionDef) and n.name == "for_flow")
ins = ff.end_lineno

block = '''    def get(self, event_id: str) -> NetworkEvent | None:
        """Fetch the single flow event with that id, or None."""
        return self.by_id.get(event_id)

    def flow_params(self, flow_id: str) -> dict:
        """Merged params across all events of one flow, for the detail card."""
        merged: dict = {}
        for e in self.for_flow(flow_id):
            merged.update(e.params or {})
        return merged

'''
lines = s.splitlines(keepends=True)
off = sum(len(l) for l in lines[:ins])
s2 = s[:off] + block + s[off:]
ast.parse(s2)
io.open(P, "w", encoding="utf-8", newline="\n").write(s2)
print("injected get + flow_params after line", ins)

# -*- coding: utf-8 -*-
"""Verbum-Anker: EventGraph.for_flow existiert nachweislich auf Disk.
Fuegt flow_params + get direkt danach ein und laesst pytest laufen."""
import ast, io, subprocess, sys, os

P = "netreplay/core/events/models.py"
s = io.open(P, encoding="utf-8").read()
m = ast.parse(s)

g = next(n for n in m.body if isinstance(n, ast.ClassDef) and n.name == "EventGraph")
ff = next(n for n in g.body if isinstance(n, ast.FunctionDef) and n.name == "for_flow")
ins_line = ff.end_lineno

block = '''
    def flow_params(self, flow_id: str) -> dict:
        """Merged params of every event in one flow (detail upstream, #21)."""
        out: dict = {}
        for e in self.for_flow(flow_id):
            out.update(e.params or {})
        return out

    def get(self, event_id: str) -> NetworkEvent | None:
        """One event by id — the packet-detail anchor (#21)."""
        return self.by_id.get(event_id)
'''

lines = s.splitlines(keepends=True)
off = sum(len(l) for l in lines[:ins_line])
s2 = s[:off] + block + s[off:]
ast.parse(s2)
io.open(P, "w", encoding="utf-8", newline="\n").write(s2)
print("injected after for_flow (line", ins_line, ")")

import io as _io
sys.stdout.flush()
r = subprocess.run(
    [sys.executable, "-X", "utf8", "-m", "pytest", "tests/test_viewers.py", "-q"],
    capture_output=True, text=True, encoding="utf-8", errors="replace",
)
print(r.stdout.splitlines()[-1] if r.stdout else r.stderr.splitlines()[-1])

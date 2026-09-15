"""Clickable timeline with events positioned by their real timestamps."""
from __future__ import annotations

import time

import flet as ft

from gui import theme

PROTOCOL_ROWS = {"TCP": 0, "DNS": 1, "TLS": 2, "UDP": 3, "ICMP": 4, "ARP": 5, "DECRYPT": 6}
COLORS = {
    "TCP": "#f44336",
    "DNS": "#ff7043",
    "TLS": "#ff8a80",
    "UDP": "#ffab91",
    "ICMP": "#ffd54f",
    "ARP": "#e57373",
    "DECRYPT": "#ff1744",
}
OTHER_COLOR = "#8a8a92"
PLOT_LEFT = 38.0
PLOT_RIGHT = 8.0
ROW_TOP = 4.0
ROW_HEIGHT = 9.0
AXIS_TOP = 69.0


def fmt_ts(ts: float) -> str:
    local = time.localtime(ts)
    return time.strftime("%H:%M:%S", local) + f".{int((ts % 1) * 1000):03d}"


class TimelineWidget:
    def __init__(self, on_select):
        self._on_select = on_select
        self._events: list[dict] = []
        self._width = 600.0
        self._stack = ft.Stack(controls=[], height=94)
        self._info = ft.Text("no events", size=11, color=theme.MUTED)
        self._selected = ft.Text("", size=12, selectable=True)
        self._t0 = 0.0
        self._span = 1.0
        self._selected_event: dict | None = None

    def controls(self) -> list[ft.Control]:
        return [
            ft.GestureDetector(
                content=ft.Container(
                    content=self._stack,
                    height=94,
                    on_size_change=self._on_size,
                    clip_behavior=ft.ClipBehavior.HARD_EDGE,
                    bgcolor=theme.red_tint(0.06),
                    border=ft.border.all(1, theme.red_tint(0.16)),
                    border_radius=4,
                ),
                on_tap=self._on_tap,
            ),
            self._info,
            self._selected,
        ]

    def _on_size(self, e) -> None:
        width = float(e.width)
        if width > PLOT_LEFT + PLOT_RIGHT + 10:
            self._width = width
            self.render()

    def render(self, events: list[dict] | None = None, selected: dict | None = None) -> None:
        if events is not None:
            self._events = events
        if selected is not None:
            self._selected_event = selected

        events = self._events
        if not events:
            self._stack.controls = []
            self._info.value = "no events"
            self._selected.value = "click the timeline to inspect an event"
            return

        t0 = events[0]["timestamp"]
        t1 = events[-1]["timestamp"]
        self._t0 = t0
        self._span = (t1 - t0) or 1.0
        plot_width = max(1.0, self._width - PLOT_LEFT - PLOT_RIGHT)
        controls: list[ft.Control] = []

        for protocol, row_i in PROTOCOL_ROWS.items():
            controls.append(
                ft.Text(protocol, left=2, top=ROW_TOP + row_i * ROW_HEIGHT - 3, size=8)
            )

        for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
            x = PLOT_LEFT + plot_width * fraction
            controls.append(
                ft.Container(
                    left=x,
                    top=0,
                    width=1,
                    height=AXIS_TOP,
                    bgcolor=theme.red_tint(0.22),
                )
            )
            controls.append(
                ft.Text(
                    fmt_ts(t0 + self._span * fraction),
                    left=max(PLOT_LEFT, min(x - 28, self._width - 64)),
                    top=AXIS_TOP + 2,
                    size=8,
                    color="#6f6f78",
                )
            )

        for ev in events:
            row_i = PROTOCOL_ROWS.get(ev["type"], 6)
            color = COLORS.get(ev["type"], OTHER_COLOR)
            x = PLOT_LEFT + (ev["timestamp"] - t0) / self._span * plot_width
            controls.append(
                ft.Container(
                    left=x - 2,
                    top=ROW_TOP + row_i * ROW_HEIGHT,
                    width=4,
                    height=7,
                    bgcolor=color,
                    border_radius=2,
                    tooltip=f"{fmt_ts(ev['timestamp'])} {ev['type']} {ev['summary']}",
                )
            )

        sel = self._selected_event
        sel_ts = sel["timestamp"] if sel else None
        if sel:
            x = PLOT_LEFT + (sel_ts - t0) / self._span * plot_width
            controls.append(
                ft.Container(left=x, top=0, width=2, height=AXIS_TOP, bgcolor=theme.RED)
            )

        self._stack.controls = controls

        self._info.value = f"range {fmt_ts(t0)} - {fmt_ts(t1)}   {len(events)} events"

        if sel:
            self._selected.value = f"{fmt_ts(sel_ts)}  {sel['type']}  {sel['summary']}"
        else:
            self._selected.value = "click the timeline to inspect an event"

    def _on_tap(self, e) -> None:
        if not self._events:
            return
        pos = getattr(e, "local_position", None)
        raw_x = pos.x if pos is not None else getattr(e, "local_x", 0.0)
        plot_width = max(1.0, self._width - PLOT_LEFT - PLOT_RIGHT)
        x = min(max(float(raw_x) - PLOT_LEFT, 0.0), plot_width)
        ts = self._t0 + (x / plot_width) * self._span
        nearest = min(self._events, key=lambda ev: abs(ev["timestamp"] - ts))
        self._on_select(nearest)

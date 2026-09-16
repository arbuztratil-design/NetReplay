"""Flow list widget."""
from __future__ import annotations

import flet as ft

from gui import theme


class FlowList:
    def __init__(self, on_select):
        self._on_select = on_select
        self._count = ft.Text("0 flows", size=11, color=theme.MUTED)
        self._list = ft.ListView(expand=True, spacing=2, padding=4, auto_scroll=False)

    def controls(self) -> list[ft.Control]:
        return [self._count, self._list]

    def render(self, flows: list[dict]) -> None:
        self._count.value = f"{len(flows)} flows"
        self._count.color = theme.RED_SOFT
        tiles: list[ft.Control] = []
        for flow in flows:
            src = f"{flow['source']}:{flow['src_port']}" if flow["src_port"] else flow["source"]
            dst = (
                f"{flow['destination']}:{flow['dst_port']}"
                if flow["dst_port"]
                else flow["destination"]
            )
            pkts = flow["packet_count"]
            size = flow["bytes"]
            title = ft.Text(f"{src}  ->  {dst}", size=12, font_family="monospace", color=theme.TEXT)
            subtitle = ft.Text(
                f"{flow['protocol']}  state={flow['state']}  pkts={pkts}  bytes={size}",
                size=11,
                color=theme.MUTED,
            )
            flow_id = flow["id"]
            tiles.append(
                ft.ListTile(
                    title=title,
                    subtitle=subtitle,
                    dense=True,
                    hover_color=theme.muted_red(0.06),
                    on_click=lambda _e, fid=flow_id: self._on_select(fid),
                )
            )
            tiles.append(ft.Divider(height=1, color=theme.red_tint(0.14)))
        self._list.controls = tiles

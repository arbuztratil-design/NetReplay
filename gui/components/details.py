"""Event / flow details widget."""
from __future__ import annotations

import time

import flet as ft


def _fmt(ts: float) -> str:
    local = time.localtime(ts)
    return time.strftime("%H:%M:%S", local) + f".{int((ts % 1) * 1000):03d}"


class DetailsPanel:
    def __init__(self):
        self._header = ft.Text("Details", size=14, weight=ft.FontWeight.BOLD)
        self._event = ft.Text("", size=12, color=ft.Colors.BLUE_200, selectable=True)
        self._flow = ft.Text("", size=12, color=ft.Colors.TEAL_200, selectable=True)
        self._body = ft.ListView(expand=True, spacing=2, padding=4)

    def controls(self) -> list[ft.Control]:
        return [self._header, self._event, self._flow, self._body]

    def show_event(self, event: dict) -> None:
        self._event.value = (
            f"{_fmt(event['timestamp'])}  {event['type']}  {event['summary']}"
        )
        hint = "select a flow to see its packets" if not event.get("flow_id") else (
            f"flow #{event['flow_id']} - select it in the list for packets"
        )
        self._flow.value = hint

    def show_flow(self, flow: dict) -> None:
        src = f"{flow['source']}:{flow['src_port']}" if flow["src_port"] else flow["source"]
        dst = (
            f"{flow['destination']}:{flow['dst_port']}"
            if flow["dst_port"]
            else flow["destination"]
        )
        lines = [
            f"Flow #{flow['id']}",
            f"{flow['protocol']}  {src} -> {dst}",
            f"state {flow['state']}   start {_fmt(flow['start_ts'])}   "
            f"end {_fmt(flow['end_ts'])}",
            f"packets {flow['packet_count']}   bytes {flow['bytes']}",
            "",
            "packets:",
        ]
        self._flow.value = "\n".join(lines)
        tiles: list[ft.Control] = []
        for pkt in flow.get("packets", []):
            src = f"{pkt['source']}:{pkt['src_port']}" if pkt["src_port"] else pkt["source"]
            dst = (
                f"{pkt['destination']}:{pkt['dst_port']}"
                if pkt["dst_port"]
                else pkt["destination"]
            )
            tiles.append(
                ft.Text(
                    f"{_fmt(pkt['ts'])}  #{pkt['id']}  {pkt['protocol']}  "
                    f"{src} -> {dst}  len={pkt['length']}",
                    size=11,
                    font_family="monospace",
                )
            )
        self._body.controls = tiles

    def show_message(self, message: str) -> None:
        self._event.value = message
        self._flow.value = ""
        self._body.controls = []
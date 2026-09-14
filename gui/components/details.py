"""Event / flow / packet details widget."""
from __future__ import annotations

import time

import flet as ft


def _fmt(ts: float) -> str:
    local = time.localtime(ts)
    return time.strftime("%H:%M:%S", local) + f".{int((ts % 1) * 1000):03d}"


def _printable_runs(data: bytes, min_run: int = 3) -> list[str]:
    """Readable ASCII runs from the raw bytes (e.g. HTTP host line)."""
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
            continue
        if len(cur) >= min_run:
            out.append(cur.decode("ascii"))
        cur.clear()
    if len(cur) >= min_run:
        out.append(cur.decode("ascii"))
    return out


def _hexdump(data: bytes) -> list[str]:
    lines: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hexs:<47}  {ascii_}")
    return lines


class DetailsPanel:
    def __init__(self, on_packet_click=None):
        self._on_packet_click = on_packet_click
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
            "packets (click for content):",
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
            pkt_id = pkt["id"]
            tiles.append(
                ft.GestureDetector(
                    content=ft.Text(
                        f"{_fmt(pkt['ts'])}  #{pkt_id}  {pkt['protocol']}  "
                        f"{src} -> {dst}  len={pkt['length']}",
                        size=11,
                        font_family="monospace",
                    ),
                    on_tap=lambda _e, pid=pkt_id: self._on_packet_click(pid)
                    if self._on_packet_click
                    else None,
                )
            )
        self._body.controls = tiles

    def show_packet(self, packet: dict, raw_hex: str) -> None:
        src = f"{packet['source']}:{packet['src_port']}" if packet["src_port"] else packet["source"]
        dst = (
            f"{packet['destination']}:{packet['dst_port']}"
            if packet["dst_port"]
            else packet["destination"]
        )
        self._event.value = (
            f"packet #{packet['id']}  {_fmt(packet['ts'])}  {packet['protocol']}  "
            f"{src} -> {dst}  len={packet['length']}"
        )
        data = bytes.fromhex(raw_hex) if raw_hex else b""
        section: list[ft.Control] = []
        runs = _printable_runs(data)
        if runs:
            section.append(
                ft.Text(
                    "printable:  " + ".  ".join(runs[:6]),
                    size=11,
                    color=ft.Colors.GREEN_300,
                    selectable=True,
                )
            )
            section.append(ft.Divider(height=1, color=ft.Colors.GREY_800))
        section.extend(
            ft.Text(line, size=11, font_family="monospace", selectable=True)
            for line in _hexdump(data)
        )
        self._flow.value = f"flow #{packet.get('flow_id')}   raw frame bytes {len(data)}"
        self._body.controls = section

    def show_message(self, message: str) -> None:
        self._event.value = message
        self._flow.value = ""
        self._body.controls = []
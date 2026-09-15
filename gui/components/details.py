"""Event / flow / packet details widget."""
from __future__ import annotations

import time

import flet as ft

from gui import theme


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


def _endpoint(host: str, port) -> str:
    return f"{host}:{port}" if port else host


def _mono(text: str, size: int = 11, color=None) -> ft.Text:
    return ft.Text(text, size=size, font_family="monospace", selectable=True, color=color)


class DetailsPanel:
    def __init__(self, on_packet_click=None):
        self._on_packet_click = on_packet_click
        self._header = ft.Text("Details", size=13, weight=ft.FontWeight.BOLD, color=theme.RED_SOFT)
        self._event = ft.Text("", size=12, color=theme.RED_SOFT, selectable=True)
        self._flow = ft.Text("", size=12, color=theme.RED_WARM, selectable=True)
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
                    color=theme.RED_WARM,
                    selectable=True,
                )
            )
            section.append(ft.Divider(height=1, color=theme.DIVIDER))
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

    def show_search(self, result: dict, query: str) -> None:
        total = result.get("total", 0)
        self._event.value = f"search '{result.get('query') or query}': {total} match(es)"
        self._flow.value = ""
        units: list[ft.Control] = []
        events = result.get("events") or []
        if events:
            units.append(ft.Text(f"events ({len(events)})", size=12, weight=ft.FontWeight.BOLD))
            for ev in events:
                units.append(
                    _mono(f"{_fmt(ev['timestamp'])}  {ev['type']:<5} {ev['summary']}")
                )
        flows = result.get("flows") or []
        if flows:
            units.append(ft.Text(f"flows ({len(flows)})", size=12, weight=ft.FontWeight.BOLD))
            for row in flows:
                units.append(
                    _mono(
                        f"#{row['id']}  {row['protocol']:<6} "
                        f"{_endpoint(row['source'], row['src_port'])} -> "
                        f"{_endpoint(row['destination'], row['dst_port'])}  "
                        f"{row['packet_count']} pkts"
                    )
                )
        packets = result.get("packets") or []
        if packets:
            units.append(ft.Text(f"packets ({len(packets)})", size=12, weight=ft.FontWeight.BOLD))
            for pkt in packets:
                units.append(
                    _mono(
                        f"#{pkt['id']}  {_fmt(pkt['ts'])}  {pkt['protocol']:<6} "
                        f"{_endpoint(pkt['source'], pkt['src_port'])} -> "
                        f"{_endpoint(pkt['destination'], pkt['dst_port'])}"
                    )
                )
        if not units:
            units.append(_mono("(no matches)", color=theme.MUTED))
        self._body.controls = units

    def show_similar(self, items: list[dict]) -> None:
        self._event.value = f"similar sessions: {len(items)}"
        self._flow.value = ""
        rows: list[ft.Control] = []
        if not items:
            rows.append(_mono("(no similar sessions)", color=theme.MUTED))
        for it in items:
            score = it.get("score", 0.0) * 100
            detail: list[str] = []
            if it.get("shared_domains"):
                detail.append("domains: " + ",".join(it["shared_domains"][:8]))
            if it.get("shared_ips"):
                detail.append("ips: " + ",".join(it["shared_ips"][:8]))
            if it.get("shared_ports"):
                detail.append("ports: " + ",".join(it["shared_ports"][:8]))
            lines = [
                ft.Text(
                    f"{score:5.1f}%  {it.get('name')}  {it.get('session_id')}",
                    size=12,
                    weight=ft.FontWeight.BOLD,
                    selectable=True,
                )
            ]
            if detail:
                lines.append(
                    _mono("  ".join(detail), color=theme.MUTED)
                )
            rows.append(ft.Column(lines, spacing=0))
        self._body.controls = rows
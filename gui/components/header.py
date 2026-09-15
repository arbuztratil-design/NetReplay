"""Header widget: capture controls, interface picker, session picker."""
from __future__ import annotations

import flet as ft

from gui import theme


class Header:
    def __init__(self, on_start, on_stop, on_open, on_refresh, on_replay, on_replay_stop,
                 on_bridge, on_bridge_stop, on_search, on_similar):
        self._on_start = on_start
        self._on_stop = on_stop
        self._on_open = on_open
        self._on_refresh = on_refresh
        self._on_replay = on_replay
        self._on_replay_stop = on_replay_stop
        self._on_bridge = on_bridge
        self._on_bridge_stop = on_bridge_stop
        self._on_search = on_search
        self._on_similar = on_similar

        self.interface = ft.Dropdown(
            width=420,
            label="Interface",
            options=[],
        )
        self.start_btn = ft.FilledButton("Start Capture", on_click=lambda _e: self._on_start())
        self.stop_btn = ft.OutlinedButton("Stop", disabled=True, on_click=lambda _e: self._on_stop())
        self.session = ft.Dropdown(width=220, label="Capture", options=[])
        self.open_btn = ft.OutlinedButton("Open", on_click=lambda _e: self._on_open())
        self.refresh_btn = ft.IconButton(ft.Icons.REFRESH, on_click=lambda _e: self._on_refresh())
        self.search_tf = ft.TextField(
            width=200,
            label="Find (IP / domain)",
            on_submit=lambda _e: self._on_search(),
        )
        self.search_btn = ft.OutlinedButton("Find", on_click=lambda _e: self._on_search())
        self.similar_btn = ft.OutlinedButton("Similar", on_click=lambda _e: self._on_similar())
        self.replay_btn = ft.FilledTonalButton(
            "Replay Out", disabled=True, on_click=lambda _e: self._on_replay()
        )
        self.replay_stop_btn = ft.OutlinedButton(
            "Stop Replay", disabled=True, on_click=lambda _e: self._on_replay_stop()
        )
        self.bridge_btn = ft.FilledTonalButton(
            "Bridge", on_click=lambda _e: self._on_bridge()
        )
        self.bridge_stop_btn = ft.OutlinedButton(
            "Stop Bridge", disabled=True, on_click=lambda _e: self._on_bridge_stop()
        )
        self.status = ft.Text("", size=11, color=theme.MUTED)
        self.info = ft.Text("", size=11, color=theme.RED_SOFT)
        self.diag = ft.Text("", size=11, color=theme.MUTED)
        self.replay_text = ft.Text("", size=11, color=theme.MUTED)
        self.bridge_text = ft.Text("", size=11, color=theme.MUTED)

    def controls(self) -> list[ft.Control]:
        return [
            ft.Row(
                [
                    self.interface,
                    self.start_btn,
                    self.stop_btn,
                    ft.VerticalDivider(),
                    self.session,
                    self.open_btn,
                    self.refresh_btn,
                    ft.VerticalDivider(),
                    self.search_tf,
                    self.search_btn,
                    self.similar_btn,
                    ft.VerticalDivider(),
                    self.replay_btn,
                    self.replay_stop_btn,
                    ft.VerticalDivider(),
                    self.bridge_btn,
                    self.bridge_stop_btn,
                ],
                wrap=True,
            ),
            ft.Row(
                [self.info, self.status, self.diag, self.replay_text, self.bridge_text],
                wrap=True,
            ),
        ]

    def set_interfaces(self, interfaces: list[dict], selected: str | None = None) -> None:
        opts = [
            ft.DropdownOption(
                key=i["name"],
                text=f"{i['name']}  [{i['description']}]" if i.get("description") else i["name"],
                tooltip=i.get("description") or i["name"],
            )
            for i in interfaces
        ]
        current = self.interface.value
        self.interface.options = opts
        keep = selected or current
        if keep and any(o.key == keep for o in opts):
            self.interface.value = keep

    def set_sessions(self, sessions: list[dict]) -> None:
        opts = [
            ft.DropdownOption(key=s["session_id"], text=f"{s['name']} ({s['packet_count']} pkts)")
            for s in sessions
        ]
        current = self.session.value
        self.session.options = opts
        if current and any(o.key == current for o in opts):
            self.session.value = current

    def set_capture(self, running: bool, packets: int, flows: int, error: str | None) -> None:
        self.start_btn.disabled = running
        self.stop_btn.disabled = not running
        if error:
            self.status.value = f"capture error: {error}"
            self.status.color = theme.RED
        elif running:
            self.status.value = f"capturing... packets={packets} flows={flows}"
            self.status.color = theme.RED_SOFT
        else:
            self.status.value = f"idle (packets={packets} flows={flows})"
            self.status.color = theme.MUTED

    def set_replay(self, running: bool, packets: int, bytes_: int, dry_run: bool, error: str | None) -> None:
        self.replay_btn.disabled = running
        self.replay_stop_btn.disabled = not running
        if error:
            self.replay_text.value = f"replay error: {error}"
            self.replay_text.color = theme.RED
        elif running:
            phase = "dry run" if dry_run else "injecting"
            self.replay_text.value = f"replay: {phase}... packets={packets} bytes={bytes_}"
            self.replay_text.color = theme.RED_SOFT
        else:
            self.replay_text.value = f"replay: done ({packets} packets, {bytes_} bytes)"
            self.replay_text.color = theme.MUTED

    def set_replay_available(self, available: bool) -> None:
        self.replay_btn.disabled = not available

    def set_bridge(self, running: bool, left: str | None, right: str | None,
                   left_forwarded: int | None, right_forwarded: int | None,
                   error: str | None) -> None:
        self.bridge_btn.disabled = running
        self.bridge_stop_btn.disabled = not running
        if error:
            self.bridge_text.value = f"bridge error: {error}"
            self.bridge_text.color = theme.RED
        elif running:
            self.bridge_text.value = (
                f"bridge: {left} <-> {right}  "
                f"L->R={left_forwarded or 0}  R->L={right_forwarded or 0}"
            )
            self.bridge_text.color = theme.RED_SOFT
        else:
            self.bridge_text.value = "bridge: stopped"
            self.bridge_text.color = theme.MUTED
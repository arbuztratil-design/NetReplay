"""NetReplay Flet GUI entry point.

The GUI is a client of the NetReplay API. It polls the REST endpoints and
refreshes the current session while a capture is running. All packet parsing,
capture and storage logic lives in the Core, never in the GUI.
"""
from __future__ import annotations

import logging
import os
import threading

import flet as ft

from gui import theme
from gui.api import ApiError, NetReplayClient
from gui.components.details import DetailsPanel
from gui.components.flow_list import FlowList
from gui.components.header import Header
from gui.components.timeline import TimelineWidget

logger = logging.getLogger(__name__)


class NetReplayGui:
    def __init__(self, page: ft.Page):
        self.page = page
        api_url = os.environ.get("NETREPLAY_API_URL", "http://127.0.0.1:8000")
        self.api = NetReplayClient(api_url)
        self._running = threading.Event()
        self._running.set()
        self._loaded_session: str | None = None
        self._live_session: str | None = None
        self._api_warned = False
        self._iface_count: int | None = None
        self._api_error: str | None = None

        self.header = Header(
            self.on_start, self.on_stop, self.on_open, self.on_refresh,
            self.on_replay, self.on_replay_stop,
            self.on_bridge, self.on_bridge_stop,
            self.on_search, self.on_similar,
        )
        self._replay_speed = "1.0"
        self._replay_dry_run = False

        self.flow_list = FlowList(self.on_flow_selected)
        self.timeline = TimelineWidget(self.on_event_selected)
        self.details = DetailsPanel(self.on_packet_selected)

        page.title = "NetReplay"
        page.theme_mode = ft.ThemeMode.DARK
        page.theme = theme.build_theme()
        page.bgcolor = theme.BLACK
        page.window.width = 1360
        page.window.height = 820

        left = ft.Container(
            content=ft.Column(
                [*self.flow_list.controls()], spacing=4, expand=True
            ),
            width=430,
            padding=8,
        )
        right = ft.Container(
            content=ft.Column(
                [*self.timeline.controls(), ft.Divider(height=1, color=theme.DIVIDER),
                 *self.details.controls()],
                expand=True,
                spacing=6,
            ),
            expand=True,
            padding=8,
        )
        page.add(
            ft.Container(
                expand=True,
                padding=12,
                gradient=ft.LinearGradient(
                    begin=ft.Alignment.TOP_LEFT,
                    end=ft.Alignment.BOTTOM_RIGHT,
                    colors=theme.GRADIENT,
                ),
                content=ft.Column(
                    [
                        ft.Container(
                            padding=ft.Padding.symmetric(vertical=8, horizontal=14),
                            bgcolor=theme.BLACK_SOFT,
                            border_radius=10,
                            border=ft.Border.all(1, theme.red_tint(0.35)),
                            content=ft.Row(
                                [
                                    ft.Icon(ft.Icons.NETWORK_PING, color=theme.RED, size=26),
                                    ft.Text(
                                        "NetReplay",
                                        size=20,
                                        weight=ft.FontWeight.BOLD,
                                        color=theme.RED_SOFT,
                                    ),
                                    ft.Text(
                                        "network traffic time machine",
                                        size=12,
                                        color=theme.MUTED,
                                        italic=True,
                                    ),
                                    ft.Container(expand=True),
                                    ft.Icon(ft.Icons.MONITOR_HEART, color=theme.red_tint(0.6), size=18),
                                    ft.Text("live monitoring", size=11, color=theme.MUTED),
                                ],
                                spacing=10,
                            ),
                        ),
                        ft.Container(
                            padding=10,
                            bgcolor=theme.BLACK_SOFT,
                            border_radius=8,
                            border=ft.Border.all(1, theme.red_tint(0.20)),
                            content=ft.Column(
                                [*self.header.controls()],
                                spacing=8,
                            ),
                        ),
                        ft.Divider(height=1, color=theme.red_tint(0.25)),
                        ft.Row([left, ft.VerticalDivider(color=theme.DIVIDER), right], expand=True, spacing=0),
                    ],
                    expand=True,
                    spacing=8,
                ),
            )
        )
        self._sync_interfaces()
        try:
            self._refresh()
        except ApiError as exc:
            self.details.show_message(
                f"API unreachable: {exc}\nstart the API with: netreplay serve"
            )
        except Exception as exc:  # noqa: BLE001
            self.details.show_message(f"startup error: {exc}")

    # ------------------------------------------------------------- poll loop

    def poll_loop(self) -> None:
        while self._running.is_set():
            try:
                self._refresh()
                self._api_warned = False
            except ApiError as exc:
                if not self._api_warned:
                    self._api_warned = True
                    self.header.diag.value = f"API down: {exc}"
                    self.header.diag.color = theme.RED
                    self.page.update()
                logger.debug("poll failed: %s", exc)
            except Exception:  # noqa: BLE001
                logger.exception("poll crashed")
            self._running.wait(1.0)

    def shutdown(self, _e=None) -> None:
        self._running.clear()

    # ------------------------------------------------------------- API actions

    def _sync_interfaces(self) -> None:
        try:
            interfaces = self.api.interfaces()
        except ApiError as exc:
            self._api_error = str(exc)
            self._iface_count = 0
            self.header.diag.value = f"API down: {exc}"
            self.header.diag.color = theme.RED
            return
        self._api_error = None
        self._iface_count = len(interfaces)
        self.header.diag.value = f"interfaces: {self._iface_count}"
        self.header.diag.color = theme.MUTED
        self.header.set_interfaces(interfaces)

    def _refresh(self) -> None:
        self._sync_interfaces()
        status = self.api.capture_status()
        sessions = self.api.sessions()
        running = bool(status.get("running"))
        self.header.set_capture(running, status.get("packets", 0), status.get("flows", 0), status.get("error"))
        self.header.set_sessions(sessions)

        replay = self.api.replay_status()
        self.header.set_replay(
            bool(replay.get("running")),
            replay.get("packets", 0),
            replay.get("bytes", 0),
            bool(replay.get("dry_run")),
            replay.get("error"),
        )

        bridge = self.api.bridge_status()
        self.header.set_bridge(
            bool(bridge.get("running")),
            bridge.get("left_interface"),
            bridge.get("right_interface"),
            bridge.get("left_forwarded"),
            bridge.get("right_forwarded"),
            bridge.get("error"),
        )

        live = None
        if running:
            live = next(
                (s["session_id"] for s in sessions if s.get("status") == "capturing"),
                None,
            )
        if live is not None:
            self._live_session = live
            self._activate(live, force=True)
        elif self._loaded_session is not None:
            self._activate(self._loaded_session, force=running)
        self.page.update()

    def _activate(self, session_id: str, force: bool = False) -> None:
        if not force and session_id == self._loaded_session:
            return
        try:
            info = self.api.session(session_id)
            flows = self.api.flows(session_id)
            events = self.api.timeline(session_id)
        except ApiError as exc:
            self.details.show_message(f"API error: {exc}")
            return
        self.flow_list.render(flows)
        self.timeline.render(events)
        label = info.get("name") or session_id
        self.header.info.value = (
            f"session: {label}   packets={info.get('packet_count', 0)}"
            f"   flows={info.get('flow_count', 0)}   events={info.get('event_count', 0)}"
        )
        self._loaded_session = session_id
        self.header.set_replay_available(True)
        self.details.show_message(f"loaded session {session_id}")

    def on_refresh(self) -> None:
        self._refresh()
        self.page.update()

    def on_start(self) -> None:
        iface = self.header.interface.value
        if not iface:
            if self._iface_count == 0 and self._api_error:
                msg = (
                    f"API unreachable ({self._api_error}).\n"
                    "start it in another terminal with: netreplay serve"
                )
            elif self._iface_count == 0:
                msg = "API returned no interfaces (is Npcap installed?)"
            else:
                msg = "choose an interface from the list first"
            self.details.show_message(msg)
            self.page.update()
            return
        try:
            self.api.capture_start(iface)
        except ApiError as exc:
            self.details.show_message(f"start capture failed: {exc}")
        self._refresh()
        self.page.update()

    def on_stop(self) -> None:
        try:
            self.api.capture_stop()
        except ApiError as exc:
            self.details.show_message(f"stop capture failed: {exc}")
        self._loaded_session = self._live_session or self._loaded_session
        self._refresh()
        self.page.update()

    def on_search(self) -> None:
        query = (self.header.search_tf.value or "").strip()
        if not query:
            self.details.show_message("enter an IP or domain to search")
            self.page.update()
            return
        if not self._loaded_session:
            self.details.show_message("load a capture first (click Open)")
            self.page.update()
            return
        try:
            result = self.api.search_session(self._loaded_session, query)
        except ApiError as exc:
            self.details.show_message(f"search failed: {exc}")
            self.page.update()
            return
        self.timeline.render(result.get("events") or [])
        self.details.show_search(result, query)
        self.header.info.value = (
            f"search: {result.get('query')} -> {result.get('total', 0)} match(es)"
        )
        self.page.update()

    def on_similar(self) -> None:
        if not self._loaded_session:
            self.details.show_message("load a capture first (click Open)")
            self.page.update()
            return
        try:
            items = self.api.similar_sessions(self._loaded_session)
        except ApiError as exc:
            self.details.show_message(f"similar failed: {exc}")
            self.page.update()
            return
        self.details.show_similar(items)
        self.page.update()

    def on_replay(self) -> None:
        if not self._loaded_session:
            self.details.show_message("load a capture first (click Open)")
            self.page.update()
            return
        iface = self.header.interface.value
        if not iface:
            self.details.show_message("choose an interface for injection")
            self.page.update()
            return
        speed_tf = ft.TextField(value=self._replay_speed, width=80, label="Speed x", autofocus=True)
        dry_sw = ft.Switch(value=self._replay_dry_run, label="dry run (no send)")

        def start(_evt):
            self._replay_speed = speed_tf.value or "1.0"
            self._replay_dry_run = dry_sw.value
            try:
                speed = float(self._replay_speed)
            except ValueError:
                speed = 1.0
            dlg.open = False
            self.page.update()
            try:
                self.api.replay_start(
                    self._loaded_session, iface, speed=speed, dry_run=self._replay_dry_run,
                )
            except ApiError as exc:
                self.details.show_message(f"replay start failed: {exc}")
            self._refresh()
            self.page.update()

        def close_dlg(_evt=None):
            dlg.open = False
            self.page.update()

        dlg = ft.AlertDialog(
            title=ft.Text("Replay Out"),
            content=ft.Column(
                [
                    ft.Text(f"Session: {self._loaded_session[:12]}...  Interface: {iface}"),
                    speed_tf,
                    dry_sw,
                ],
                spacing=8,
            ),
            actions=[
                ft.TextButton("Cancel", on_click=close_dlg),
                ft.FilledButton("Start", on_click=start),
            ],
        )
        self.page.overlay.append(dlg)
        dlg.open = True
        self.page.update()

    def on_replay_stop(self) -> None:
        try:
            self.api.replay_stop()
        except ApiError as exc:
            self.details.show_message(f"replay stop failed: {exc}")
        self._refresh()
        self.page.update()

    def on_bridge(self) -> None:
        try:
            ifaces = self.api.interfaces()
        except ApiError as exc:
            self.details.show_message(f"bridge set-up failed: {exc}")
            self.page.update()
            return
        if not ifaces:
            self.details.show_message("no interfaces available (is Npcap installed?)")
            self.page.update()
            return
        opts = [
            ft.DropdownOption(key=i["name"], text=i["name"]) for i in ifaces
        ]
        left_dd = ft.Dropdown(label="Left interface", options=opts, width=280)
        right_dd = ft.Dropdown(label="Right interface", options=list(opts), width=280)
        if self.header.interface.value not in (None, ""):
            left_dd.value = self.header.interface.value

        def start(_evt):
            left = left_dd.value
            right = right_dd.value
            dlg.open = False
            self.page.update()
            if not left or not right or left == right:
                self.details.show_message("choose two different interfaces")
                self.page.update()
                return
            try:
                self.api.bridge_start(left, right)
            except ApiError as exc:
                self.details.show_message(f"bridge start failed: {exc}")
            self._refresh()
            self.page.update()

        def close_dlg(_evt=None):
            dlg.open = False
            self.page.update()

        dlg = ft.AlertDialog(
            title=ft.Text("Live L2 Bridge"),
            content=ft.Column([left_dd, right_dd], spacing=8),
            actions=[
                ft.TextButton("Cancel", on_click=close_dlg),
                ft.FilledButton("Start", on_click=start),
            ],
        )
        self.page.overlay.append(dlg)
        dlg.open = True
        self.page.update()

    def on_bridge_stop(self) -> None:
        try:
            self.api.bridge_stop()
        except ApiError as exc:
            self.details.show_message(f"bridge stop failed: {exc}")
        self._refresh()
        self.page.update()

    def on_open(self) -> None:
        value = self.header.session.value
        if not value:
            self.details.show_message("choose a capture from the list first")
            self.page.update()
            return
        self._activate(value, force=True)
        self.page.update()

    def on_flow_selected(self, flow_id: int) -> None:
        if not self._loaded_session:
            self.details.show_message("load a capture first (click Open)")
            self.page.update()
            return
        try:
            flow = self.api.flow(self._loaded_session, flow_id, include_packets=True)
        except ApiError as exc:
            self.details.show_message(f"API error: {exc}")
            self.page.update()
            return
        self.details.show_flow(flow)
        self.page.update()

    def on_packet_selected(self, packet_id: int) -> None:
        if not self._loaded_session:
            self.details.show_message("load a capture first (click Open)")
            self.page.update()
            return
        try:
            packet = self.api.packet(self._loaded_session, packet_id, raw=True)
        except ApiError as exc:
            self.details.show_message(f"packet #{packet_id}: API error: {exc}")
            self.page.update()
            return
        self.details.show_packet(packet, packet.get("raw_hex") or "")
        self.page.update()

    def on_event_selected(self, event: dict) -> None:
        self.details.show_event(event)
        self.timeline.render(selected=event)
        self.page.update()


def main(page: ft.Page) -> None:
    gui = NetReplayGui(page)
    page.on_close = gui.shutdown
    page.run_thread(gui.poll_loop)
"""Toolbox widget: tabs exposing every NetReplay feature through the API.

Tabs: Analysis (stats/filter/loss/layers), Scenarios (+annotations),
Compare & Incidents, Export & Sanitize, Regression and Replay. Each action
calls the REST API via :class:`~gui.api.NetReplayClient` and writes a short
result report into the shared output view.
"""
from __future__ import annotations

import json

import flet as ft

from gui import theme
from gui.api import ApiError, NetReplayClient


def _output_text() -> ft.Text:
    return ft.Text("", size=11, font_family="monospace", selectable=True, color=theme.RED_SOFT)


class Toolbox:
    def __init__(
        self,
        client: NetReplayClient,
        get_session_id,
        get_sessions,
        get_interface,
        refresh,
    ):
        self._client = client
        self._get_session_id = get_session_id
        self._get_sessions = get_sessions
        self._get_interface = get_interface
        self._refresh = refresh
        self._output = _output_text()
        self._build()

    # ---------------------------------------------------------------- helpers

    def _session_or_warn(self) -> str | None:
        session_id = self._get_session_id()
        if not session_id:
            self._say("load a capture first (Open)")
            return None
        return session_id

    def _say(self, message: str) -> None:
        self._output.value = message
        self._refresh()

    def _guard(self, label: str, fn) -> None:
        try:
            fn()
        except ApiError as exc:
            self._say(f"{label} failed: {exc}")
        except Exception as exc:  # noqa: BLE001
            self._say(f"{label} error: {type(exc).__name__}: {exc}")

    # -------------------------------------------------------------- building

    def _build(self) -> None:
        self._analysis_tab = self._build_analysis()
        self._scenario_tab = self._build_scenarios()
        self._compare_tab = self._build_compare()
        self._export_tab = self._build_export()
        self._regression_tab = self._build_regression()
        self._replay_tab = self._build_replay()

    def controls(self) -> list[ft.Control]:
        self._tab_defs = [
            ("Analysis", self._analysis_tab),
            ("Scenarios", self._scenario_tab),
            ("Compare/Incidents", self._compare_tab),
            ("Export/Sanitize", self._export_tab),
            ("Regression", self._regression_tab),
            ("Replay", self._replay_tab),
        ]
        self._tab_body = ft.Container(content=self._tab_defs[0][1], padding=4)
        self._tab_buttons = [
            ft.TextButton(label, on_click=lambda _e, i=i: self._select_tab(i))
            for i, (label, _ctrl) in enumerate(self._tab_defs)
        ]
        return [
            ft.Container(
                content=ft.Column(
                    [
                        ft.Text("Toolbox", size=13, weight=ft.FontWeight.BOLD, color=theme.RED_SOFT),
                        ft.Row(self._tab_buttons, wrap=True, spacing=2),
                        ft.Container(
                            content=self._tab_body,
                            height=210,
                            border=ft.Border.all(1, theme.red_tint(0.15)),
                            border_radius=6,
                            padding=4,
                        ),
                        ft.Divider(height=1, color=theme.DIVIDER),
                        self._output,
                    ],
                    spacing=6,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=8,
                border_radius=8,
                border=ft.Border.all(1, theme.red_tint(0.20)),
                bgcolor=theme.BLACK_SOFT,
            )
        ]

    def _select_tab(self, index: int) -> None:
        _label, control = self._tab_defs[index]
        self._tab_body.content = control
        self._refresh()

    # -------------------------------------------------------------- analysis

    def _build_analysis(self) -> ft.Control:
        self._filter_expr = ft.TextField(label="Display filter", width=280,
                                         hint_text="protocol == tcp and port == 443")
        self._filter_kind = ft.Dropdown(
            label="Kind", width=140, value="flows",
            options=[ft.DropdownOption(key=k, text=k) for k in ("flows", "packets", "events")],
        )
        self._layers_packet = ft.TextField(label="Packet id", width=120, value="1")

        def do_stats(_e):
            session = self._session_or_warn()
            if not session:
                return
            self._guard("stats", lambda: self._say(
                json.dumps(self._client.stats(session), indent=2)
            ))

        def do_loss(_e):
            session = self._session_or_warn()
            if not session:
                return
            self._guard("loss", lambda: self._show_loss(session))

        def do_filter(_e):
            session = self._session_or_warn()
            if not session:
                return
            expr = (self._filter_expr.value or "").strip()
            if not expr:
                self._say("enter a filter expression")
                return
            self._guard("filter", lambda: self._show_filter(session, expr))

        def do_layers(_e):
            session = self._session_or_warn()
            if not session:
                return
            try:
                packet_id = int(self._layers_packet.value or "0")
            except ValueError:
                self._say("packet id must be a number")
                return
            self._guard("layers", lambda: self._show_layers(session, packet_id))

        return ft.Column(
            [
                ft.Row([ft.FilledTonalButton("Stats", on_click=do_stats),
                        ft.FilledTonalButton("Packet loss", on_click=do_loss)]),
                ft.Row([self._filter_expr, self._filter_kind,
                        ft.FilledTonalButton("Apply filter", on_click=do_filter)]),
                ft.Row([self._layers_packet,
                        ft.FilledTonalButton("Layer tree + hex", on_click=do_layers)]),
            ],
            spacing=6,
        )

    def _show_filter(self, session: str, expr: str) -> None:
        result = self._client.filter_session(session, expr, self._filter_kind.value or "flows")
        self._say(f"filter '{result['expr']}' ({result['kind']}): {result['count']} match(es)\nids: {result['ids'][:40]}")

    def _show_loss(self, session: str) -> None:
        report = self._client.loss(session)
        lines = [
            f"loss markers: {report['total']}  gaps={report['gaps']} "
            f"retransmissions={report['retransmissions']} overlaps={report['overlaps']}",
            f"duration: {report['duration']:.3f}s",
        ]
        for marker in report["markers"][:30]:
            lines.append(
                f"  flow={marker['flow_id']} {marker['start_ts']:.3f}-{marker['end_ts']:.3f} "
                f"[{marker['severity']}] {marker['detail']}"
            )
        self._say("\n".join(lines))

    def _show_layers(self, session: str, packet_id: int) -> None:
        data = self._client.packet_layers(session, packet_id)
        lines = [f"packet #{packet_id} layers:"]

        def walk(node, depth):
            fields = ", ".join(f"{k}={v}" for k, v in node["fields"].items() if v not in (None, ""))
            lines.append("  " * depth + f"- {node['name']} {fields}".rstrip())
            for child in node["children"]:
                walk(child, depth + 1)

        walk(data["layers"], 0)
        if data.get("hex"):
            lines.append(f"hex ({data['size']} bytes, first rows):")
            for row in data["hex"][:8]:
                lines.append(f"  {row['offset']:08x}  {row['hex']:<47}  {row['ascii']}")
        self._say("\n".join(lines))

    # ------------------------------------------------------------- scenarios

    def _build_scenarios(self) -> ft.Control:
        self._scn_name = ft.TextField(label="Scenario name", width=200)
        self._scn_flows = ft.TextField(label="Flow ids (csv)", width=140)
        self._scn_tags = ft.TextField(label="Tags (csv)", width=140)
        self._scn_id = ft.TextField(label="Scenario id", width=240)
        self._ann_target = ft.Dropdown(
            label="Annotation target", width=160,
            options=[ft.DropdownOption(key=t, text=t) for t in ("packet", "flow", "event", "time-range")],
            value="packet",
        )
        self._ann_target_id = ft.TextField(label="Target id", width=100)
        self._ann_label = ft.TextField(label="Label", width=160)

        def parse_ints(text: str) -> list[int]:
            return [int(x) for x in (text or "").replace(" ", "").split(",") if x]

        def do_create(_e):
            session = self._session_or_warn()
            if not session:
                return
            try:
                scenario = self._client.create_scenario(
                    session,
                    name=self._scn_name.value or "scenario",
                    tags=[t for t in (self._scn_tags.value or "").split(",") if t],
                    flow_ids=parse_ints(self._scn_flows.value),
                )
            except ApiError as exc:
                self._say(f"create scenario failed: {exc}")
                return
            self._say(f"created scenario {scenario['id']}: {scenario['name']}")

        def do_list(_e):
            session = self._session_or_warn()
            if not session:
                return
            items = self._client.scenarios(session)
            if not items:
                self._say("(no scenarios)")
                return
            lines = []
            for s in items:
                runs = self._client.runs(session, s["id"])
                lines.append(f"{s['id']}  {s['status']:<8} {s['name']}  runs={len(runs)}  tags={s['tags']}")
            self._say("\n".join(lines))

        def do_delete(_e):
            session = self._session_or_warn()
            if not session or not self._scn_id.value:
                self._say("enter a scenario id")
                return
            self._client.delete_scenario(session, self._scn_id.value.strip())
            self._say("deleted")

        def do_run(_e):
            session = self._session_or_warn()
            if not session or not self._scn_id.value:
                self._say("enter a scenario id")
                return
            run = self._client.create_run(session, self._scn_id.value.strip(), name="gui run")
            self._client.update_run(session, run["id"], status="done", result={"source": "gui"})
            self._say(f"run {run['id']} -> done")

        def do_annotate(_e):
            session = self._session_or_warn()
            if not session:
                return
            target_id = None
            if self._ann_target_id.value:
                try:
                    target_id = int(self._ann_target_id.value)
                except ValueError:
                    self._say("target id must be numeric")
                    return
            ann = self._client.add_annotation(
                session, self._ann_target.value, target_id, self._ann_label.value or ""
            )
            self._say(f"annotation #{ann['id']} on {ann['target']}")

        def do_list_ann(_e):
            session = self._session_or_warn()
            if not session:
                return
            items = self._client.annotations(session)
            if not items:
                self._say("(no annotations)")
                return
            self._say("\n".join(
                f"#{a['id']} {a['target']}:{a['target_id']} [{a['color']}] {a['label']}"
                for a in items
            ))

        return ft.Column(
            [
                ft.Row([self._scn_name, self._scn_flows, self._scn_tags,
                        ft.FilledTonalButton("Create", on_click=do_create)]),
                ft.Row([self._scn_id, ft.OutlinedButton("List", on_click=do_list),
                        ft.OutlinedButton("Run", on_click=do_run),
                        ft.OutlinedButton("Delete", on_click=do_delete)]),
                ft.Row([self._ann_target, self._ann_target_id, self._ann_label,
                        ft.FilledTonalButton("Annotate", on_click=do_annotate),
                        ft.OutlinedButton("List annotations", on_click=do_list_ann)]),
            ],
            spacing=6,
        )

    # --------------------------------------------------------- compare tab

    def _build_compare(self) -> ft.Control:
        self._cmp_other = ft.Dropdown(label="Compare with session", width=360, options=[])
        self._inc_top = ft.TextField(label="Top", width=80, value="5")

        def refresh_options(_e=None):
            sessions = self._get_sessions()
            self._cmp_other.options = [
                ft.DropdownOption(key=s["session_id"], text=f"{s['name']} ({s['session_id'][:8]})")
                for s in sessions
            ]

        self._refresh_compare_options = refresh_options

        def do_compare(_e):
            session = self._session_or_warn()
            if not session:
                return
            other = self._cmp_other.value
            if not other:
                self._say("choose a second session")
                return
            report = self._client.compare(session, other)
            lines = [
                f"identical: {report['identical']}",
                f"flows added={report['flows']['added']} removed={report['flows']['removed']} changed={report['flows']['changed']}",
                f"duration {report['timing']['duration_before']:.3f}s -> {report['timing']['duration_after']:.3f}s ({report['timing']['duration_delta']:+.3f}s)",
                "events:",
            ]
            for ev in report["events"]:
                if ev["delta"] != 0:
                    lines.append(f"  {ev['type']:<16} {ev['before']}->{ev['after']} ({ev['delta']:+d})")
            self._say("\n".join(lines))

        def do_incidents(_e):
            session = self._session_or_warn()
            if not session:
                return
            try:
                top = int(self._inc_top.value or "5")
            except ValueError:
                top = 5
            items = self._client.incidents(session, top=top)
            if not items:
                self._say("(no similar incidents)")
                return
            self._say("\n".join(f"{m['score'] * 100:5.1f}%  {m['name']}  {m['session_id']}" for m in items))

        return ft.Column(
            [
                ft.Row([self._cmp_other,
                        ft.FilledTonalButton("Refresh list", on_click=refresh_options),
                        ft.FilledTonalButton("Compare", on_click=do_compare)]),
                ft.Row([self._inc_top, ft.FilledTonalButton("Find similar incidents", on_click=do_incidents)]),
            ],
            spacing=6,
        )

    # ---------------------------------------------------------- export tab

    def _build_export(self) -> ft.Control:
        self._exp_format = ft.Dropdown(
            label="Format", width=140, value="json",
            options=[ft.DropdownOption(key=f, text=f) for f in ("json", "ndjson", "csv")],
        )
        self._exp_kind = ft.Dropdown(
            label="CSV kind", width=140, value="packets",
            options=[ft.DropdownOption(key=k, text=k) for k in ("packets", "flows")],
        )

        def do_export(_e):
            session = self._session_or_warn()
            if not session:
                return
            text = self._client.export_text(session, self._exp_format.value or "json",
                                            self._exp_kind.value or "packets")
            preview = "\n".join(text.splitlines()[:40])
            self._say(f"export {self._exp_format.value} ({len(text)} chars), preview:\n{preview}")

        def do_sanitize(_e):
            session = self._session_or_warn()
            if not session:
                return
            report = self._client.sanitize(session)
            self._say(
                f"sanitized -> {report['output']}\n"
                f"flows={report['flows']} packets={report['packets']} events={report['events']}\n"
                f"redacted={report['redacted']}"
            )

        return ft.Column(
            [
                ft.Row([self._exp_format, self._exp_kind,
                        ft.FilledTonalButton("Export (preview)", on_click=do_export)]),
                ft.Row([ft.FilledTonalButton("Sanitize to workspace", on_click=do_sanitize)]),
            ],
            spacing=6,
        )

    # ------------------------------------------------------ regression tab

    def _build_regression(self) -> ft.Control:
        default = json.dumps({
            "cases": [{
                "name": "gui case",
                "session": "<session>.nrp",
                "expect": {"min_packets": 1},
            }]
        }, indent=2)
        self._reg_text = ft.TextField(
            label="Regression cases (JSON)", value=default, multiline=True,
            min_lines=6, max_lines=10, expand=True,
            text_style=ft.TextStyle(font_family="monospace", size=11),
        )

        def do_run(_e):
            try:
                payload = json.loads(self._reg_text.value or "{}")
            except json.JSONDecodeError as exc:
                self._say(f"invalid JSON: {exc}")
                return
            report = self._client.regression_run(payload.get("cases") or [])
            lines = [f"regression: {report['passed']} passed, {report['failed']} failed"]
            for result in report["results"]:
                mark = "PASS" if result["passed"] else "FAIL"
                lines.append(f"  [{mark}] {result['name']}")
                if result.get("error"):
                    lines.append(f"        error: {result['error']}")
                for check in result.get("checks", []):
                    if not check["passed"]:
                        lines.append(f"        failed: {check['name']} ({check['detail']})")
            self._say("\n".join(lines))

        return ft.Column(
            [
                self._reg_text,
                ft.Row([ft.FilledTonalButton("Run regression", on_click=do_run)]),
            ],
            spacing=6,
        )

    # ----------------------------------------------------------- replay tab

    def _build_replay(self) -> ft.Control:
        self._rep_mode = ft.Dropdown(
            label="Mode", width=130, value="story",
            options=[ft.DropdownOption(key=m, text=m) for m in ("story", "faithful")],
        )
        self._rep_speed = ft.TextField(label="Speed x", width=90, value="1.0")
        self._rep_flows = ft.TextField(label="Flow ids (csv)", width=140)
        self._rep_validate = ft.Switch(label="validate frames", value=False)
        self._rep_ipmap = ft.TextField(label="IP map (old=new, csv)", width=260,
                                       hint_text="10.0.0.1=172.16.0.1")
        self._rep_portmap = ft.TextField(label="Port map (old=new, csv)", width=200,
                                         hint_text="443=8443")
        self._rep_truncate = ft.TextField(label="Truncate to (bytes, 0=off)", width=170, value="0")

        def _parse_kv(text: str) -> dict[str, str]:
            out: dict[str, str] = {}
            for pair in (text or "").replace(" ", "").split(","):
                if "=" in pair:
                    key, _, value = pair.partition("=")
                    if key:
                        out[key] = value
            return out

        def do_replay(_e):
            session = self._session_or_warn()
            if not session:
                return
            iface = self._get_interface()
            if not iface:
                self._say("choose an interface for injection")
                return
            try:
                speed = float(self._rep_speed.value or "1.0")
            except ValueError:
                speed = 1.0
            flow_ids = [int(x) for x in (self._rep_flows.value or "").replace(" ", "").split(",") if x]
            ip_map = _parse_kv(self._rep_ipmap.value)
            port_map = {int(k): int(v) for k, v in _parse_kv(self._rep_portmap.value).items()}
            mutations = []
            try:
                truncate = int(self._rep_truncate.value or "0")
            except ValueError:
                truncate = 0
            if truncate > 0:
                mutations.append({"type": "truncate", "max_length": truncate})
            self._client.replay_start(
                session, iface, speed=speed, dry_run=True,
                mode=self._rep_mode.value or "story", flow_ids=flow_ids,
                validate_frames=bool(self._rep_validate.value),
                ip_map=ip_map, port_map=port_map, mutations=mutations,
            )
            self._say("replay started (dry run); see replay status in the header")

        return ft.Column(
            [
                ft.Row([self._rep_mode, self._rep_speed, self._rep_flows, self._rep_validate]),
                ft.Row([self._rep_ipmap, self._rep_portmap, self._rep_truncate]),
                ft.Row([
                    ft.FilledTonalButton("Start replay (dry run)", on_click=do_replay),
                    ft.OutlinedButton("Stop replay",
                                      on_click=lambda _e: self._stop_replay()),
                ]),
            ],
            spacing=6,
        )

    def _stop_replay(self) -> None:
        self._guard("replay stop", lambda: self._say(str(self._client.replay_stop())))

    def refresh_dynamic(self) -> None:
        """Refresh session lists used by the Compare tab."""
        refresh = getattr(self, "_refresh_compare_options", None)
        if refresh is not None:
            try:
                refresh()
            except ApiError:
                pass

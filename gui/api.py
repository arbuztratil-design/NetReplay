"""Thin HTTP client for the NetReplay API."""
from __future__ import annotations

from typing import Any

import httpx


class ApiError(Exception):
    pass


class NetReplayClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            timeout=httpx.Timeout(10.0, connect=3.0), trust_env=False
        )

    def _get(self, path: str, **params: Any) -> Any:
        try:
            resp = self._client.get(f"{self.base_url}{path}", params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise ApiError(f"GET {path}: {exc}") from exc

    def _get_text(self, path: str, **params: Any) -> str:
        try:
            resp = self._client.get(f"{self.base_url}{path}", params=params)
            resp.raise_for_status()
            return resp.text
        except httpx.HTTPError as exc:
            raise ApiError(f"GET {path}: {exc}") from exc

    def _post(self, path: str, body: Any | None = None) -> Any:
        try:
            resp = self._client.post(f"{self.base_url}{path}", json=body or {})
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise ApiError(f"POST {path}: {exc}") from exc

    def _patch(self, path: str, body: Any | None = None) -> Any:
        try:
            resp = self._client.patch(f"{self.base_url}{path}", json=body or {})
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise ApiError(f"PATCH {path}: {exc}") from exc

    def _delete(self, path: str) -> Any:
        try:
            resp = self._client.delete(f"{self.base_url}{path}")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise ApiError(f"DELETE {path}: {exc}") from exc

    # ------------------------------------------------------------------ core

    def interfaces(self) -> list[dict]:
        return self._get("/api/interfaces")

    def sessions(self) -> list[dict]:
        return self._get("/api/sessions")

    def session(self, session_id: str) -> dict:
        return self._get(f"/api/sessions/{session_id}")

    def stats(self, session_id: str) -> dict:
        return self._get(f"/api/sessions/{session_id}/stats")

    def timeline(
        self,
        session_id: str,
        start: float | None = None,
        end: float | None = None,
        flow_id: int | None = None,
        types: str | None = None,
        limit: int = 2000,
    ) -> list[dict]:
        params: dict[str, Any] = {"limit": limit}
        if start is not None:
            params["start"] = start
        if end is not None:
            params["end"] = end
        if flow_id is not None:
            params["flow_id"] = flow_id
        if types:
            params["types"] = types
        return self._get(f"/api/sessions/{session_id}/timeline", **params)

    def flows(self, session_id: str) -> list[dict]:
        return self._get(f"/api/sessions/{session_id}/flows")

    def flow(self, session_id: str, flow_id: int, include_packets: bool = True) -> dict:
        return self._get(
            f"/api/sessions/{session_id}/flows/{flow_id}",
            include_packets="true" if include_packets else "false",
        )

    def packets_page(self, session_id: str, limit: int = 100, offset: int = 0) -> dict:
        return self._get(
            f"/api/sessions/{session_id}/packets", limit=limit, offset=offset
        )

    def packet(self, session_id: str, packet_id: int, raw: bool = False) -> dict:
        return self._get(
            f"/api/sessions/{session_id}/packets/{packet_id}",
            raw="true" if raw else "false",
        )

    def packet_layers(self, session_id: str, packet_id: int) -> dict:
        return self._get(f"/api/sessions/{session_id}/packets/{packet_id}/layers")

    def loss(self, session_id: str) -> dict:
        return self._get(f"/api/sessions/{session_id}/loss")

    def filter_session(
        self, session_id: str, expr: str, kind: str = "flows", limit: int = 500
    ) -> dict:
        return self._get(
            f"/api/sessions/{session_id}/filter", expr=expr, kind=kind, limit=limit
        )

    # ------------------------------------------------------------- scenarios

    def scenarios(self, session_id: str) -> list[dict]:
        return self._get(f"/api/sessions/{session_id}/scenarios")

    def create_scenario(
        self,
        session_id: str,
        name: str,
        description: str = "",
        tags: list[str] | None = None,
        notes: str = "",
        flow_ids: list[int] | None = None,
        start_ts: float | None = None,
        end_ts: float | None = None,
        protocols: list[str] | None = None,
    ) -> dict:
        return self._post(f"/api/sessions/{session_id}/scenarios", {
            "name": name,
            "description": description,
            "tags": tags or [],
            "notes": notes,
            "flow_ids": flow_ids or [],
            "start_ts": start_ts,
            "end_ts": end_ts,
            "protocols": protocols or [],
        })

    def update_scenario(self, session_id: str, scenario_id: str, **fields: Any) -> dict:
        return self._patch(
            f"/api/sessions/{session_id}/scenarios/{scenario_id}", fields
        )

    def delete_scenario(self, session_id: str, scenario_id: str) -> dict:
        return self._delete(f"/api/sessions/{session_id}/scenarios/{scenario_id}")

    def runs(self, session_id: str, scenario_id: str) -> list[dict]:
        return self._get(f"/api/sessions/{session_id}/scenarios/{scenario_id}/runs")

    def create_run(self, session_id: str, scenario_id: str, name: str = "") -> dict:
        return self._post(
            f"/api/sessions/{session_id}/scenarios/{scenario_id}/runs", {"name": name}
        )

    def update_run(self, session_id: str, run_id: str, **fields: Any) -> dict:
        return self._patch(f"/api/sessions/{session_id}/runs/{run_id}", fields)

    def annotations(self, session_id: str) -> list[dict]:
        return self._get(f"/api/sessions/{session_id}/annotations")

    def add_annotation(
        self,
        session_id: str,
        target: str,
        target_id: int | None = None,
        label: str = "",
        notes: str = "",
        color: str = "yellow",
    ) -> dict:
        return self._post(f"/api/sessions/{session_id}/annotations", {
            "target": target,
            "target_id": target_id,
            "label": label,
            "notes": notes,
            "color": color,
        })

    def delete_annotation(self, session_id: str, annotation_id: int) -> dict:
        return self._delete(f"/api/sessions/{session_id}/annotations/{annotation_id}")

    # ------------------------------------------------------------- forensics

    def compare(self, session_id: str, other_id: str) -> dict:
        return self._get(f"/api/sessions/{session_id}/compare/{other_id}")

    def incidents(self, session_id: str, top: int = 5) -> list[dict]:
        return self._get(f"/api/sessions/{session_id}/incidents", top=top)

    def export_text(self, session_id: str, fmt: str = "json", kind: str = "packets") -> str:
        return self._get_text(
            f"/api/sessions/{session_id}/export", format=fmt, kind=kind
        )

    def sanitize(self, session_id: str) -> dict:
        return self._post(f"/api/sessions/{session_id}/sanitize")

    def regression_run(self, cases: list[dict]) -> dict:
        return self._post("/api/regression/run", {"cases": cases})

    # ---------------------------------------------------------------- search

    def search_session(self, session_id: str, query: str, limit: int = 100) -> dict:
        return self._get(f"/api/sessions/{session_id}/search", q=query, limit=limit)

    def similar_sessions(self, session_id: str, top: int = 5) -> list[dict]:
        return self._get(f"/api/sessions/{session_id}/similar", top=top)

    # ---------------------------------------------------------------- capture

    def capture_start(self, interface: str) -> dict:
        return self._post("/api/capture/start", {"interface": interface})

    def capture_stop(self) -> dict:
        return self._post("/api/capture/stop")

    def capture_status(self) -> dict:
        return self._get("/api/capture/status")

    # ----------------------------------------------------------------- replay

    def replay_start(
        self,
        session_id: str,
        interface: str,
        speed: float = 1.0,
        dry_run: bool = False,
        limit: int | None = None,
        offset: int = 0,
        max_gap: float = 5.0,
        mode: str = "story",
        flow_ids: list[int] | None = None,
        start_ts: float | None = None,
        end_ts: float | None = None,
        validate_frames: bool = False,
        ip_map: dict[str, str] | None = None,
        mac_map: dict[str, str] | None = None,
        port_map: dict[str, int] | None = None,
        mutations: list[dict] | None = None,
    ) -> dict:
        body: dict[str, Any] = {
            "interface": interface,
            "speed": speed,
            "max_gap": max_gap,
            "dry_run": dry_run,
            "offset": offset,
            "mode": mode,
            "validate_frames": validate_frames,
            "flow_ids": flow_ids or [],
            "ip_map": ip_map or {},
            "mac_map": mac_map or {},
            "port_map": port_map or {},
            "mutations": mutations or [],
        }
        if limit is not None:
            body["limit"] = limit
        if start_ts is not None:
            body["start_ts"] = start_ts
        if end_ts is not None:
            body["end_ts"] = end_ts
        return self._post(f"/api/replay-out/{session_id}", body)

    def replay_stop(self) -> dict:
        return self._post("/api/replay-out/stop")

    def replay_status(self) -> dict:
        return self._get("/api/replay-out/status")

    # ----------------------------------------------------------------- bridge

    def bridge_start(self, left_interface: str, right_interface: str) -> dict:
        return self._post("/api/bridge/start", {
            "left_interface": left_interface,
            "right_interface": right_interface,
        })

    def bridge_stop(self) -> dict:
        return self._post("/api/bridge/stop")

    def bridge_status(self) -> dict:
        return self._get("/api/bridge/status")

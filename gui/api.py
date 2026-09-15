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

    def _post(self, path: str, body: Any | None = None) -> Any:
        try:
            resp = self._client.post(f"{self.base_url}{path}", json=body or {})
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise ApiError(f"POST {path}: {exc}") from exc

    def interfaces(self) -> list[dict]:
        return self._get("/api/interfaces")

    def sessions(self) -> list[dict]:
        return self._get("/api/sessions")

    def session(self, session_id: str) -> dict:
        return self._get(f"/api/sessions/{session_id}")

    def timeline(
        self,
        session_id: str,
        start: float | None = None,
        end: float | None = None,
        flow_id: int | None = None,
        limit: int = 2000,
    ) -> list[dict]:
        params = {}
        if start is not None:
            params["start"] = start
        if end is not None:
            params["end"] = end
        if flow_id is not None:
            params["flow_id"] = flow_id
        params["limit"] = limit
        return self._get(f"/api/sessions/{session_id}/timeline", **params)

    def flows(self, session_id: str) -> list[dict]:
        return self._get(f"/api/sessions/{session_id}/flows")

    def flow(self, session_id: str, flow_id: int, include_packets: bool = True) -> dict:
        return self._get(
            "/api/sessions/{}/flows/{}".format(session_id, flow_id),
            include_packets="true" if include_packets else "false",
        )

    def packet(self, session_id: str, packet_id: int, raw: bool = False) -> dict:
        return self._get(
            "/api/sessions/{}/packets/{}".format(session_id, packet_id),
            raw="true" if raw else "false",
        )

    def capture_start(self, interface: str) -> dict:
        return self._post("/api/capture/start", {"interface": interface})

    def capture_stop(self) -> dict:
        return self._post("/api/capture/stop")

    def capture_status(self) -> dict:
        return self._get("/api/capture/status")

    def replay_start(
        self,
        session_id: str,
        interface: str,
        speed: float = 1.0,
        dry_run: bool = False,
        limit: int | None = None,
        offset: int = 0,
        max_gap: float = 5.0,
    ) -> dict:
        body = {
            "interface": interface,
            "speed": speed,
            "max_gap": max_gap,
            "dry_run": dry_run,
            "offset": offset,
        }
        if limit is not None:
            body["limit"] = limit
        return self._post(f"/api/replay-out/{session_id}", body)

    def replay_stop(self) -> dict:
        return self._post("/api/replay-out/stop")

    def replay_status(self) -> dict:
        return self._get("/api/replay-out/status")

    def bridge_start(self, left_interface: str, right_interface: str) -> dict:
        return self._post("/api/bridge/start", {
            "left_interface": left_interface,
            "right_interface": right_interface,
        })

    def bridge_stop(self) -> dict:
        return self._post("/api/bridge/stop")

    def bridge_status(self) -> dict:
        return self._get("/api/bridge/status")

    def search_session(self, session_id: str, query: str, limit: int = 100) -> dict:
        return self._get(f"/api/sessions/{session_id}/search", q=query, limit=limit)

    def similar_sessions(self, session_id: str, top: int = 5) -> list[dict]:
        return self._get(f"/api/sessions/{session_id}/similar", top=top)
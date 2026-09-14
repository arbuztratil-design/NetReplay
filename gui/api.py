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

    def flow(self, flow_id: int, include_packets: bool = True) -> dict:
        return self._get(
            "/api/flows/{}".format(flow_id), include_packets="true" if include_packets else "false"
        )

    def packet(self, packet_id: int, raw: bool = False) -> dict:
        return self._get("/api/packets/{}".format(packet_id), raw="true" if raw else "false")

    def capture_start(self, interface: str) -> dict:
        return self._post("/api/capture/start", {"interface": interface})

    def capture_stop(self) -> dict:
        return self._post("/api/capture/stop")

    def capture_status(self) -> dict:
        return self._get("/api/capture/status")
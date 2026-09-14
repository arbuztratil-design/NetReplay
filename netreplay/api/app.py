"""FastAPI application factory."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netreplay.api.routes import capture, flows, packets, replay, sessions, bridge
from netreplay.api.websocket import register_ws
from netreplay.core.service import NetReplayService

logger = logging.getLogger(__name__)


def create_app(workspace: str | Path) -> FastAPI:
    service = NetReplayService(workspace)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        app.state.loop = asyncio.get_running_loop()
        app.state.event_queue = asyncio.Queue()
        app.state.broadcast_task = asyncio.create_task(_broadcast_loop(app))
        logger.info("NetReplay API ready (workspace=%s)", service.workspace)
        try:
            yield
        finally:
            app.state.broadcast_task.cancel()
            try:
                await app.state.broadcast_task
            except asyncio.CancelledError:
                pass

    app = FastAPI(title="NetReplay API", version="0.1.0", lifespan=lifespan)
    app.state.service = service

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(sessions.router, prefix="/api")
    app.include_router(flows.router, prefix="/api")
    app.include_router(packets.router, prefix="/api")
    app.include_router(capture.router, prefix="/api")
    app.include_router(replay.router, prefix="/api")
    app.include_router(bridge.router, prefix="/api")
    register_ws(app)
    return app


async def _broadcast_loop(app: FastAPI) -> None:
    """Forwards live events from the capture thread to all WebSocket peers."""
    from netreplay.api.websocket import manager

    while True:
        event = await app.state.event_queue.get()
        await manager.broadcast(event)
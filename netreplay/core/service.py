"""Capture pipeline and session management.

This is the glue that ties Capture -> Parse -> Flows -> Timeline -> Storage
together. The API and CLI use :class:`NetReplayService`; nothing else should
reach into packet capture or storage directly.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from netreplay.core.capture.base import CaptureBackend, CaptureError
from netreplay.core.capture.pcap_backend import PcapBackend
from netreplay.core.capture.scapy_backend import ScapyBackend
from netreplay.core.flows.tracker import FlowTracker
from netreplay.core.packets.parser import parse_packet
from netreplay.core.replay.inject import ReplayOutService, ReplayOutStatus
from netreplay.core.replay.selection import ReplaySelection
from netreplay.core.replay.timing import ReplayMode
from netreplay.core.proxy.bridge import BridgeService, BridgeStatus
from netreplay.core.storage import open_session
from netreplay.core.storage.database import (
    SessionInfo,
    SessionStorage,
    new_session_id,
)
from netreplay.core.storage.flush import FlushPolicy
from netreplay.core.storage.nrp import InvalidNrpError
from netreplay.core.timeline.service import EventGenerator, TimelineEvent
from netreplay.core.flows.reassembly import TcpReassembler

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CaptureStatus:
    running: bool = False
    interface: str | None = None
    output: str | None = None
    session_id: str | None = None
    packets: int = 0
    flows: int = 0
    dropped: int = 0
    started_at: float | None = None
    error: str | None = None


EventCallback = Callable[[TimelineEvent], None]


class CaptureController:
    """Runs the capture pipeline (scapy -> parser -> flows -> storage) in a
    background thread."""

    def __init__(
        self,
        interface: str,
        output: str | Path,
        on_event: EventCallback | None = None,
        backend: CaptureBackend | None = None,
        flush: FlushPolicy | None = None,
    ) -> None:
        self.interface = interface
        self.output = Path(output)
        self.on_event = on_event
        self._backend = backend or ScapyBackend(interface)
        self._flush = flush or FlushPolicy()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._packets = 0
        self._flows = 0
        self._drops = 0
        self._session_id: str | None = None
        self._started_at: float | None = None
        self._error: str | None = None

    # ------------------------------------------------------------------ public

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._packets = 0
            self._flows = 0
            self._drops = 0
            self._session_id = None
            self._started_at = None
            self._error = None
            self._thread = threading.Thread(
                target=self._run, name="netreplay-capture", daemon=True
            )
            self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        thread = self._thread
        if thread is None:
            return
        try:
            self._backend.stop()
        except CaptureError as exc:
            self._error = str(exc)
        except Exception as exc:  # noqa: BLE001
            self._error = f"stop failed: {exc}"
        thread.join(timeout=timeout)

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for the capture pipeline; return false if it is still running."""
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout=timeout)
        return not thread.is_alive()

    def status(self) -> CaptureStatus:
        with self._lock:
            return CaptureStatus(
                running=bool(self._thread and self._thread.is_alive()),
                interface=self.interface,
                output=str(self.output),
                session_id=self._session_id,
                packets=self._packets,
                flows=self._flows,
                dropped=self._drops,
                started_at=self._started_at,
                error=self._error,
            )

    # ------------------------------------------------------------------ internals

    def _run(self) -> None:
        backend = self._backend
        session: SessionStorage | None = None
        try:
            session = open_session(self.output, create=True)
            session.set_name_and_interface(
                name=f"capture {self.interface}", interface=self.interface
            )
            with self._lock:
                self._session_id = session.meta("session_id")
            tracker = FlowTracker()
            gen = EventGenerator()
            reassemblers: dict[int, TcpReassembler] = {}
            backend.start()
            with self._lock:
                self._started_at = _now()
            flush = self._flush
            session.begin_batch()
            pending = 0
            last_flush = _now()
            for raw in backend.packets():
                try:
                    parsed = parse_packet(raw.data, ts=raw.ts)
                except Exception:  # noqa: BLE001 - never stop capture on a bad frame
                    logger.debug("failed to parse frame", exc_info=True)
                    continue
                result = tracker.feed(parsed)
                session.add_packet(parsed)
                session.upsert_flow(result.flow)
                for event in gen.feed(parsed, result):
                    session.add_event(event.timestamp, event.type, event.flow_id, event.summary)
                    if self.on_event is not None:
                        try:
                            self.on_event(event)
                        except Exception:  # noqa: BLE001
                            logger.exception("event callback failed")
                # --- TCP reassembly: feed segments, surface issues (#13) ---
                if parsed.protocol == "TCP" and result.flow.id is not None:
                    flow_id = result.flow.id
                    reasm = reassemblers.get(flow_id)
                    if reasm is None:
                        reasm = TcpReassembler()
                        reassemblers[flow_id] = reasm
                    tcp_seq = parsed.info.get("tcp_seq", 0)
                    payload = parsed.info.get("raw_payload")
                    if payload is None:
                        payload = raw.data  # fallback: full frame bytes
                    is_server = (
                        parsed.source == result.flow.destination
                        and (parsed.src_port or 0) == (result.flow.dst_port or 0)
                    )
                    if is_server:
                        out = reasm.feed_server(tcp_seq, payload, parsed.ts)
                    else:
                        out = reasm.feed_client(tcp_seq, payload, parsed.ts)
                    if out.issue is not None:
                        ev = gen.feed_reassembly_issue(flow_id, out.issue)
                        session.add_event(ev.timestamp, ev.type, ev.flow_id, ev.summary)
                        if self.on_event is not None:
                            try:
                                self.on_event(ev)
                            except Exception:  # noqa: BLE001
                                logger.exception("event callback failed")
                with self._lock:
                    self._packets += 1
                    self._flows = max(self._flows, result.flow.id or 0)
                pending += 1
                now = _now()
                if flush.should_flush(pending, last_flush, now):
                    session.commit_batch()
                    pending = 0
                    last_flush = now
                    session.begin_batch()
            if session.in_batch:
                session.commit_batch()
            with self._lock:
                self._drops = backend.drops
            session.finalize(dropped=self._drops)
        except CaptureError as exc:
            self._error = str(exc)
            logger.error("capture error: %s", exc)
        except Exception as exc:  # noqa: BLE001
            self._error = f"{type(exc).__name__}: {exc}"
            logger.exception("capture pipeline crashed")
        finally:
            try:
                backend.stop()
            except Exception:  # noqa: BLE001
                pass
            if session is not None:
                try:
                    session.rollback_batch()
                    with self._lock:
                        self._drops = self._drops or backend.drops
                    session.finalize(dropped=self._drops)
                except Exception:  # noqa: BLE001
                    logger.exception("finalize failed")


def _now() -> float:
    import time

    return time.time()


class ReplayOutController:
    """Runs replay-out (L2 frame injection) in a background thread."""

    def __init__(
        self,
        session: SessionStorage,
        interface: str,
        speed: float = 1.0,
        max_gap: float = 5.0,
        dry_run: bool = False,
        offset: int = 0,
        limit: int | None = None,
        mode: ReplayMode = ReplayMode.STORY,
        selection: ReplaySelection | None = None,
        validate: bool = False,
    ) -> None:
        self.interface = interface
        self.session_id = session.meta("session_id")
        self.dry_run = dry_run
        self._mode = mode if isinstance(mode, ReplayMode) else ReplayMode(mode)
        self._service = ReplayOutService(
            session,
            interface=interface,
            speed=speed,
            max_gap=max_gap,
            dry_run=dry_run,
            offset=offset,
            limit=limit,
            mode=mode,
            selection=selection,
            validate=validate,
            on_progress=self._on_progress,
        )
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._status = ReplayOutStatus()

    # ------------------------------------------------------------------ public

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._status = ReplayOutStatus(mode=self._mode.value)
            self._thread = threading.Thread(
                target=self._run, name="netreplay-replay-out", daemon=True
            )
            self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._service.stop()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for replay-out to finish; return false if still running."""
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout=timeout)
        return not thread.is_alive()

    def status(self) -> ReplayOutStatus:
        with self._lock:
            return self._status

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self._thread and self._thread.is_alive())

    # ------------------------------------------------------------------ internals

    def _run(self) -> None:
        result = self._service.run()
        with self._lock:
            self._status = result

    def _on_progress(self, status: ReplayOutStatus) -> None:
        with self._lock:
            self._status = status


class BridgeController:
    """Runs the L2 live bridge in a background thread."""

    def __init__(
        self,
        left_interface: str,
        right_interface: str,
    ) -> None:
        self.left_interface = left_interface
        self.right_interface = right_interface
        self._service = BridgeService(
            left_interface, right_interface, on_progress=self._on_progress,
        )
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._status = BridgeStatus()

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._status = BridgeStatus()
            self._thread = threading.Thread(
                target=self._run, name="netreplay-bridge", daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._service.stop()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self._thread and self._thread.is_alive())

    @property
    def status(self) -> BridgeStatus:
        with self._lock:
            return self._status

    def _run(self) -> None:
        result = self._service.run()
        with self._lock:
            self._status = result

    def _on_progress(self, status: BridgeStatus) -> None:
        with self._lock:
            self._status = status


class NetReplayService:
    """High-level service: session discovery and capture control."""

    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._capture: CaptureController | None = None
        self._replay: ReplayOutController | None = None
        self._bridge: BridgeController | None = None

    # ------------------------------------------------------------------ sessions

    def list_sessions(self) -> list[SessionInfo]:
        result: list[SessionInfo] = []
        for path in sorted(self.workspace.glob("*.nrp")):
            try:
                result.append(open_session(path).info())
            except InvalidNrpError:
                logger.warning("skipping invalid .nrp file %s", path)
        return result

    def get_session_path(self, session_id: str) -> Path | None:
        for path in self.workspace.glob("*.nrp"):
            try:
                storage = open_session(path)
            except InvalidNrpError:
                continue
            if storage.meta("session_id") == session_id:
                return path
        return None

    def open_session(self, session_id: str) -> SessionStorage | None:
        path = self.get_session_path(session_id)
        return open_session(path) if path else None

    # ------------------------------------------------------------------ capture

    def start_capture(
        self,
        interface: str,
        output: str | Path | None = None,
        on_event: EventCallback | None = None,
        backend: CaptureBackend | None = None,
        flush: FlushPolicy | None = None,
    ) -> CaptureController:
        if self._capture is not None and self._capture.status().running:
            raise CaptureError("a capture is already running")
        path = Path(output) if output else self.workspace / f"{new_session_id()}.nrp"
        controller = CaptureController(
            interface=interface, output=path, on_event=on_event, backend=backend,
            flush=flush,
        )
        controller.start()
        self._capture = controller
        return controller

    def import_pcap(
        self,
        source: str | Path,
        output: str | Path | None = None,
        timeout: float = 300.0,
        keylog: str | Path | None = None,
    ) -> CaptureStatus:
        """Convert a PCAP/PCAPNG file into an analyzed NetReplay session.

        When *keylog* points to an NSS key log file with CLIENT_RANDOM lines,
        the imported session is post-processed: TLS 1.2 AES-GCM application
        data is decrypted and emitted as DECRYPT timeline events.
        """
        source_path = Path(source)
        path = Path(output) if output else self.workspace / f"{source_path.stem}.nrp"
        controller = CaptureController(
            interface=f"pcap:{source_path}",
            output=path,
            backend=PcapBackend(source_path),
        )
        controller.start()
        completed = controller.wait(timeout=timeout)
        status = controller.status()
        if not completed:
            controller.stop(timeout=10.0)
            raise CaptureError(f"PCAP import timed out after {timeout:g} seconds")
        if status.error:
            raise CaptureError(status.error)
        if keylog is not None:
            self._decrypt_session(path, keylog)
        return status

    def _decrypt_session(self, path: Path, keylog: str | Path) -> None:
        from netreplay.core.protocols.decrypt_service import decrypt_session

        session = open_session(path)
        try:
            count = decrypt_session(session, str(keylog))
        finally:
            session.close()
        logger.info("TLS 1.2 decryption emitted %d DECRYPT event(s)", count)

    def stop_capture(self, timeout: float = 10.0) -> CaptureStatus:
        if self._capture is None:
            return CaptureStatus()
        self._capture.stop(timeout=timeout)
        status = self._capture.status()
        self._capture = None
        return status

    @property
    def capture(self) -> CaptureController | None:
        return self._capture

    # ------------------------------------------------------------------ replay-out

    def start_replay(
        self,
        session_id: str,
        interface: str,
        speed: float = 1.0,
        max_gap: float = 5.0,
        dry_run: bool = False,
        offset: int = 0,
        limit: int | None = None,
        mode: ReplayMode = ReplayMode.STORY,
        selection: ReplaySelection | None = None,
        validate: bool = False,
    ) -> ReplayOutController:
        if self._replay is not None and self._replay.running:
            raise CaptureError("a replay-out is already running")
        session = self.open_session(session_id)
        if session is None:
            raise CaptureError(f"session not found: {session_id}")
        controller = ReplayOutController(
            session,
            interface=interface,
            speed=speed,
            max_gap=max_gap,
            dry_run=dry_run,
            offset=offset,
            limit=limit,
            mode=mode,
            selection=selection,
            validate=validate,
        )
        controller.start()
        self._replay = controller
        return controller

    def stop_replay(self, timeout: float = 10.0) -> ReplayOutStatus:
        if self._replay is None:
            return ReplayOutStatus()
        self._replay.stop(timeout=timeout)
        status = self._replay.status()
        self._replay = None
        return status

    @property
    def replay(self) -> ReplayOutController | None:
        return self._replay

    # ------------------------------------------------------------------ bridge

    def start_bridge(
        self,
        left_interface: str,
        right_interface: str,
    ) -> BridgeController:
        if self._bridge is not None and self._bridge.running:
            raise CaptureError("a bridge is already running")
        controller = BridgeController(
            left_interface=left_interface,
            right_interface=right_interface,
        )
        controller.start()
        self._bridge = controller
        return controller

    def stop_bridge(self, timeout: float = 10.0) -> BridgeStatus:
        if self._bridge is None:
            return BridgeStatus()
        self._bridge.stop(timeout=timeout)
        status = self._bridge.status
        self._bridge = None
        return status

    @property
    def bridge(self) -> BridgeController | None:
        return self._bridge

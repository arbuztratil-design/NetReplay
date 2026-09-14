"""L2 live bridge: ordering, bidirectional forwarding, stop, error handling."""
from __future__ import annotations

import queue
import threading

from netreplay.core.proxy.bridge import BridgeService


class FakePacket:
    def __init__(self, raw: bytes, ts: float = 0.0):
        self._raw = raw
        self.time = ts

    def __bytes__(self):
        return self._raw


class FakeSniffer:
    """Simulates ScapyBackend: yields frames from a queue, stops when None is placed."""

    def __init__(self, iface: str, frames: list[bytes] | None = None):
        self.iface = iface
        self._queue: queue.Queue = queue.Queue()
        self._started = False
        self._stopped = False
        if frames:
            for f in frames:
                self._queue.put(FakePacket(f))

    @property
    def running(self) -> bool:
        return self._started and not self._stopped

    def start(self) -> None:
        self._started = True

    def packets(self):
        while True:
            item = self._queue.get()
            if item is None:
                break
            yield item

    def stop(self) -> None:
        self._stopped = True

    def inject(self, raw: bytes | None) -> None:
        if raw is None:
            self._queue.put(None)
        else:
            self._queue.put(FakePacket(raw))


class FakeSender:
    def __init__(self, iface: str):
        self.iface = iface
        self.sent: list[tuple[str, bytes]] = []
        self.closed = False

    def send(self, raw: bytes) -> None:
        self.sent.append((self.iface, raw))

    def close(self) -> None:
        self.closed = True


class BrokenSender(FakeSender):
    def send(self, raw: bytes) -> None:
        raise RuntimeError("wire down")


class BridgeTestHarness:
    """Collects sniffers and senders by interface name for test inspection."""

    def __init__(self):
        self.sniffers: dict[str, FakeSniffer] = {}
        self.senders: dict[str, FakeSender] = {}

    def sniffer_factory(self, iface: str) -> FakeSniffer:
        if iface not in self.sniffers:
            self.sniffers[iface] = FakeSniffer(iface)
        return self.sniffers[iface]

    def sender_factory(self, iface: str) -> FakeSender:
        if iface not in self.senders:
            self.senders[iface] = FakeSender(iface)
        return self.senders[iface]


def test_bidirectional_forwarding(monkeypatch):
    monkeypatch.setattr("netreplay.core.proxy.bridge.time.sleep", lambda s: None)
    harness = BridgeTestHarness()
    sniffer_l = harness.sniffer_factory("eth0")
    sniffer_l.inject(b"frame-from-left")
    sniffer_l.inject(None)  # stop
    sniffer_r = harness.sniffer_factory("eth1")
    sniffer_r.inject(b"frame-from-right")
    sniffer_r.inject(None)

    service = BridgeService(
        "eth0", "eth1",
        sniffer_factory=harness.sniffer_factory,
        sender_factory=harness.sender_factory,
    )
    status = service.run()
    assert status.left_forwarded == 1
    assert status.right_forwarded == 1
    assert harness.senders["eth0"].sent == [("eth0", b"frame-from-right")]
    assert harness.senders["eth1"].sent == [("eth1", b"frame-from-left")]


def test_empty_queues_forward_nothing(monkeypatch):
    monkeypatch.setattr("netreplay.core.proxy.bridge.time.sleep", lambda s: None)
    harness = BridgeTestHarness()
    harness.sniffer_factory("eth0").inject(None)
    harness.sniffer_factory("eth1").inject(None)

    status = BridgeService(
        "eth0", "eth1",
        sniffer_factory=harness.sniffer_factory,
        sender_factory=harness.sender_factory,
    ).run()
    assert status.left_forwarded == 0
    assert status.right_forwarded == 0
    assert status.errors == 0


def test_multiple_frames(monkeypatch):
    monkeypatch.setattr("netreplay.core.proxy.bridge.time.sleep", lambda s: None)
    harness = BridgeTestHarness()
    sniffer_l = harness.sniffer_factory("eth0")
    for i in range(5):
        sniffer_l.inject(b"f" + str(i).encode())
    sniffer_l.inject(None)
    harness.sniffer_factory("eth1").inject(None)

    status = BridgeService(
        "eth0", "eth1",
        sniffer_factory=harness.sniffer_factory,
        sender_factory=harness.sender_factory,
    ).run()
    assert status.left_forwarded == 5
    assert harness.senders["eth1"].sent == [("eth1", b"f" + str(i).encode()) for i in range(5)]


def test_broken_sender_increments_errors(monkeypatch):
    monkeypatch.setattr("netreplay.core.proxy.bridge.time.sleep", lambda s: None)
    harness = BridgeTestHarness()
    harness.sniffer_factory("eth0").inject(b"frame")
    harness.sniffer_factory("eth0").inject(None)
    harness.sniffer_factory("eth1").inject(b"other")
    harness.sniffer_factory("eth1").inject(None)

    broken = BrokenSender("eth0")
    real = FakeSender("eth1")

    def sender_factory(iface: str):
        return broken if iface == "eth0" else real

    status = BridgeService(
        "eth0", "eth1",
        sniffer_factory=harness.sniffer_factory,
        sender_factory=sender_factory,
    ).run()
    assert status.errors == 1
    assert status.left_forwarded == 1  # left→right uses FakeSender("eth1")
    assert status.right_forwarded == 0  # right→left hits BrokenSender("eth0")
    assert real.sent == [("eth1", b"frame")]


def test_stop_mid_forward(monkeypatch):
    monkeypatch.setattr("netreplay.core.proxy.bridge.time.sleep", lambda s: None)
    harness = BridgeTestHarness()
    sniffer_l = harness.sniffer_factory("eth0")
    for i in range(20):
        sniffer_l.inject(b"f" + str(i).encode())
    sniffer_l.inject(None)
    harness.sniffer_factory("eth1").inject(None)

    flag = threading.Event()

    class TriggerSender(FakeSender):
        def send(self, raw: bytes) -> None:
            super().send(raw)
            if not flag.is_set():
                flag.set()
                service.stop()

    service = BridgeService(
        "eth0", "eth1",
        sniffer_factory=harness.sniffer_factory,
        sender_factory=lambda iface: TriggerSender(iface),
    )
    status = service.run()
    assert status.stopped
    assert status.left_forwarded >= 1


def test_senders_closed_after_run(monkeypatch):
    monkeypatch.setattr("netreplay.core.proxy.bridge.time.sleep", lambda s: None)
    harness = BridgeTestHarness()
    harness.sniffer_factory("eth0").inject(None)
    harness.sniffer_factory("eth1").inject(None)

    BridgeService(
        "eth0", "eth1",
        sniffer_factory=harness.sniffer_factory,
        sender_factory=harness.sender_factory,
    ).run()
    assert harness.senders["eth0"].closed
    assert harness.senders["eth1"].closed


def test_bytes_counted(monkeypatch):
    monkeypatch.setattr("netreplay.core.proxy.bridge.time.sleep", lambda s: None)
    harness = BridgeTestHarness()
    harness.sniffer_factory("eth0").inject(b"abcdef")
    harness.sniffer_factory("eth0").inject(None)
    harness.sniffer_factory("eth1").inject(None)

    status = BridgeService(
        "eth0", "eth1",
        sniffer_factory=harness.sniffer_factory,
        sender_factory=harness.sender_factory,
    ).run()
    assert status.left_bytes == 6
    assert status.left_forwarded == 1


def test_bridge_status_properties():
    from netreplay.core.proxy.bridge import BridgeStatus

    s = BridgeStatus(left_forwarded=3, right_forwarded=2, left_bytes=100, right_bytes=50)
    assert s.total_forwarded == 5
    assert s.total_bytes == 150
    assert s.running is True
    s2 = BridgeStatus(error="boom")
    assert s2.running is False


def test_stop_on_empty(monkeypatch):
    monkeypatch.setattr("netreplay.core.proxy.bridge.time.sleep", lambda s: None)
    harness = BridgeTestHarness()
    harness.sniffer_factory("eth0").inject(None)
    harness.sniffer_factory("eth1").inject(None)

    service = BridgeService(
        "eth0", "eth1",
        sniffer_factory=harness.sniffer_factory,
        sender_factory=harness.sender_factory,
    )
    service.stop()
    status = service.run()
    assert status.stopped

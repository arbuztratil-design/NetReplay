"""P1 #25-26: display-filter language and BPF capture filters."""
from __future__ import annotations

import pytest

from netreplay.core.capture.base import CaptureBackend
from netreplay.core.capture.filters import (
    BpfFilter,
    BpfFilterError,
    attach_bpf_filter,
    parse_bpf,
)
from netreplay.core.display_filter import FilterError, compile_filter
from netreplay.core.storage.database import EventRow, FlowRow, PacketRow


def _packets() -> list[PacketRow]:
    return [
        PacketRow(id=1, ts=100.0, source="10.0.0.1", destination="10.0.0.2", protocol="TCP", src_port=5000, dst_port=443, length=120, flow_id=1),
        PacketRow(id=2, ts=101.0, source="10.0.0.2", destination="8.8.8.8", protocol="UDP", src_port=53, dst_port=53, length=80, flow_id=2),
        PacketRow(id=3, ts=102.0, source="10.0.0.1", destination="10.0.0.3", protocol="TCP", src_port=5001, dst_port=80, length=900, flow_id=3),
    ]


def test_filter_protocol_and_port() -> None:
    flt = compile_filter("protocol == tcp and port == 443")
    ids = [p.id for p in flt.select(_packets())]
    assert ids == [1]


def test_filter_protocol_shorthand() -> None:
    flt = compile_filter("udp")
    ids = [p.id for p in flt.select(_packets())]
    assert ids == [2]


def test_filter_or_and_parens() -> None:
    flt = compile_filter("(dport == 80 or dport == 443) and ip == 10.0.0.1")
    ids = [p.id for p in flt.select(_packets())]
    assert ids == [1, 3]


def test_filter_not_and_length_comparison() -> None:
    flt = compile_filter("not length > 500")
    ids = [p.id for p in flt.select(_packets())]
    assert ids == [1, 2]


def test_filter_contains_on_summary() -> None:
    rows = [
        EventRow(id=1, ts=1.0, event_type="DNS", flow_id=1, summary="DNS QUERY replay.test"),
        EventRow(id=2, ts=2.0, event_type="TLS", flow_id=1, summary="TLS ClientHello sni=example.com"),
    ]
    flt = compile_filter("summary contains REPLAY")
    ids = [r.id for r in flt.select(rows)]
    assert ids == [1]


def test_filter_quoted_value() -> None:
    flt = compile_filter('ip == "10.0.0.1"')
    ids = [p.id for p in flt.select(_packets())]
    assert ids == [1, 3]


def test_filter_empty_matches_all() -> None:
    flt = compile_filter("   ")
    assert len(flt.select(_packets())) == 3


def test_filter_matches_flow_rows() -> None:
    flow = FlowRow(id=7, source="1.1.1.1", destination="2.2.2.2", protocol="TCP", src_port=1234, dst_port=22, start_ts=0.0, end_ts=1.0, packet_count=1, bytes=10, state="ESTABLISHED")
    assert compile_filter("dport == 22 and protocol == tcp").matches(flow)
    assert not compile_filter("port == 443").matches(flow)


def test_filter_rejects_bad_field_and_operator() -> None:
    with pytest.raises(FilterError):
        compile_filter("bogus == 1")
    with pytest.raises(FilterError):
        compile_filter("port = 443")
    with pytest.raises(FilterError):
        compile_filter("tcp and")


def test_bpf_accepts_valid_expression() -> None:
    bpf = parse_bpf("tcp port 443")
    assert bpf.expression == "tcp port 443"
    assert bpf.to_libpcap_args() == ["-f", "tcp port 443"]


def test_bpf_empty_allowed() -> None:
    bpf = parse_bpf("  ")
    assert bpf.is_empty
    assert bpf.to_libpcap_args() == []


def test_bpf_rejects_malformed() -> None:
    with pytest.raises(BpfFilterError):
        parse_bpf("(tcp port 443")
    with pytest.raises(BpfFilterError):
        parse_bpf("tcp; rm -rf /")
    with pytest.raises(BpfFilterError):
        BpfFilter("tcp && udp")


def test_attach_bpf_filter_to_backend() -> None:
    class DummyBackend(CaptureBackend):
        @property
        def running(self) -> bool:
            return False

        def start(self) -> None:  # pragma: no cover
            pass

        def stop(self) -> None:  # pragma: no cover
            pass

        def packets(self):  # pragma: no cover
            return iter(())

    backend = DummyBackend("eth0")
    assert backend.bpf_filter == ""
    bpf = attach_bpf_filter(backend, "udp port 53")
    assert bpf.expression == "udp port 53"
    assert backend.bpf_filter == "udp port 53"

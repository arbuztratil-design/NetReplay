"""P1 #22-24: flow detail, raw/hex and layer-tree viewers."""
from __future__ import annotations

from netreplay.core.flows.models import Flow
from netreplay.core.packets.models import Packet, ParsedPacket
from netreplay.core.viewers.inspectors import (
    LayerNode,
    flow_detail,
    layer_tree,
    raw_hex,
)


def _flow() -> Flow:
    return Flow(
        id=1,
        source="10.0.0.1",
        destination="10.0.0.2",
        protocol="TCP",
        src_port=5000,
        dst_port=443,
        start_ts=100.0,
        end_ts=102.0,
        packet_count=4,
        bytes=2048,
        state="ESTABLISHED",
    )


def _packets() -> list[Packet]:
    return [
        Packet(ts=100.0, source="10.0.0.1", destination="10.0.0.2", protocol="TCP", src_port=5000, dst_port=443, length=512, id=1, flow_id=1),
        Packet(ts=102.0, source="10.0.0.2", destination="10.0.0.1", protocol="TCP", src_port=443, dst_port=5000, length=512, id=2, flow_id=1),
        Packet(ts=101.0, source="10.0.0.1", destination="10.0.0.2", protocol="TCP", src_port=5000, dst_port=443, length=512, id=3, flow_id=1),
        Packet(ts=100.5, source="10.0.0.2", destination="10.0.0.1", protocol="TCP", src_port=443, dst_port=5000, length=512, id=4, flow_id=1),
    ]


def test_flow_detail_summary_and_timing() -> None:
    view = flow_detail(_flow(), _packets())
    assert view.duration == 2.0
    assert view.packets_per_second == 2.0
    assert view.bytes_per_second == 1024.0
    assert view.first_packet_ts == 100.0
    assert view.last_packet_ts == 102.0


def test_flow_detail_orders_packets_by_ts() -> None:
    view = flow_detail(_flow(), _packets())
    assert [p.ts for p in view.packets] == [100.0, 100.5, 101.0, 102.0]
    assert [p.id for p in view.packets] == [1, 4, 3, 2]


def test_flow_detail_carries_metadata() -> None:
    view = flow_detail(_flow(), _packets(), metadata={"note": "lab"})
    assert view.metadata == {"note": "lab"}
    assert view.flow.state == "ESTABLISHED"


def test_raw_hex_rows_and_ascii() -> None:
    view = raw_hex(b"AB\x00\xff", width=4)
    assert view.size == 4
    assert len(view.rows) == 1
    row = view.rows[0]
    assert row.offset == 0
    assert row.hex_bytes == "41 42 00 ff"
    assert row.ascii == "AB.."


def test_raw_hex_wraps_at_width() -> None:
    view = raw_hex(bytes(range(20)), width=16)
    assert len(view.rows) == 2
    assert view.rows[0].offset == 0
    assert view.rows[1].offset == 16
    assert len(view.rows[1].hex_bytes.split()) == 4


def test_raw_hex_rejects_bad_width() -> None:
    import pytest

    with pytest.raises(ValueError):
        raw_hex(b"x", width=0)


def test_layer_tree_ethernet_ip_transport_app() -> None:
    parsed = ParsedPacket(
        ts=1.0,
        source="10.0.0.1",
        destination="10.0.0.2",
        protocol="TCP",
        src_port=5000,
        dst_port=443,
        length=128,
        ttl=64,
        info={"tls": {"version": "0x0303"}},
    )
    root = layer_tree(parsed)
    assert root.name == "Ethernet"
    ip = root.children[0]
    assert ip.name == "IP"
    assert ip.fields["ttl"] == 64
    transport = ip.children[0]
    assert transport.name == "TCP"
    assert transport.fields["dst_port"] == 443
    assert transport.children[0].name == "TLS"

"""Golden PCAP/PCAPNG corpus (#46).

Every scenario in :mod:`tests.golden_corpus` is imported end to end
(PCAP -> parse -> flow -> reassembly -> protocol analysis -> .nrp) and checked
against its fixed golden expectations, so a regression in any stage fails a
concrete assertion.
"""
from __future__ import annotations

import pytest

from netreplay.core.service import NetReplayService
from tests import golden_corpus as gc


def _is_ipv6(addr: str) -> bool:
    if ":" not in addr:
        return False
    # An Ethernet MAC is exactly 17 chars with 5 colons; IPv6 is not.
    return not (len(addr) == 17 and addr.count(":") == 5)


@pytest.mark.parametrize("name", list(gc.SCENARIOS))
def test_golden_capture(name: str, tmp_path) -> None:
    capture, path = gc.build(name, tmp_path / "captures")
    assert path.exists()
    assert path.suffix == capture.suffix

    workspace = tmp_path / "ws"
    workspace.mkdir()
    service = NetReplayService(workspace)
    status = service.import_pcap(path)

    assert status.error is None
    assert status.packets == capture.expected_packets

    sessions = service.list_sessions()
    assert len(sessions) == 1
    session = service.open_session(sessions[0].session_id)
    assert session is not None
    assert session.info().packet_count == capture.expected_packets

    flows = list(session.flows())
    assert len(flows) >= capture.min_flows
    assert capture.protocols <= {f.protocol for f in flows}

    if capture.has_ipv6:
        assert any(_is_ipv6(f.source) or _is_ipv6(f.destination) for f in flows)

    event_types = {e.event_type for e in session.events(limit=100_000)}
    assert capture.event_types <= event_types

    facts = {(f.protocol, f.name): f.value for f in session.protocol_facts()}
    for key, want in capture.facts.items():
        protocol, _, fname = key.partition(".")
        got = facts.get((protocol, fname))
        assert got is not None, f"missing fact {key}"
        assert want in got, f"{key}={got!r} does not contain {want!r}"


def test_corpus_is_complete() -> None:
    """The corpus covers every traffic class named in the roadmap (#46)."""
    required = {
        "tcp_basic",
        "tcp_retransmission",
        "tcp_gap",
        "ipv4_ipv6",
        "tls_client_hello",
        "http2_preface",
        "malformed",
        "tcp_basic_pcapng",
    }
    assert required <= set(gc.SCENARIOS)
    assert any(c.suffix == ".pcapng" for c in gc.SCENARIOS.values())

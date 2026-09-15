"""NetReplay CLI (Typer).

The CLI uses the Core layer directly. Guide: packet parsing, flow tracking,
storage and timeline logic live in ``netreplay.core`` and are - intentionally
- not reimplemented here.
"""
from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

import typer

from netreplay.core.capture.base import CaptureError
from netreplay.core.capture.scapy_backend import list_interfaces
from netreplay.core.service import NetReplayService
from netreplay.core.storage import open_session
from netreplay.core.storage.database import SessionInfo
from netreplay.core.storage.nrp import InvalidNrpError
from netreplay.core.timeline.service import ReplayService, TimelineService
from netreplay.core.replay.inject import ReplayOutService
from netreplay.core.proxy.bridge import BridgeService

app = typer.Typer(help="NetReplay - network traffic time machine.", no_args_is_help=True)
logger = logging.getLogger("netreplay")


def _default_workspace() -> str:
    return os.environ.get("NETREPLAY_WORKSPACE", str(Path.cwd() / "netreplay_data"))


def _fmt_ts(ts: float) -> str:
    local = time.localtime(ts)
    return time.strftime("%H:%M:%S", local) + f".{int((ts % 1) * 1000):03d}"


def _die(message: str, code: int = 1) -> None:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _load(path: Path):
    if not path.exists():
        _die(f"file not found: {path}")
    if path.suffix.lower() != ".nrp":
        _die(f"not a NetReplay capture: {path} (expected .nrp)")
    try:
        return open_session(path)
    except InvalidNrpError as exc:
        _die(str(exc))


@app.command()
def interfaces() -> None:
    """List network interfaces available for capture."""
    found = list_interfaces()
    if not found:
        _die("no interfaces found (is Npcap installed?)")
    typer.echo("NetReplay - available interfaces")
    typer.echo("")
    for iface in found:
        desc = f"  [{iface.description}]" if iface.description else ""
        typer.echo(f"  {iface.name}{desc}")


@app.command()
def capture(
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i",
        help="Interface to capture on (default). Not needed with --source/--mock",
    ),
    source: Optional[Path] = typer.Option(
        None, "--source", help="Offline source: stream a .pcap/.pcapng file through the pipeline"
    ),
    mock: bool = typer.Option(
        False, "--mock", help="Generate deterministic synthetic traffic (no Npcap required)"
    ),
    mock_packets: int = typer.Option(
        40, "--mock-packets", help="Frames to emit with --mock (0 = until stopped)"
    ),
    mock_rate: float = typer.Option(
        0.0, "--mock-rate", help="Emission rate in packets/second with --mock (0 = as fast as possible)"
    ),
    output: Path = typer.Option(
        Path("./capture.nrp"), "--output", "-o", help="Output .nrp file"
    ),
    duration: Optional[float] = typer.Option(
        None, "--duration", "-d", help="Stop automatically after N seconds"
    ),
) -> None:
    """Capture traffic and save it as a .nrp capture.

    Sources: a live interface (default), a stored PCAP/PCAPNG file (--source),
    or deterministic synthetic traffic (--mock).
    """
    from netreplay.core.capture import MockBackend, PcapBackend

    modes = sum(1 for m in (interface is not None, source is not None, mock) if m)
    if source is not None and source.suffix.lower() not in {".pcap", ".pcapng"}:
        _die("--source must end with .pcap or .pcapng")
    if mock and source is not None:
        _die("--mock and --source are mutually exclusive")
    if mock and interface is not None:
        _die("--mock does not use an interface")
    if modes == 0:
        _die("choose a source: --interface, --source, or --mock")
    if output.suffix.lower() != ".nrp":
        _die("output must end with .nrp")

    typer.echo("NetReplay Capture")
    typer.echo("")
    if mock:
        label = "mock (synthetic)"
        typer.echo(f"  Source:   {label}")
        backend = MockBackend(interface="mock", packets=mock_packets, rate=mock_rate)
    elif source is not None:
        label = str(source)
        typer.echo(f"  Source:   {label}")
        backend = PcapBackend(source)
    else:
        label = interface
        typer.echo(f"  Interface: {label}")
        backend = None
    typer.echo(f"  Output:    {output}")
    interface_label = label

    service = NetReplayService(output.parent)
    controller = service.start_capture(interface=interface_label, output=output, backend=backend)
    started = time.time()
    typer.echo("")
    typer.echo("  Capturing... press Ctrl+C to stop.")
    typer.echo("")

    # A synthetic stop -> allow KeyboardInterrupt handling below.
    try:
        while True:
            status = controller.status()
            typer.echo(
                f"\r  Packets: {status.packets}   Flows: {status.flows}   "
                f"Errors: {status.error or 'none'}"
            )
            if not status.running:
                break
            if duration is not None and time.time() - started >= duration:
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    service.stop_capture()
    status = controller.status()
    failed = bool(status.error)
    if status.error:
        typer.secho(f"\n  capture error: {status.error}", fg=typer.colors.RED)
    typer.echo("")
    typer.echo(f"  Saved: {output}")
    typer.echo(f"  Packets: {status.packets}")
    typer.echo(f"  Flows:   {status.flows}")
    typer.echo("")

    if not failed:
        try:
            _print_recent_timeline(output, limit=8)
        except Exception:  # noqa: BLE001
            pass
    else:
        raise typer.Exit(1)


@app.command("import-pcap")
def import_pcap(
    source: Path = typer.Argument(..., help="Source .pcap or .pcapng file"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output .nrp file (default: <source>.nrp)"
    ),
    workspace: Path = typer.Option(
        Path(_default_workspace()), "--workspace", "-w", help="Workspace directory"
    ),
    keylog: Optional[Path] = typer.Option(
        None, "--keylog", "-k", help="NSS key log file to decrypt TLS 1.2/1.3 (CLIENT_RANDOM / traffic-secret lines)"
    ),
) -> None:
    """Import and analyze an existing PCAP/PCAPNG capture."""
    if source.suffix.lower() not in {".pcap", ".pcapng"}:
        _die("source must end with .pcap or .pcapng")
    destination = output or workspace / f"{source.stem}.nrp"
    if destination.suffix.lower() != ".nrp":
        _die("output must end with .nrp")

    typer.echo("NetReplay - PCAP import")
    typer.echo("")
    typer.echo(f"  Source: {source}")
    typer.echo(f"  Output: {destination}")
    if keylog is not None:
        typer.echo(f"  Keylog: {keylog}")
    try:
        status = NetReplayService(workspace).import_pcap(source, destination, keylog=keylog)
    except CaptureError as exc:
        _die(str(exc))

    typer.echo(f"  Packets: {status.packets}")
    typer.echo(f"  Flows:   {status.flows}")
    typer.echo("")
    _print_recent_timeline(destination, limit=12)


def _print_recent_timeline(output: Path, limit: int = 8) -> None:
    session = _load(output)
    events = TimelineService(session).events(limit=limit)
    typer.echo("  Recent timeline events:")
    for ev in reversed(events[-limit:]):
        typer.echo(f"  {_fmt_ts(ev.timestamp)}  {ev.type:<5} {ev.summary}")


@app.command()
def inspect(
    path: Path = typer.Argument(..., help=".nrp capture file"),
    search: Optional[str] = typer.Option(
        None, "--search", "-s", help="Find flows/events/packets matching an IP or a domain"
    ),
    similar: bool = typer.Option(
        False, "--similar", help="Rank similar sessions in the workspace by fingerprint"
    ),
    workspace: Path = typer.Option(
        Path(_default_workspace()), "--workspace", "-w", help="Workspace for --similar"
    ),
    top: int = typer.Option(5, help="Max similar sessions to show (with --similar)"),
) -> None:
    """Show metadata about a stored capture (optionally search or compare)."""
    from netreplay.core.search import search_session, similar_sessions

    session = _load(path)
    info: SessionInfo = session.info()
    typer.echo("NetReplay - capture info")
    typer.echo("")
    typer.echo(f"  Session:   {info.name}")
    typer.echo(f"  File:      {info.path}")
    typer.echo(f"  Interface: {info.interface or '-'}")
    typer.echo(f"  Captured:  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info.created_at))}")
    typer.echo(f"  Status:    {info.status}")
    typer.echo(f"  Packets:   {info.packet_count}")
    typer.echo(f"  Flows:     {info.flow_count}")
    typer.echo(f"  Events:    {info.event_count}")
    typer.echo(
        f"  Range:     {_fmt_ts(info.first_ts) if info.first_ts else '-'} -> "
        f"{_fmt_ts(info.last_ts) if info.last_ts else '-'}"
    )
    if search:
        result = search_session(session, search)
        typer.echo("")
        typer.echo(f"  Search: {result.query} ({result.total} match(es))")
        if result.events:
            typer.echo(f"    events ({len(result.events)}):")
            for ev in result.events:
                typer.echo(f"      {_fmt_ts(ev.ts)}  {ev.event_type:<5} {ev.summary}")
        if result.flows:
            typer.echo(f"    flows ({len(result.flows)}):")
            for row in result.flows:
                src = f"{row.source}:{row.src_port}" if row.src_port else row.source
                dst = f"{row.destination}:{row.dst_port}" if row.dst_port else row.destination
                typer.echo(
                    f"      #{row.id}  {row.protocol:<6} {src:<30} -> {dst:<30}"
                    f"  {row.packet_count} pkts"
                )
        if result.packets:
            typer.echo(f"    packets ({len(result.packets)}):")
            for pkt in result.packets[:20]:
                src = f"{pkt.source}:{pkt.src_port}" if pkt.src_port else pkt.source
                dst = f"{pkt.destination}:{pkt.dst_port}" if pkt.dst_port else pkt.destination
                typer.echo(f"      #{pkt.id}  {_fmt_ts(pkt.ts)}  {pkt.protocol:<6} {src:<30} -> {dst}")
            if len(result.packets) > 20:
                typer.echo(f"      ... and {len(result.packets) - 20} more")
        elif not result.events and not result.flows:
            typer.echo("    (no matches)")
    if similar:
        typer.echo("")
        found = similar_sessions(path, workspace=workspace, top=top)
        typer.echo(f"  Similar sessions (workspace={workspace}):")
        if not found:
            typer.echo("    (none)")
        for sim in found:
            shared = []
            if sim.shared_domains:
                shared.append(f"domains: {','.join(sim.shared_domains[:8])}")
            if sim.shared_ips:
                shared.append(f"ips: {','.join(sim.shared_ips[:8])}")
            if sim.shared_ports:
                shared.append(f"ports: {','.join(sim.shared_ports[:8])}")
            detail = "  " + "; ".join(shared) if shared else ""
            typer.echo(f"    {sim.score * 100:5.1f}%  {sim.name}  {sim.session_id}{detail}")


@app.command()
def flows(
    path: Path = typer.Argument(..., help=".nrp capture file"),
    sort: str = typer.Option("start_ts", help="Sort by: start_ts | bytes | packets"),
    limit: int = typer.Option(50, help="Show at most N flows"),
) -> None:
    """List flows in a capture."""
    session = _load(path)
    typer.echo("NetReplay - flows")
    typer.echo("")
    header = f"{'id':>4}  {'protocol':<6} {'source':<30} {'destination':<30} {'pkts':>5} {'bytes':>9}  state"
    typer.echo(header)
    typer.echo("-" * len(header))
    for row in session.flows(sort=sort)[:limit]:
        src = f"{row.source}:{row.src_port}" if row.src_port else row.source
        dst = f"{row.destination}:{row.dst_port}" if row.dst_port else row.destination
        typer.echo(
            f"{row.id:>4}  {row.protocol:<6} {src:<30} {dst:<30} "
            f"{row.packet_count:>5} {row.bytes:>9}  {row.state}"
        )


@app.command()
def timeline(
    path: Path = typer.Argument(..., help=".nrp capture file"),
    start: Optional[float] = None,
    end: Optional[float] = None,
    types: Optional[str] = typer.Option(
        None, help="Comma separated event types (TCP,DNS,TLS,...)"
    ),
    flow_id: Optional[int] = None,
    limit: int = typer.Option(200, help="Max events to show"),
) -> None:
    """Show timeline events within an optional time range."""
    session = _load(path)
    type_list = [t.strip().upper() for t in (types or "").split(",") if t.strip()] if types else None
    events = TimelineService(session).events(
        start=start, end=end, types=type_list, flow_id=flow_id, limit=limit
    )
    typer.echo("NetReplay - timeline")
    typer.echo("")
    for ev in events:
        typer.echo(f"  {_fmt_ts(ev.timestamp)}  {ev.type:<5} {ev.summary}")


@app.command()
def replay(
    path: Path = typer.Argument(..., help=".nrp capture file"),
    speed: float = typer.Option(1.0, help="Playback speed multiplier"),
    limit: int = typer.Option(500, help="Max events to replay"),
) -> None:
    """Historical replay: play stored events back with realistic gaps."""
    session = _load(path)
    service = ReplayService(session, speed=speed)
    typer.echo("NetReplay - historical replay")
    typer.echo("")
    for index, (gap, event) in enumerate(service.events()):
        if index >= limit:
            break
        if gap > 0:
            time.sleep(min(gap, 5.0))
        typer.echo(f"  {_fmt_ts(event.timestamp)}  {event.type:<5} {event.summary}")


@app.command("replay-out")
def replay_out(
    path: Path = typer.Argument(..., help=".nrp capture file"),
    interface: str = typer.Option(..., "--interface", "-i", help="Interface to inject into"),
    speed: float = typer.Option(1.0, "--speed", help="Playback speed multiplier"),
    limit: Optional[int] = typer.Option(None, "--limit", help="Inject at most N packets"),
    offset: int = typer.Option(0, "--offset", help="Skip the first N packets"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Count/validate without sending"),
) -> None:
    """Replay captured traffic back into the network."""
    service = ReplayOutService(
        _load(path), interface=interface, speed=speed, dry_run=dry_run,
        offset=offset, limit=limit,
    )
    mode = "dry run, no packets sent" if dry_run else f"injecting into {interface}"
    typer.echo("NetReplay - replay-out")
    typer.echo("")
    typer.echo(f"  Source:   {path}")
    typer.echo(f"  Mode:     {mode}")
    typer.echo(f"  Speed:    x{speed:g}")
    typer.echo("")
    typer.echo("  Ctrl+C to stop.")
    status = service.run()
    typer.echo("")
    if status.error:
        typer.secho(f"  error: {status.error}", fg=typer.colors.RED)
    typer.echo(f"  Packets:  {status.packets}")
    typer.echo(f"  Bytes:    {status.bytes}")
    typer.echo(f"  Duration: {status.duration:.1f}s")
    if status.stopped:
        typer.echo("  Stopped by user.")
    if status.error:
        raise typer.Exit(1)


@app.command()
def bridge(
    left_interface: str = typer.Option(..., "--left", "-L", help="Left interface"),
    right_interface: str = typer.Option(..., "--right", "-R", help="Right interface"),
) -> None:
    """Live L2 bridge: sniff on both interfaces, forward to the other."""
    typer.echo("NetReplay - Live L2 Bridge")
    typer.echo("")
    typer.echo(f"  Left:   {left_interface}")
    typer.echo(f"  Right:  {right_interface}")
    typer.echo("")
    typer.echo("  Ctrl+C to stop.")
    typer.echo("")
    service = BridgeService(left_interface, right_interface)
    status = service.run()
    typer.echo("")
    if status.error:
        typer.secho(f"  error: {status.error}", fg=typer.colors.RED)
    typer.echo(f"  Left -> Right:   {status.left_forwarded} pkts  ({status.left_bytes} bytes)")
    typer.echo(f"  Right -> Left:   {status.right_forwarded} pkts  ({status.right_bytes} bytes)")
    typer.echo(f"  Errors:          {status.errors}")
    typer.echo(f"  Duration:        {status.duration:.1f}s")
    if status.stopped:
        typer.echo("  Stopped by user.")
    if status.error:
        raise typer.Exit(1)


@app.command()
def sessions(
    workspace: Path = typer.Option(
        Path(_default_workspace()), "--workspace", "-w", help="Workspace directory"
    ),
) -> None:
    """List captures stored in a workspace."""
    service = NetReplayService(workspace)
    found = service.list_sessions()
    typer.echo("NetReplay - sessions")
    typer.echo("")
    if not found:
        typer.echo("  (no captures yet)")
    for info in found:
        typer.echo(
            f"  {info.session_id}  {info.name:<24} packets={info.packet_count:<6}"
            f" status={info.status}"
        )


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port", "-p"),
    workspace: Path = typer.Option(Path(_default_workspace()), "--workspace", "-w"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code change"),
) -> None:
    """Run the NetReplay REST + WebSocket API server."""
    import uvicorn

    from netreplay.api import create_app

    typer.echo(f"NetReplay API on http://{host}:{port}")
    typer.echo(f"Workspace: {workspace}")
    app_obj = create_app(workspace)
    uvicorn.run(app_obj, host=host, port=port, reload=reload)


@app.command()
def gui(
    api_url: str = typer.Option("http://127.0.0.1:8000", "--api-url"),
    workspace: Path = typer.Option(Path(_default_workspace()), "--workspace", "-w"),
) -> None:
    """Launch the Flet GUI (connects to the NetReplay API)."""
    try:
        import flet as ft  # noqa: F401
    except ImportError:
        _die("flet is not installed")
    os.environ["NETREPLAY_API_URL"] = api_url
    os.environ["NETREPLAY_WORKSPACE"] = str(workspace)
    from gui.main import main as gui_main

    ft.app(target=gui_main)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    app()

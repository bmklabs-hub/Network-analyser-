"""wd-probe command line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from wd_probe.capabilities import probe_adapter, survey_capable_adapters
from wd_probe.capture.base import CaptureError
from wd_probe.capture.wireless import WirelessCaptureEngine
from wd_probe.contracts import (
    CaptureKind,
    CapturePoint,
    CaptureSession,
    SampleType,
    WirelessConfig,
    WirelessMode,
)
from wd_probe.reduce.wifi_tshark import WifiTsharkReducer
from wd_probe.spool import Spool
from wd_probe.upload import Uploader, UploadError

app = typer.Typer(add_completion=False, help="WiFi-Diagnose probe — capture and reduce.")
console = Console()

DEFAULT_SPOOL = "~/.wd-probe/spool.db"
DEFAULT_CAPDIR = "~/.wd-probe/captures"


# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def capabilities(
    iface: Optional[str] = typer.Option(None, "--iface", "-i", help="Adapter to probe."),
) -> None:
    """Report honestly what this machine's wireless adapters can do."""
    if iface:
        infos, advice = [probe_adapter(iface)], []
    else:
        infos, advice = survey_capable_adapters()

    if not infos:
        console.print("[red]No wireless interfaces found.[/] Is `iw` installed?")
        raise typer.Exit(1)

    for info in infos:
        if info.monitor_reliable is True:
            colour = "green"
        elif info.monitor_reliable is False or not info.monitor_advertised:
            colour = "red"
        else:
            colour = "yellow"

        kind = {"usb": "USB dongle", "pci": "built-in card"}.get(info.bus or "", "unknown bus")
        body = [
            f"[bold]driver:[/] {info.driver or 'unknown'}   [dim]({kind})[/]",
            f"[bold]bands:[/] {'+'.join(info.bands) + ' GHz' if info.bands else 'unknown'}",
            f"[bold]monitor mode:[/] [{colour}]{info.monitor_verdict}[/]",
            f"[bold]channels seen:[/] {len(info.freqs_mhz)}",
        ]
        for n in info.notes:
            body.append(f"\n[yellow]![/] {n}")
        console.print(Panel("\n".join(body), title=f"[bold]{info.name}[/]", expand=False))

    for a in advice:
        console.print(f"\n[red bold]→[/] {a}")


# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def capture(
    iface: str = typer.Option(..., "--iface", "-i"),
    channel: Optional[int] = typer.Option(None, "--channel", "-c"),
    width: int = typer.Option(20, "--width", "-w", help="20 / 40 / 80 / 160 MHz"),
    duration: int = typer.Option(60, "--duration", "-d", help="Seconds."),
    hopping: bool = typer.Option(False, "--hopping", help="Survey mode (rate metrics disabled)."),
    site: str = typer.Option("lab", "--site"),
    out: str = typer.Option(DEFAULT_CAPDIR, "--out"),
    spool_path: str = typer.Option(DEFAULT_SPOOL, "--spool"),
    reduce_now: bool = typer.Option(True, "--reduce/--no-reduce"),
) -> None:
    """Capture 802.11 frames, then reduce them into the spool."""
    engine = WirelessCaptureEngine(
        iface=iface,
        channel=channel,
        width_mhz=width,
        mode=WirelessMode.HOPPING if hopping else WirelessMode.LOCKED,
        site_id=site,
    )

    problems = engine.preflight()
    if problems:
        console.print("[red bold]Preflight failed:[/]")
        for p in problems:
            console.print(f"  [red]•[/] {p}")
        raise typer.Exit(1)

    if hopping:
        console.print(
            "[yellow]Hopping mode: rate metrics (retry %, airtime %) will be "
            "recorded as unavailable — the denominator is a time sample.[/]"
        )

    console.print(f"Capturing {duration}s on [bold]{iface}[/] ch{channel}…")
    try:
        session = engine.capture(Path(out).expanduser(), duration)
    except CaptureError as e:
        # An expected, explained refusal — print the instruction, not a traceback.
        console.print(f"[red bold]Capture refused:[/] {e}")
        raise typer.Exit(1) from e

    q = session.quality
    colour = "green" if q.loss_pct == 0 else ("yellow" if q.loss_pct < 1 else "red")
    console.print(
        f"Captured [bold]{q.packets_captured}[/] frames, "
        f"dropped [{colour}]{q.total_drops}[/] ({q.loss_pct}%)"
    )
    if not q.is_analyzable():
        console.print("[red bold]Loss above 1% — treat this capture as unreliable.[/]")

    sp = Spool(spool_path)
    sp.save_session(session)

    if reduce_now and session.pcap_path:
        n = _reduce_into_spool(Path(session.pcap_path), session, sp)
        sp.save_session(session)      # ADR-29: persist the verdict the reducer reached
        console.print(f"Reduced into [bold]{n}[/] samples. Session [bold]{session.id}[/]")
        console.print(f"  → wd-probe report {session.id}")
    sp.close()


# ─────────────────────────────────────────────────────────────────────────────

@app.command("reduce")
def reduce_cmd(
    pcap: Path = typer.Argument(..., help="Existing 802.11 pcap file."),
    channel: Optional[int] = typer.Option(None, "--channel", "-c"),
    hopping: bool = typer.Option(False, "--hopping"),
    site: str = typer.Option("lab", "--site"),
    spool_path: str = typer.Option(DEFAULT_SPOOL, "--spool"),
) -> None:
    """Reduce a pcap captured elsewhere (or a test fixture) into the spool."""
    cp = CapturePoint(
        kind=CaptureKind.WIRELESS_MONITOR,
        site_id=site,
        description=f"offline reduce of {pcap.name}",
        wireless=WirelessConfig(
            adapter="offline",
            mode=WirelessMode.HOPPING if hopping else WirelessMode.LOCKED,
            channel=channel,
        ),
    )
    session = CaptureSession(capture_point=cp, pcap_path=str(pcap))
    sp = Spool(spool_path)
    sp.save_session(session)
    n = _reduce_into_spool(pcap, session, sp)
    sp.save_session(session)          # persist quality filled in by the reducer
    console.print(f"Reduced [bold]{pcap.name}[/] → {n} samples. Session [bold]{session.id}[/]")
    console.print(f"  → wd-probe report {session.id}")
    sp.close()


def _reduce_into_spool(pcap: Path, session: CaptureSession, sp: Spool) -> int:
    reducer = WifiTsharkReducer()
    if not reducer.supports(session):
        console.print("[red]No reducer supports this capture kind.[/]")
        raise typer.Exit(1)
    return sp.add_many(reducer.reduce(pcap, session))


# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def sessions(spool_path: str = typer.Option(DEFAULT_SPOOL, "--spool")) -> None:
    """List capture sessions in the spool."""
    sp = Spool(spool_path)
    rows = sp.list_sessions()
    if not rows:
        console.print("No sessions yet.")
        raise typer.Exit()

    t = Table(title="Capture sessions")
    for c in ("session", "started (UTC)", "kind", "mode", "ch", "frames", "loss %"):
        t.add_column(c)
    for r in rows:
        cp = json.loads(r["capture_point"])
        q = json.loads(r["quality"])
        w = cp.get("wireless") or {}
        loss = q.get("loss_pct", 0.0)
        t.add_row(
            r["id"], r["started_at"][:19], cp["kind"],
            w.get("mode", "-"), str(w.get("channel") or "-"),
            str(q.get("packets_captured", 0)),
            f"[{'green' if loss == 0 else 'red'}]{loss}[/]",
        )
    console.print(t)
    sp.close()


@app.command()
def report(
    session_id: str = typer.Argument(...),
    spool_path: str = typer.Option(DEFAULT_SPOOL, "--spool"),
    top: int = typer.Option(10, "--top", help="Stations to show."),
) -> None:
    """Show the reduced results for one session."""
    sp = Spool(spool_path)
    srow = sp.get_session(session_id)
    if not srow:
        console.print(f"[red]No session {session_id}[/]")
        raise typer.Exit(1)

    cp = json.loads(srow["capture_point"])
    w = cp.get("wireless") or {}

    # The report must show what the reducer CONCLUDED, not what the operator
    # declared. Those differ exactly when it matters most.
    declared = cp.get("rate_metrics_valid", True)
    valid, reason, freqs = declared, None, None
    for r in sp.samples(session_id, SampleType.SESSION_QUALITY):
        q = json.loads(r["payload"])
        valid = q.get("effective_rate_metrics_valid", declared)
        reason = q.get("suppression_reason")
        freqs = q.get("distinct_freqs")
        break

    lines = [
        f"[bold]{cp['description']}[/]",
        f"kind={cp['kind']}  mode={w.get('mode')}  declared channel={w.get('channel')}",
        f"rate metrics valid: [{'green' if valid else 'red'}]{valid}[/]",
    ]
    if declared and not valid:
        lines.append("[red]declared valid by the operator — OVERRIDDEN by the data[/]")
    if freqs is not None:
        lines.append(f"frequencies observed: {freqs}")
    console.print(Panel("\n".join(lines), title=session_id, expand=False))

    if not valid:
        console.print(f"[yellow]Rate metrics suppressed — {reason}.[/]")
        console.print(
            "[yellow]retry % and airtime % need a complete observation of one "
            "channel; a hopping radio gives them a random denominator.[/]\n"
        )

    # per-second table
    t = Table(title="Per-second frame stats")
    for c in ("time (UTC)", "ch", "frames", "retry", "retry %", "airtime %",
              "mgmt", "ctrl", "data", "beacons", "deauth", "stations", "RSSI mean"):
        t.add_column(c, justify="right")

    rows = list(sp.samples(session_id, SampleType.WIFI_FRAME_STAT))
    for r in rows[:40]:
        p = json.loads(r["payload"])
        rp = p.get("retry_pct")
        at = p.get("airtime_busy_pct")
        rp_s = "—" if rp is None else f"{rp:.1f}"
        rp_c = "red" if (rp or 0) > 25 else ("yellow" if (rp or 0) > 10 else "green")
        t.add_row(
            r["ts"][11:19], str(p.get("channel") or "-"),
            str(p["frames_total"]), str(p["frames_retry"]),
            f"[{rp_c}]{rp_s}[/]" if rp is not None else "—",
            "—" if at is None else f"{at:.1f}",
            str(p["frames_mgmt"]), str(p["frames_ctrl"]), str(p["frames_data"]),
            str(p["beacon_count"]), str(p["deauth_count"]),
            str(p["distinct_stations"]),
            "—" if p.get("rssi_mean_dbm") is None else f"{p['rssi_mean_dbm']:.0f}",
        )
    console.print(t)
    if len(rows) > 40:
        console.print(f"[dim]… {len(rows) - 40} more seconds not shown[/]")

    # stations
    st = Table(title=f"Top {top} transmitters")
    for c in ("station (hashed)", "frames", "retry", "retry %", "bytes", "airtime µs", "RSSI min/max"):
        st.add_column(c, justify="right")
    srows = list(sp.samples(session_id, SampleType.WIFI_STATION_STAT))
    for r in srows[:top]:
        p = json.loads(r["payload"])
        rp = p.get("retry_pct")
        st.add_row(
            p["station_mac_hash"], str(p["frames"]), str(p["frames_retry"]),
            "—" if rp is None else f"{rp:.1f}",
            str(p["bytes_total"]), str(p["airtime_us"]),
            f"{p.get('rssi_min_dbm', '—')}/{p.get('rssi_max_dbm', '—')}",
        )
    console.print(st)
    sp.close()


@app.command()
def upload(
    server: str = typer.Option(
        "http://127.0.0.1:8000", "--server", envvar="WD_SERVER_URL",
        help="wd-server base URL.",
    ),
    token: str = typer.Option("", "--token", envvar="WD_PROBE_TOKEN",
                              help="Probe bearer token."),
    batch: int = typer.Option(500, "--batch"),
    spool_path: str = typer.Option(DEFAULT_SPOOL, "--spool"),
) -> None:
    """Send everything not yet uploaded to wd-server. Safe to re-run."""
    sp = Spool(spool_path)
    before = sp.stats()["pending_upload"]
    if before == 0:
        console.print("Nothing to upload — spool is fully sent.")
        sp.close()
        raise typer.Exit()
    try:
        res = Uploader(sp, server, token, batch_size=batch).run()
    except UploadError as e:
        console.print(f"[red bold]Upload failed:[/] {e}")
        console.print(f"[dim]{sp.stats()['pending_upload']} samples still waiting in the spool.[/]")
        sp.close()
        raise typer.Exit(1) from e
    console.print(
        f"Uploaded [bold]{res.samples_sent}[/] samples in {res.batches} batch(es) "
        f"→ {server}  (duplicates ignored by server: {res.duplicates}, retries: {res.retries})"
    )
    for err in res.errors:
        console.print(f"[yellow]![/] {err}")
    console.print(f"pending now: {sp.stats()['pending_upload']}")
    sp.close()


@app.command()
def status(spool_path: str = typer.Option(DEFAULT_SPOOL, "--spool")) -> None:
    """Spool summary."""
    sp = Spool(spool_path)
    s = sp.stats()
    console.print(Panel(
        f"sessions:        {s['sessions']}\n"
        f"samples:         {s['samples']}\n"
        f"pending upload:  {s['pending_upload']}",
        title="spool", expand=False,
    ))
    sp.close()


if __name__ == "__main__":
    app()

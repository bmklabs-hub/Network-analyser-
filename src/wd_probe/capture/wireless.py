"""Wireless monitor-mode capture via dumpcap.

Why dumpcap and not tshark: dumpcap is the small, privileged capture engine
that Wireshark itself runs underneath. It writes packets and does nothing
else. tshark dissects while capturing, and dissection under load is exactly
how you drop packets.

Why not scapy's sniff(): it is a Python loop per packet. Fine for a hundred
frames, hopeless as a capture engine.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from wd_probe.capabilities import probe_adapter
from wd_probe.capture.base import CaptureError
from wd_probe.contracts import (
    CaptureKind,
    CapturePoint,
    CaptureQuality,
    CaptureSession,
    WirelessConfig,
    WirelessMode,
)

# dumpcap summary line, e.g.
#   Packets received/dropped on interface 'wlan1': 4821/17 (pcap:12/dumpcap:5/...)
_DROP_RE = re.compile(
    r"Packets received/dropped on interface\s+'[^']+':\s*(\d+)/(\d+)"
)
_PCAP_DROP_RE = re.compile(r"pcap:(\d+)")
_IFDROP_RE = re.compile(r"ps_ifdrop:(\d+)")


class WirelessCaptureEngine:
    """Capture 802.11 frames from an adapter already in monitor mode."""

    name = "wireless_dumpcap"

    def __init__(
        self,
        iface: str,
        channel: int | None = None,
        width_mhz: int = 20,
        mode: WirelessMode = WirelessMode.LOCKED,
        site_id: str = "lab",
        description: str = "",
        buffer_mb: int = 256,
        ring_filesize_kb: int = 262_144,   # 256 MB — stays in page cache
        ring_files: int = 20,
    ) -> None:
        self.iface = iface
        self.channel = channel
        self.width_mhz = width_mhz
        self.mode = mode
        self.site_id = site_id
        self.description = description or f"monitor {iface} ch{channel}"
        self.buffer_mb = buffer_mb
        self.ring_filesize_kb = ring_filesize_kb
        self.ring_files = ring_files
        self.dumpcap = shutil.which("dumpcap") or "dumpcap"

    # ── preflight ───────────────────────────────────────────────────────────

    def preflight(self) -> list[str]:
        problems: list[str] = []

        if not shutil.which("dumpcap"):
            problems.append("dumpcap not found — sudo apt install wireshark-common")

        info = probe_adapter(self.iface)
        if not info.present:
            problems.append(f"interface {self.iface} not found")
            return problems
        if not info.monitor_capable:
            problems.append(f"{self.iface} does not advertise monitor mode")

        itype = subprocess.run(
            ["iw", "dev", self.iface, "info"], capture_output=True, text=True
        ).stdout
        if "type monitor" not in itype:
            problems.append(
                f"{self.iface} is NOT currently in monitor mode. Run:\n"
                f"    sudo ip link set {self.iface} down\n"
                f"    sudo iw dev {self.iface} set monitor control\n"
                f"    sudo ip link set {self.iface} up"
            )

        if self.mode is WirelessMode.LOCKED and self.channel is None:
            problems.append("locked mode requires --channel")

        return problems

    # ── capture point description ───────────────────────────────────────────

    def build_capture_point(self) -> CapturePoint:
        info = probe_adapter(self.iface)
        band = None
        if self.channel:
            band = "2.4" if self.channel <= 14 else "5"
        return CapturePoint(
            kind=CaptureKind.WIRELESS_MONITOR,
            site_id=self.site_id,
            description=self.description,
            wireless=WirelessConfig(
                adapter=self.iface,
                driver=info.driver,
                mode=self.mode,
                channel=self.channel,
                width_mhz=self.width_mhz,
                band=band,
            ),
        )

    # ── capture ─────────────────────────────────────────────────────────────

    def current_channel(self) -> int | None:
        """Which channel is the adapter actually on right now?

        Returns None if we cannot tell — `iw` missing, interface absent, or no
        channel line. Callers must treat None as "unknown", never as "wrong":
        a probe that cannot measure something must not assert a value for it.
        """
        try:
            out = subprocess.run(
                ["iw", "dev", self.iface, "info"],
                capture_output=True, text=True, timeout=10,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        m = re.search(r"^\s*channel\s+(\d+)", out, re.M)
        return int(m.group(1)) if m else None

    def set_channel(self) -> None:
        """Put the radio on the requested channel.

        Changing channel needs CAP_NET_ADMIN, which an unprivileged user does
        not have — but *capturing* only needs the `wireshark` group. So the
        normal, recommended way to run this tool is:

            sudo iw dev wlan1 set channel 36 HT20     # once, as root
            wd-probe capture -i wlan1 -c 36           # as your normal user

        That keeps the privileged step small and explicit, and it means you are
        never running the whole Python application as root. So when we cannot
        set the channel ourselves, we check whether it is *already* correct and
        carry on if it is — refusing to work would be pedantry, not safety.
        """
        if self.channel is None:
            return

        if self.current_channel() == self.channel:
            return  # already where we want to be — nothing to do

        width_arg = {20: "HT20", 40: "HT40+", 80: "80MHz", 160: "160MHz"}.get(
            self.width_mhz, "HT20"
        )
        attempts = [
            ["iw", "dev", self.iface, "set", "channel", str(self.channel), width_arg],
            # some drivers reject HT40/80 on some channels — fall back to 20 MHz
            ["iw", "dev", self.iface, "set", "channel", str(self.channel)],
        ]
        last_err = ""
        for cmd in attempts:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            except FileNotFoundError:
                raise CaptureError("`iw` not found — sudo apt install iw") from None
            except subprocess.SubprocessError as exc:
                last_err = str(exc)
                continue
            if r.returncode == 0:
                return
            last_err = (r.stderr or "").strip()

        if self.current_channel() == self.channel:
            return  # something else set it in the meantime; fine

        if "not permitted" in last_err.lower() or "permission" in last_err.lower():
            raise CaptureError(
                f"Cannot change channel as an unprivileged user, and {self.iface} is "
                f"on channel {self.current_channel()} rather than {self.channel}.\n"
                f"Set it once as root, then re-run this command normally:\n"
                f"    sudo iw dev {self.iface} set channel {self.channel} {width_arg}"
            )
        raise CaptureError(f"could not set channel {self.channel}: {last_err}")

    def capture(self, out_dir: Path, duration_s: int) -> CaptureSession:
        out_dir.mkdir(parents=True, exist_ok=True)
        cp = self.build_capture_point()
        session = CaptureSession(capture_point=cp)

        stem = out_dir / f"{session.id}.pcap"
        self.set_channel()

        cmd = [
            self.dumpcap,
            "-i", self.iface,
            "-B", str(self.buffer_mb),
            "-b", f"filesize:{self.ring_filesize_kb}",
            "-b", f"files:{self.ring_files}",
            "-a", f"duration:{duration_s}",
            "-w", str(stem),
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        stderr = proc.stderr or ""

        # dumpcap returns non-zero on a real failure; a clean duration stop is 0
        if proc.returncode != 0 and "Packets captured" not in stderr:
            raise CaptureError(f"dumpcap failed: {stderr.strip()[:400]}")

        session.ended_at = datetime.now(timezone.utc)
        session.quality = self._parse_quality(stderr)

        files = sorted(out_dir.glob(f"{session.id}*.pcap"))
        if not files:
            raise CaptureError(f"dumpcap produced no files in {out_dir}")
        session.pcap_path = str(files[0])
        session.notes = f"{len(files)} ring file(s)"
        return session

    @staticmethod
    def _parse_quality(stderr: str) -> CaptureQuality:
        q = CaptureQuality()
        m = _DROP_RE.search(stderr)
        if m:
            q.packets_captured = int(m.group(1))
            total_dropped = int(m.group(2))
            pm = _PCAP_DROP_RE.search(stderr)
            im = _IFDROP_RE.search(stderr)
            q.drops_kernel = int(pm.group(1)) if pm else total_dropped
            q.drops_interface = int(im.group(1)) if im else 0
            # avoid double counting when both sub-counters are present
            if pm and im:
                q.drops_kernel = int(pm.group(1))
                q.drops_interface = int(im.group(1))
        else:
            cm = re.search(r"Packets captured:\s*(\d+)", stderr)
            if cm:
                q.packets_captured = int(cm.group(1))
        return q

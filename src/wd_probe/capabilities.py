"""Capability prober — find out honestly what this machine can do.

Design v0.2 §4: capabilities are negotiated per run, never assumed. This
module answers three questions about a wireless adapter:

  1. Is it there, and what driver is behind it?
  2. Can it do monitor mode?
  3. Which bands can it actually see?

Question 3 is the one people skip. An adapter that does flawless monitor mode
on 2.4 GHz is blind to essentially all modern enterprise WiFi, and a tool that
does not say so will produce empty results that look like good news.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class AdapterInfo:
    name: str
    driver: str | None = None
    monitor_capable: bool = False
    bands: list[str] = field(default_factory=list)
    freqs_mhz: list[int] = field(default_factory=list)
    present: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not self.present:
            return f"{self.name}: NOT FOUND"
        b = "+".join(self.bands) if self.bands else "unknown"
        m = "monitor OK" if self.monitor_capable else "NO MONITOR MODE"
        return f"{self.name}: driver={self.driver or '?'} bands={b} GHz — {m}"


def _run(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


# Known driver characteristics. Out-of-tree drivers need the kernel pinned or
# an unattended upgrade will make the adapter disappear at the worst moment.
DRIVER_NOTES = {
    "ath9k_htc": "Atheros AR9271 — in-kernel, very reliable, but 2.4 GHz / 802.11n only.",
    "mt76x2u":   "MediaTek MT7612U — in-kernel, 2.4+5 GHz. The reference adapter.",
    "mt76x0u":   "MediaTek — in-kernel.",
    "rtl8xxxu":  "Realtek in-kernel driver; monitor support varies by chip revision.",
    "rtw88_usb": "Realtek in-kernel; monitor support varies.",
    "88XXau":    "OUT-OF-TREE DKMS driver — pin the kernel (apt-mark hold).",
    "8812au":    "OUT-OF-TREE DKMS driver — pin the kernel (apt-mark hold).",
    "8821au":    "OUT-OF-TREE DKMS driver — pin the kernel (apt-mark hold).",
    "rtl88x2bu": "OUT-OF-TREE DKMS driver — pin the kernel (apt-mark hold).",
    "88x2bu":    "OUT-OF-TREE DKMS driver — pin the kernel (apt-mark hold).",
}


def _band_of(freq: int) -> str | None:
    if 2400 <= freq <= 2500:
        return "2.4"
    if 5100 <= freq <= 5900:
        return "5"
    if 5925 <= freq <= 7125:
        return "6"
    return None


def probe_adapter(iface: str) -> AdapterInfo:
    info = AdapterInfo(name=iface)

    if not shutil.which("iw"):
        info.notes.append("`iw` not installed — run: sudo apt install iw")
        return info

    link = _run(["iw", "dev", iface, "info"])
    if not link:
        info.notes.append(f"interface {iface} not found (try: iw dev)")
        return info
    info.present = True

    # driver name comes from the sysfs symlink, most reliably via ethtool
    if shutil.which("ethtool"):
        out = _run(["ethtool", "-i", iface])
        m = re.search(r"^driver:\s*(\S+)", out, re.M)
        if m:
            info.driver = m.group(1)

    phy_m = re.search(r"wiphy\s+(\d+)", link)
    phy_out = _run(["iw", f"phy#{phy_m.group(1)}", "info"]) if phy_m else _run(["iw", "list"])

    if "* monitor" in phy_out:
        info.monitor_capable = True

    for fm in re.finditer(r"^\s*\*\s+(\d{4})(?:\.\d+)?\s+MHz", phy_out, re.M):
        f = int(fm.group(1))
        info.freqs_mhz.append(f)
        b = _band_of(f)
        if b and b not in info.bands:
            info.bands.append(b)
    info.bands.sort()

    if info.driver and info.driver in DRIVER_NOTES:
        info.notes.append(DRIVER_NOTES[info.driver])
    elif info.driver:
        info.notes.append(f"Driver '{info.driver}' not in the known list — verify monitor mode manually.")

    if info.bands == ["2.4"]:
        info.notes.append(
            "2.4 GHz ONLY. Fine for learning the pipeline, but modern enterprise "
            "WiFi is on 5/6 GHz. Budget for an MT7612U adapter before real surveys."
        )
    if not info.monitor_capable:
        info.notes.append("Monitor mode NOT advertised by this phy — capture will fail.")

    return info


def list_wireless_interfaces() -> list[str]:
    out = _run(["iw", "dev"])
    return re.findall(r"^\s*Interface\s+(\S+)", out, re.M)

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
    bus: str | None = None                  # "pci" (built-in) | "usb" (dongle)
    monitor_advertised: bool = False        # what the driver CLAIMS
    monitor_reliable: bool | None = None    # None = unknown, False = known bad
    bands: list[str] = field(default_factory=list)
    freqs_mhz: list[int] = field(default_factory=list)
    present: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def monitor_verdict(self) -> str:
        """Never say 'yes' when we only know 'the driver says so'.

        `iw list` reports the phy's advertised capability flags. That is a
        claim by the driver, not a measurement — and for several drivers it is
        a claim that does not survive contact with real traffic. Reporting an
        advertised flag as a confirmed capability is exactly the kind of
        confident-but-wrong output this whole product exists to avoid.
        """
        if not self.monitor_advertised:
            return "NOT SUPPORTED"
        if self.monitor_reliable is False:
            return "advertised — but UNRELIABLE on this driver"
        if self.monitor_reliable is True:
            return "supported (known-good driver)"
        return "advertised — not yet verified with real traffic"

    @property
    def summary(self) -> str:
        if not self.present:
            return f"{self.name}: NOT FOUND"
        b = "+".join(self.bands) if self.bands else "unknown"
        return (f"{self.name}: driver={self.driver or '?'} bus={self.bus or '?'} "
                f"bands={b} GHz — monitor: {self.monitor_verdict}")


def _run(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


# Known driver characteristics.
#   reliable=True   proven good for monitor mode
#   reliable=False  advertises monitor mode but does NOT deliver in practice
#   reliable=None   unknown — verify before trusting
DRIVER_NOTES: dict[str, tuple[bool | None, str]] = {
    # ── known-good USB capture adapters ──────────────────────────────────────
    "ath9k_htc": (True,
        "Atheros AR9271 — in-kernel, the gold standard for monitor mode. "
        "But 2.4 GHz and 802.11n ONLY: blind to 5/6 GHz and to 11ac/ax."),
    "mt76x2u": (True,
        "MediaTek MT7612U — in-kernel, 2.4+5 GHz, reliable capture. "
        "The reference adapter for this project."),
    "mt76x0u": (True, "MediaTek — in-kernel, generally reliable."),
    "carl9170": (True, "Atheros AR9170 — in-kernel, dated but honest."),

    # ── built-in PCIe chipsets: monitor mode advertised, rarely dependable ──
    "iwlwifi": (False,
        "Intel built-in card. It will ENTER monitor mode and then capture "
        "incompletely — commonly management and control frames but missing "
        "data frames, varying by band, kernel and firmware. Intel publishes no "
        "official monitor-mode support statement. Do NOT use for survey work."),
    "ath11k_pci": (False, "Qualcomm built-in — monitor mode largely non-functional."),
    "ath12k": (False, "Qualcomm built-in — monitor mode largely non-functional."),
    "mt7921e": (None, "MediaTek built-in — monitor mode varies by firmware. Verify."),
    "rtw89_8852ae": (False, "Realtek built-in — monitor mode unreliable."),

    # ── Realtek USB, out-of-tree: work, but fragile against kernel updates ──
    "88XXau": (True, "OUT-OF-TREE DKMS driver — pin the kernel (apt-mark hold)."),
    "8812au": (True, "OUT-OF-TREE DKMS driver — pin the kernel (apt-mark hold)."),
    "8821au": (True, "OUT-OF-TREE DKMS driver — pin the kernel (apt-mark hold)."),
    "rtl88x2bu": (True, "OUT-OF-TREE DKMS driver — pin the kernel (apt-mark hold)."),
    "88x2bu": (True, "OUT-OF-TREE DKMS driver — pin the kernel (apt-mark hold)."),
    "rtl8xxxu": (None, "Realtek in-kernel — monitor support varies by chip revision."),
    "rtw88_usb": (None, "Realtek in-kernel — monitor support varies."),
    "rtl8821au": (None,
        "Realtek RTL8811AU/8821AU — 'AC600' class, e.g. TP-Link Archer T2U Plus. "
        "2.4+5 GHz, 802.11ac, up to 80 MHz. Two things to know: (1) almost "
        "certainly an OUT-OF-TREE DKMS driver — run `dkms status` and if it is "
        "listed, `sudo apt-mark hold` your kernel. (2) It is 1x1, a single "
        "spatial stream, so it will miss frames in busy cells and cannot fully "
        "resolve 2x2+ MIMO transmissions. Usable for survey work; not a "
        "reference-grade sniffer."),
}

# Promotion rule for the table above:
#   reliability starts at None and is only ever raised to True by EVIDENCE —
#   a real capture from that chipset, committed as a fixture, whose frame
#   counts and retry rates look sane. Never promote a driver because the
#   internet says it works, and never because it advertised the capability.
#   That is the difference between a datasheet and a measurement.

# Drivers that only ever appear on internal cards.
BUILTIN_DRIVERS = {"iwlwifi", "ath11k_pci", "ath12k", "mt7921e", "rtw89_8852ae", "iwlmvm"}


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

    # driver name and bus come from ethtool; bus-info discriminates
    # PCI ("0000:00:14.3", i.e. built-in) from USB ("1-4:1.0", i.e. a dongle)
    if shutil.which("ethtool"):
        out = _run(["ethtool", "-i", iface])
        m = re.search(r"^driver:\s*(\S+)", out, re.M)
        if m:
            info.driver = m.group(1)
        bm = re.search(r"^bus-info:\s*(\S+)", out, re.M)
        if bm:
            info.bus = "pci" if re.match(r"^[0-9a-f]{4}:", bm.group(1)) else "usb"
    if info.bus is None and info.driver in BUILTIN_DRIVERS:
        info.bus = "pci"

    phy_m = re.search(r"wiphy\s+(\d+)", link)
    phy_out = _run(["iw", f"phy#{phy_m.group(1)}", "info"]) if phy_m else _run(["iw", "list"])

    if "* monitor" in phy_out:
        info.monitor_advertised = True

    for fm in re.finditer(r"^\s*\*\s+(\d{4})(?:\.\d+)?\s+MHz", phy_out, re.M):
        f = int(fm.group(1))
        info.freqs_mhz.append(f)
        b = _band_of(f)
        if b and b not in info.bands:
            info.bands.append(b)
    info.bands.sort()

    if info.driver and info.driver in DRIVER_NOTES:
        reliable, note = DRIVER_NOTES[info.driver]
        info.monitor_reliable = reliable
        info.notes.append(note)
    elif info.driver:
        info.notes.append(
            f"Driver '{info.driver}' is not in the known list — treat monitor "
            f"mode as unverified until you have captured real frames with it."
        )

    if info.bus == "pci":
        info.notes.append(
            "This is a BUILT-IN card, not a USB capture dongle. Built-in "
            "chipsets are designed to be good clients, not good sniffers."
        )
    if info.bands == ["2.4"]:
        info.notes.append(
            "2.4 GHz ONLY. Fine for learning the pipeline, but modern enterprise "
            "WiFi is on 5/6 GHz. Budget for an MT7612U adapter before real surveys."
        )
    if not info.monitor_advertised:
        info.notes.append("Monitor mode NOT advertised by this phy — capture will fail.")

    return info


def survey_capable_adapters() -> tuple[list[AdapterInfo], list[str]]:
    """All wireless adapters, plus advice about the set as a whole.

    Exists because the per-adapter view cannot answer the question that
    actually matters: *do you own anything you can survey with?*
    """
    infos = [probe_adapter(n) for n in list_wireless_interfaces()]
    advice: list[str] = []

    usable = [i for i in infos
              if i.monitor_advertised and i.monitor_reliable is not False]
    usb = [i for i in infos if i.bus == "usb"]

    if not infos:
        advice.append("No wireless interfaces at all. Is `iw` installed?")
    elif not usb:
        advice.append(
            "No USB wireless adapter detected — only built-in card(s). If your "
            "dongle is plugged in, it has not enumerated: check `lsusb`, then "
            "`sudo dmesg | tail -40` for a driver that failed to bind."
        )
    if not usable:
        advice.append(
            "Nothing here is dependable for monitor-mode survey work. Tier 2/3 "
            "captures will be incomplete in ways that are hard to detect."
        )
    return infos, advice


def list_wireless_interfaces() -> list[str]:
    out = _run(["iw", "dev"])
    return re.findall(r"^\s*Interface\s+(\S+)", out, re.M)

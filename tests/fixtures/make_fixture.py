"""Generate a synthetic 802.11 pcap with KNOWN ground truth.

╔══════════════════════════════════════════════════════════════════════════╗
║  This file is how you get CI coverage for hardware-dependent code.       ║
║                                                                           ║
║  The reducer's job is to count frames and compute retry percentages. To   ║
║  test that, you do not need a WiFi card, an AP, or a lab — you need a     ║
║  pcap whose correct answers you already know. So we synthesise one.       ║
║                                                                           ║
║  Every test then asserts against GROUND_TRUTH below. If the reducer says  ║
║  station A had 22% retries when we injected exactly 20%, the test fails   ║
║  on a Linux CI runner with no radio anywhere near it.                     ║
║                                                                           ║
║  The same trick applies to the wired side later: commit a small real      ║
║  pcap, assert on the conn.log Zeek produces from it.                      ║
╚══════════════════════════════════════════════════════════════════════════╝

Regenerate with:  python tests/fixtures/make_fixture.py
"""

from __future__ import annotations

from pathlib import Path

from scapy.all import (  # type: ignore[import-untyped]
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    RadioTap,
    Raw,
    wrpcap,
)

OUT = Path(__file__).parent / "wifi_lab.pcap"

# ── the scenario we are inventing ────────────────────────────────────────────
T0 = 1_755_500_000.0          # fixed epoch so tests are deterministic
DURATION_S = 10
FREQ_MHZ = 5180               # channel 36
AP_MAC = "aa:bb:cc:00:00:01"
STA_A = "11:22:33:aa:aa:aa"   # the unhappy client — 20% retries
STA_B = "11:22:33:bb:bb:bb"   # the healthy client — 5% retries

BEACONS_PER_SEC = 10
STA_A_FRAMES_PER_SEC = 20
STA_A_RETRY_PER_SEC = 4       # 4/20 = 20%
STA_B_FRAMES_PER_SEC = 10
STA_B_RETRY_PER_SEC = 1       # 1/10 = 10%
ACKS_PER_SEC = 5              # control frames, no transmitter address
DEAUTH_AT_SEC = 7             # one deauth event, to test event counting

GROUND_TRUTH = {
    "duration_s": DURATION_S,
    "freq_mhz": FREQ_MHZ,
    "channel": 36,
    "beacons_total": BEACONS_PER_SEC * DURATION_S,
    "sta_a_frames": STA_A_FRAMES_PER_SEC * DURATION_S,
    "sta_a_retries": STA_A_RETRY_PER_SEC * DURATION_S,
    "sta_a_retry_pct": 100.0 * STA_A_RETRY_PER_SEC / STA_A_FRAMES_PER_SEC,
    "sta_b_frames": STA_B_FRAMES_PER_SEC * DURATION_S,
    "sta_b_retries": STA_B_RETRY_PER_SEC * DURATION_S,
    "sta_b_retry_pct": 100.0 * STA_B_RETRY_PER_SEC / STA_B_FRAMES_PER_SEC,
    "deauth_total": 1,
    "frames_per_sec": (
        BEACONS_PER_SEC + STA_A_FRAMES_PER_SEC + STA_B_FRAMES_PER_SEC + ACKS_PER_SEC
    ),
    # second DEAUTH_AT_SEC carries one extra frame — the deauth itself
    "deauth_at_sec": DEAUTH_AT_SEC,
    # distinct transmitters seen per second: AP + STA_A + STA_B (ACKs have no TA)
    "distinct_stations_per_sec": 3,
}

RETRY_FLAG = 0x08   # Dot11 FCfield bit 3
TO_DS = 0x01


def _rt(rssi: int) -> RadioTap:
    """Radiotap header. `present` must be set explicitly or scapy emits an
    empty bitmap and tshark reports every field as absent."""
    return RadioTap(
        present="dBm_AntSignal+Channel+Rate",
        Rate=12,
        ChannelFrequency=FREQ_MHZ,
        ChannelFlags=0x0140,        # 5 GHz + OFDM
        dBm_AntSignal=rssi,
    )


def build() -> list:
    pkts = []

    for sec in range(DURATION_S):
        base = T0 + sec

        # AP beacons — steady, strong
        for i in range(BEACONS_PER_SEC):
            p = (_rt(-45)
                 / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                         addr2=AP_MAC, addr3=AP_MAC)
                 / Dot11Beacon(cap="ESS+privacy")
                 / Dot11Elt(ID="SSID", info="LAB-AP"))
            p.time = base + i * 0.1
            pkts.append(p)

        # Station A — far away, retrying hard
        for i in range(STA_A_FRAMES_PER_SEC):
            retry = i < STA_A_RETRY_PER_SEC
            p = (_rt(-78)
                 / Dot11(type=2, subtype=0,
                         FCfield=TO_DS | (RETRY_FLAG if retry else 0),
                         addr1=AP_MAC, addr2=STA_A, addr3=AP_MAC)
                 / Raw(b"\x00" * 200))
            p.time = base + 0.01 + i * 0.04
            pkts.append(p)

        # Station B — close, healthy
        for i in range(STA_B_FRAMES_PER_SEC):
            retry = i < STA_B_RETRY_PER_SEC
            p = (_rt(-52)
                 / Dot11(type=2, subtype=0,
                         FCfield=TO_DS | (RETRY_FLAG if retry else 0),
                         addr1=AP_MAC, addr2=STA_B, addr3=AP_MAC)
                 / Raw(b"\x00" * 120))
            p.time = base + 0.02 + i * 0.08
            pkts.append(p)

        # Control ACKs — note these carry NO transmitter address, which
        # exercises the reducer's empty-TA path.
        for i in range(ACKS_PER_SEC):
            p = _rt(-50) / Dot11(type=1, subtype=13, addr1=AP_MAC)
            p.time = base + 0.03 + i * 0.15
            pkts.append(p)

        # one deauth, mid-capture
        if sec == DEAUTH_AT_SEC:
            p = (_rt(-46)
                 / Dot11(type=0, subtype=12, addr1=STA_A, addr2=AP_MAC, addr3=AP_MAC)
                 / Dot11Deauth(reason=7))
            p.time = base + 0.5
            pkts.append(p)

    pkts.sort(key=lambda p: p.time)
    return pkts


if __name__ == "__main__":
    packets = build()
    wrpcap(str(OUT), packets)
    print(f"wrote {OUT} — {len(packets)} frames over {DURATION_S}s")
    for k, v in GROUND_TRUTH.items():
        print(f"  {k:28} {v}")

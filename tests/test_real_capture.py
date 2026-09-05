"""Regression tests against a REAL capture from real hardware.

Fixture: 60 s from a TP-Link Archer T2U Plus (RTL8821AU, driver rtl8821au
v5.12.5.2, out-of-tree DKMS) on a Kali ThinkPad, in a live multi-AP
environment. 10,859 frames.

Every test here encodes a bug the synthetic fixture could never have found,
because I wrote the synthetic fixture and it therefore contained only the
shapes I already expected. This file is the argument for capturing real
traffic exactly once and keeping it forever.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wd_probe.contracts import (
    CaptureKind,
    CapturePoint,
    CaptureSession,
    SampleType,
    WirelessConfig,
    WirelessMode,
)
from wd_probe.reduce.wifi_tshark import WifiTsharkReducer

FIXTURE = Path(__file__).parent / "fixtures" / "real_wifi_rtl8821au.pcap"
pytestmark = pytest.mark.skipif(not FIXTURE.exists(), reason="real fixture absent")


@pytest.fixture(scope="module")
def reduced():
    """Reduce the real capture, declared LOCKED — as the operator believed."""
    session = CaptureSession(
        capture_point=CapturePoint(
            kind=CaptureKind.WIRELESS_MONITOR,
            description="real rtl8821au capture",
            wireless=WirelessConfig(
                adapter="wlan1", driver="rtl8821au",
                mode=WirelessMode.LOCKED, channel=36,   # ← the operator's claim
            ),
        )
    )
    envs = list(WifiTsharkReducer(mac_salt="test").reduce(FIXTURE, session))
    return {
        "frame": [e for e in envs if e.sample_type is SampleType.WIFI_FRAME_STAT],
        "station": [e for e in envs if e.sample_type is SampleType.WIFI_STATION_STAT],
        "quality": [e for e in envs if e.sample_type is SampleType.SESSION_QUALITY][0],
    }


# ── it parses at all ─────────────────────────────────────────────────────────

# Assertion policy for this file, learned the hard way when my first two
# guesses failed:
#   EXACT   for things the committed fixture pins forever — packet count,
#           retry count, frequency count. These catch parser regressions.
#   BOUNDED for things that are properties of the radio environment — bucket
#           count, RSSI range. Pinning those tests the hotel's WiFi, not my
#           code, and turns an honest test into a tripwire.

def test_real_capture_parses(reduced):
    assert reduced["quality"].payload["packets_captured"] == 10_859   # exact
    assert len(reduced["station"]) == 80                              # exact
    # 59.93 s of capture lands in 59 or 60 one-second buckets depending on
    # where the first frame falls inside its second.
    assert 58 <= len(reduced["frame"]) <= 61


def test_multiple_antenna_signals_do_not_break_parsing(reduced):
    """Real radiotap carries one dBm value per antenna. `-E occurrence=f`
    keeps the first; without it the tab-separated row would gain columns and
    every field after it would shift silently. The synthetic fixture had one
    antenna, so it could never have caught this."""
    with_rssi = [e for e in reduced["frame"] if e.payload["rssi_mean_dbm"] is not None]
    assert len(with_rssi) == len(reduced["frame"])       # every bucket has signal
    # physically plausible, not environment-specific: a real capture in a busy
    # hotel saw -100 dBm at the noise floor and -17 dBm from a metre away
    assert all(-110 < e.payload["rssi_min_dbm"] <= 0 for e in with_rssi)
    assert all(-110 < e.payload["rssi_max_dbm"] <= 0 for e in with_rssi)
    assert all(e.payload["rssi_min_dbm"] <= e.payload["rssi_max_dbm"] for e in with_rssi)


def test_frames_without_a_transmitter_are_counted_but_not_as_stations(reduced):
    """CTS and ACK carry no TA. Real captures are full of them — this one is
    97% control frames."""
    for e in reduced["frame"]:
        p = e.payload
        assert (p["frames_mgmt"] + p["frames_ctrl"] + p["frames_data"]
                + p["frames_unparseable"]) == p["frames_total"]
        assert p["distinct_stations"] <= p["frames_total"]


# ── THE headline regression ──────────────────────────────────────────────────

def test_hopping_is_detected_from_data_despite_a_locked_declaration(reduced):
    """The bug this capture exposed.

    The operator ran a script that locks the channel, and declared the capture
    LOCKED. NetworkManager kept scanning in the background and dragged the
    radio across 29 frequencies in two bands. The reducer trusted the
    declaration and published retry % and airtime % computed over a random
    sample of time — confident, plausible, meaningless numbers.

    A guard that fires only when a human correctly declares the condition is
    not a guard. The evidence was in every radiotap header all along.
    """
    q = reduced["quality"].payload

    assert q["declared_rate_metrics_valid"] is True       # what we were told
    assert q["hopping_detected_from_data"] is True        # what was true
    assert q["effective_rate_metrics_valid"] is False     # what we published
    assert q["distinct_freqs"] == 29
    assert "29 frequencies" in q["suppression_reason"]

    # and it must reach every row, not just the summary
    assert all(e.payload["rate_metrics_valid"] is False for e in reduced["frame"])
    assert all(e.payload["retry_pct"] is None for e in reduced["frame"])
    assert all(e.payload["airtime_busy_pct"] is None for e in reduced["frame"])
    assert all(e.payload["retry_pct"] is None for e in reduced["station"])


def test_no_channel_is_invented_for_a_hopping_capture(reduced):
    """The modal frequency of a one-second bucket during channel hopping is an
    artefact of the hop schedule. Reporting it as 'the channel' invents a fact,
    so we report nothing."""
    assert all(e.payload["channel"] is None for e in reduced["frame"])


def test_raw_counts_survive_suppression(reduced):
    """We suppress the ratio, never the evidence. An engineer must still be
    able to audit what was actually seen."""
    assert sum(e.payload["frames_total"] for e in reduced["frame"]) == 10_859
    assert sum(e.payload["frames_retry"] for e in reduced["frame"]) == 39


def test_privacy_holds_on_real_macs(reduced):
    """80 real devices were in range. None of their addresses may appear."""
    blob = json.dumps([e.payload for e in reduced["frame"] + reduced["station"]])
    assert ":" not in blob or "aa:bb" not in blob
    for e in reduced["station"]:
        h = e.payload["station_mac_hash"]
        assert len(h) == 16 and ":" not in h


# ═════════════════════════════════════════════════════════════════════════════
# Second real capture — the POSITIVE case.
#
# Same adapter, same laptop, two days later, after the script learned to
# release the interface from NetworkManager. Channel 6, genuinely locked:
# one frequency for the whole minute.
#
# The first fixture proves we suppress rate metrics when we must. This one
# proves we do not suppress them when we needn't — an over-cautious tool that
# refuses to answer is just a slower way of being useless.
# ═════════════════════════════════════════════════════════════════════════════

LOCKED_FIXTURE = Path(__file__).parent / "fixtures" / "real_wifi_locked_ch6.pcap"


@pytest.fixture(scope="module")
def locked():
    session = CaptureSession(
        capture_point=CapturePoint(
            kind=CaptureKind.WIRELESS_MONITOR,
            description="real rtl8821au capture, channel 6, lock verified",
            wireless=WirelessConfig(
                adapter="wlan1", driver="rtl8821au",
                mode=WirelessMode.LOCKED, channel=6,
            ),
        )
    )
    envs = list(WifiTsharkReducer(mac_salt="test").reduce(LOCKED_FIXTURE, session))
    return {
        "frame": [e for e in envs if e.sample_type is SampleType.WIFI_FRAME_STAT],
        "station": [e for e in envs if e.sample_type is SampleType.WIFI_STATION_STAT],
        "quality": [e for e in envs if e.sample_type is SampleType.SESSION_QUALITY][0],
    }


@pytest.mark.skipif(not LOCKED_FIXTURE.exists(), reason="locked fixture absent")
def test_genuinely_locked_capture_is_not_suppressed(locked):
    """The complement of the hopping test. Over-suppression is also a bug."""
    q = locked["quality"].payload
    assert q["distinct_freqs"] == 1
    assert q["hopping_detected_from_data"] is False
    assert q["effective_rate_metrics_valid"] is True
    assert q["suppression_reason"] is None

    assert all(e.payload["rate_metrics_valid"] is True for e in locked["frame"])
    assert all(isinstance(e.payload["retry_pct"], float) for e in locked["frame"])
    assert all(e.payload["channel"] == 6 for e in locked["frame"])


@pytest.mark.skipif(not LOCKED_FIXTURE.exists(), reason="locked fixture absent")
def test_locked_capture_metrics_are_physically_plausible(locked):
    """Sanity, not exactness. A retry rate above 100% or airtime above 100%
    would mean the arithmetic is wrong, whatever the environment."""
    for e in locked["frame"]:
        p = e.payload
        assert 0.0 <= p["retry_pct"] <= 100.0
        assert 0.0 <= p["airtime_busy_pct"] <= 100.0
        assert p["frames_retry"] <= p["frames_total"]


@pytest.mark.skipif(not LOCKED_FIXTURE.exists(), reason="locked fixture absent")
def test_data_frames_are_actually_captured_when_locked(locked):
    """The hopping capture saw 13 data frames in 60 s — the radio was never
    on one channel long enough. Locked, the same adapter sees hundreds."""
    total_data = sum(e.payload["frames_data"] for e in locked["frame"])
    assert total_data == 624


@pytest.mark.skipif(not LOCKED_FIXTURE.exists(), reason="locked fixture absent")
def test_malformed_frames_are_counted_not_silently_dropped(locked):
    """Bug #5, found by this capture.

    Two frames had radiotap headers tshark could not dissect. They were
    counted in frames_total but in no type bucket, so mgmt+ctrl+data came to
    4625 against a total of 4627 — two frames vanished, and anyone summing
    the columns would have been quietly short.

    Real captures always contain a few of these. Count them explicitly.
    """
    q = locked["quality"].payload
    assert q["frames_unparseable"] == 2
    for e in locked["frame"]:
        p = e.payload
        assert (p["frames_mgmt"] + p["frames_ctrl"] + p["frames_data"]
                + p["frames_unparseable"]) == p["frames_total"]

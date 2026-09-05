"""Reducer tests — run on any Linux box, no WiFi hardware required."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fixtures.make_fixture import GROUND_TRUTH, STA_A, STA_B
from wd_probe.contracts import (
    CaptureKind,
    CapturePoint,
    CaptureSession,
    SampleType,
    WirelessConfig,
    WirelessMode,
)
from wd_probe.reduce.wifi_tshark import WifiTsharkReducer, _hash_mac, freq_to_channel

FIXTURE = Path(__file__).parent / "fixtures" / "wifi_lab.pcap"
SALT = "test-salt"


def _session(mode: WirelessMode = WirelessMode.LOCKED) -> CaptureSession:
    return CaptureSession(
        capture_point=CapturePoint(
            kind=CaptureKind.WIRELESS_MONITOR,
            description="fixture",
            wireless=WirelessConfig(adapter="test0", mode=mode, channel=36, width_mhz=80),
        )
    )


def _reduce(mode: WirelessMode = WirelessMode.LOCKED):
    sess = _session(mode)
    envs = list(WifiTsharkReducer(mac_salt=SALT).reduce(FIXTURE, sess))
    frame = [e for e in envs if e.sample_type is SampleType.WIFI_FRAME_STAT]
    station = [e for e in envs if e.sample_type is SampleType.WIFI_STATION_STAT]
    quality = [e for e in envs if e.sample_type is SampleType.SESSION_QUALITY]
    return sess, frame, station, quality


@pytest.fixture(scope="module")
def reduced():
    return _reduce()


# ── frame-level counts ───────────────────────────────────────────────────────

def test_one_bucket_per_second(reduced):
    _, frame, _, _ = reduced
    assert len(frame) == GROUND_TRUTH["duration_s"]


def test_frames_per_second_matches_injected(reduced):
    """Every second carries the injected frame count — plus the single deauth
    in one of them. Being exact about that extra frame rather than loosening
    the assertion is the difference between a test that catches a real
    off-by-one and a test that waves one through."""
    _, frame, _, _ = reduced
    base = GROUND_TRUTH["frames_per_sec"]
    for i, e in enumerate(frame):
        expected = base + (1 if i == GROUND_TRUTH["deauth_at_sec"] else 0)
        assert e.payload["frames_total"] == expected, f"second {i}"


def test_beacon_count_matches(reduced):
    _, frame, _, _ = reduced
    total = sum(e.payload["beacon_count"] for e in frame)
    assert total == GROUND_TRUTH["beacons_total"]


def test_deauth_detected_in_the_right_second(reduced):
    _, frame, _, _ = reduced
    deauths = [(e.ts.second, e.payload["deauth_count"]) for e in frame
               if e.payload["deauth_count"]]
    assert len(deauths) == 1
    assert deauths[0][1] == GROUND_TRUTH["deauth_total"]


def test_frame_type_split_is_exhaustive(reduced):
    """mgmt + ctrl + data must account for every frame — no silent drops."""
    _, frame, _, _ = reduced
    for e in frame:
        p = e.payload
        assert (p["frames_mgmt"] + p["frames_ctrl"] + p["frames_data"]
                + p["frames_unparseable"]) == p["frames_total"]


def test_channel_derived_from_radiotap_frequency(reduced):
    _, frame, _, _ = reduced
    assert all(e.payload["freq_mhz"] == GROUND_TRUTH["freq_mhz"] for e in frame)
    assert all(e.payload["channel"] == GROUND_TRUTH["channel"] for e in frame)


def test_distinct_stations_excludes_frames_without_a_transmitter(reduced):
    """ACK frames carry no TA. They must count as frames but not as stations."""
    _, frame, _, _ = reduced
    for e in frame:
        assert e.payload["distinct_stations"] == GROUND_TRUTH["distinct_stations_per_sec"]


# ── the headline metric ──────────────────────────────────────────────────────

def test_per_station_retry_pct_matches_ground_truth(reduced):
    _, _, station, _ = reduced
    by_hash = {e.payload["station_mac_hash"]: e.payload for e in station}

    a = by_hash[_hash_mac(STA_A, SALT)]
    assert a["frames"] == GROUND_TRUTH["sta_a_frames"]
    assert a["frames_retry"] == GROUND_TRUTH["sta_a_retries"]
    assert a["retry_pct"] == pytest.approx(GROUND_TRUTH["sta_a_retry_pct"])

    b = by_hash[_hash_mac(STA_B, SALT)]
    assert b["frames"] == GROUND_TRUTH["sta_b_frames"]
    assert b["frames_retry"] == GROUND_TRUTH["sta_b_retries"]
    assert b["retry_pct"] == pytest.approx(GROUND_TRUTH["sta_b_retry_pct"])


def test_rssi_range_per_station(reduced):
    """Station A was injected at -78 dBm, B at -52. The far one must read weaker."""
    _, _, station, _ = reduced
    by_hash = {e.payload["station_mac_hash"]: e.payload for e in station}
    a = by_hash[_hash_mac(STA_A, SALT)]
    b = by_hash[_hash_mac(STA_B, SALT)]
    assert a["rssi_min_dbm"] == a["rssi_max_dbm"] == -78
    assert b["rssi_min_dbm"] == b["rssi_max_dbm"] == -52
    assert a["rssi_min_dbm"] < b["rssi_min_dbm"]


# ── the hopping guard — the rule that stops us publishing nonsense ───────────

def test_hopping_capture_suppresses_rate_metrics():
    """A hopping capture must report retry_pct as None, not as a number.

    This is the single most important behavioural test in the suite. The
    frames are identical; only the capture point's mode differs. If this ever
    starts returning a float, the tool has begun publishing statistics with a
    random denominator — plausible-looking numbers that are simply wrong.
    """
    _, frame, station, _ = _reduce(WirelessMode.HOPPING)

    assert all(e.payload["retry_pct"] is None for e in frame)
    assert all(e.payload["airtime_busy_pct"] is None for e in frame)
    assert all(e.payload["rate_metrics_valid"] is False for e in frame)
    assert all(e.payload["retry_pct"] is None for e in station)

    # raw counts are still recorded — we suppress the ratio, not the evidence
    assert all(e.payload["frames_total"] > 0 for e in frame)
    assert all(e.payload["frames_retry"] >= 0 for e in frame)


def test_locked_capture_publishes_rate_metrics(reduced):
    _, frame, _, _ = reduced
    assert all(e.payload["rate_metrics_valid"] is True for e in frame)
    assert all(isinstance(e.payload["retry_pct"], float) for e in frame)


# ── quality accounting ───────────────────────────────────────────────────────

def test_session_quality_emitted_and_totals_agree(reduced):
    _, frame, _, quality = reduced
    assert len(quality) == 1
    q = quality[0].payload
    assert q["packets_captured"] == sum(e.payload["frames_total"] for e in frame)
    assert q["loss_pct"] == 0.0


# ── privacy ──────────────────────────────────────────────────────────────────

def test_mac_hash_is_stable_salted_and_opaque():
    assert _hash_mac(STA_A, SALT) == _hash_mac(STA_A.upper(), SALT)   # case-insensitive
    assert _hash_mac(STA_A, SALT) != _hash_mac(STA_A, "other-salt")   # salted
    assert STA_A.replace(":", "") not in _hash_mac(STA_A, SALT)       # not reversible by eye


def test_raw_macs_never_appear_in_any_payload(reduced):
    """Regression guard: a raw MAC leaking into an uploaded payload is a
    privacy incident, so assert it at the boundary rather than trusting review."""
    _, frame, station, quality = reduced
    blob = json.dumps([e.payload for e in frame + station + quality])
    for mac in (STA_A, STA_B):
        assert mac not in blob


# ── helpers ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("freq,chan", [
    (2412, 1), (2437, 6), (2462, 11), (2484, 14),
    (5180, 36), (5745, 149), (5955, 1),
])
def test_freq_to_channel(freq, chan):
    assert freq_to_channel(freq) == chan

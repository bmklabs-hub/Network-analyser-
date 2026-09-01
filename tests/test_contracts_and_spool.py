"""Contract and spool tests — the architectural guarantees, asserted."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from wd_probe.contracts import (
    CaptureKind,
    CapturePoint,
    CaptureQuality,
    CaptureSession,
    Envelope,
    SampleType,
    WiredConfig,
    WirelessConfig,
    WirelessMode,
)
from wd_probe.reduce.base import Reducer
from wd_probe.reduce.wifi_tshark import WifiTsharkReducer
from wd_probe.reduce.zeek import ZeekReducer
from wd_probe.spool import Spool

UTC_NOW = datetime.now(timezone.utc)


def _env(session_id: str = "s1", uuid: str | None = None) -> Envelope:
    kw = {"sample_uuid": uuid} if uuid else {}
    return Envelope(
        session_id=session_id,
        capture_point_id="cp-1",
        sample_type=SampleType.WIFI_FRAME_STAT,
        ts=UTC_NOW,
        payload={"frames_total": 1},
        **kw,
    )


# ── timestamps ───────────────────────────────────────────────────────────────

def test_envelope_rejects_naive_timestamps():
    """Cross-domain correlation is timestamp matching. One naive datetime
    anywhere in the pipeline silently corrupts it, so we refuse at the edge."""
    with pytest.raises(ValueError, match="timezone-aware"):
        Envelope(
            session_id="s1", capture_point_id="cp-1",
            sample_type=SampleType.WIFI_FRAME_STAT,
            ts=datetime.now(),                  # naive — no tzinfo
            payload={},
        )


def test_envelope_accepts_utc():
    assert _env().ts.tzinfo is not None


# ── the hopping guard, at the contract level ─────────────────────────────────

def test_locked_wireless_point_allows_rate_metrics():
    cp = CapturePoint(
        kind=CaptureKind.WIRELESS_MONITOR,
        wireless=WirelessConfig(adapter="wlan1", mode=WirelessMode.LOCKED, channel=36),
    )
    assert cp.rate_metrics_valid is True


def test_hopping_wireless_point_forbids_rate_metrics():
    cp = CapturePoint(
        kind=CaptureKind.WIRELESS_MONITOR,
        wireless=WirelessConfig(adapter="wlan1", mode=WirelessMode.HOPPING,
                                hop_set=[1, 6, 11, 36, 40], dwell_ms=250),
    )
    assert cp.rate_metrics_valid is False


def test_wired_point_always_allows_rate_metrics():
    cp = CapturePoint(kind=CaptureKind.SPAN, wired=WiredConfig(interface="eth1"))
    assert cp.rate_metrics_valid is True


# ── drop accounting ──────────────────────────────────────────────────────────

def test_loss_pct_and_analyzability():
    q = CaptureQuality(packets_captured=9_900, drops_kernel=100)
    assert q.total_drops == 100
    assert q.loss_pct == 1.0
    assert q.is_analyzable(max_loss_pct=1.0) is True
    assert q.is_analyzable(max_loss_pct=0.5) is False


def test_lossy_capture_is_rejected():
    q = CaptureQuality(packets_captured=7_000, drops_kernel=2_000, drops_interface=1_000)
    assert q.loss_pct == 30.0
    assert q.is_analyzable() is False


def test_zero_traffic_does_not_divide_by_zero():
    assert CaptureQuality().loss_pct == 0.0


# ── the seam ─────────────────────────────────────────────────────────────────

def test_both_reducers_satisfy_the_same_protocol():
    """The whole justification for building wireless first.

    If the wired reducer could not satisfy the same Protocol, the contracts
    were shaped around 802.11 and the wired work would be a refactor rather
    than an addition.
    """
    assert isinstance(WifiTsharkReducer(), Reducer)
    assert isinstance(ZeekReducer(), Reducer)


def test_reducers_claim_disjoint_capture_kinds():
    wifi, zeek = WifiTsharkReducer(), ZeekReducer()
    wireless = CaptureSession(capture_point=CapturePoint(
        kind=CaptureKind.WIRELESS_MONITOR,
        wireless=WirelessConfig(adapter="wlan1", channel=36)))
    wired = CaptureSession(capture_point=CapturePoint(
        kind=CaptureKind.SPAN, wired=WiredConfig(interface="eth1")))

    assert wifi.supports(wireless) and not wifi.supports(wired)
    assert zeek.supports(wired) and not zeek.supports(wireless)


# ── spool ────────────────────────────────────────────────────────────────────

@pytest.fixture
def spool(tmp_path):
    s = Spool(tmp_path / "spool.db")
    yield s
    s.close()


def test_insert_is_idempotent(spool):
    """A retried upload batch must never duplicate data. The probe mints the
    UUID, so the same sample re-inserted is a no-op."""
    e = _env(uuid="fixed-uuid-1")
    assert spool.add_many([e]) == 1
    assert spool.add_many([e]) == 0
    assert spool.stats()["samples"] == 1


def test_unsent_queue_is_just_a_null_column(spool):
    envs = [_env() for _ in range(5)]
    spool.add_many(envs)
    assert len(spool.unsent()) == 5

    spool.mark_sent([e.sample_uuid for e in envs[:3]])
    assert len(spool.unsent()) == 2
    assert spool.stats()["pending_upload"] == 2


def test_session_round_trips_with_quality(spool):
    sess = CaptureSession(
        capture_point=CapturePoint(
            kind=CaptureKind.WIRELESS_MONITOR,
            description="round trip",
            wireless=WirelessConfig(adapter="wlan1", channel=36, mode=WirelessMode.LOCKED),
        ),
        ended_at=UTC_NOW + timedelta(seconds=60),
    )
    sess.quality.packets_captured = 1234
    sess.quality.drops_kernel = 6
    spool.save_session(sess)

    row = spool.get_session(sess.id)
    assert row is not None
    assert "round trip" in row["capture_point"]
    assert '"packets_captured":1234' in row["quality"].replace(" ", "")


def test_save_session_twice_updates_rather_than_duplicating(spool):
    sess = CaptureSession(capture_point=CapturePoint(
        kind=CaptureKind.WIRELESS_MONITOR,
        wireless=WirelessConfig(adapter="wlan1", channel=36)))
    spool.save_session(sess)
    sess.notes = "updated"
    spool.save_session(sess)
    assert spool.stats()["sessions"] == 1
    assert spool.get_session(sess.id)["notes"] == "updated"


def test_survives_reopen(tmp_path):
    """Durability: the spool must outlive the process, not just the run."""
    path = tmp_path / "spool.db"
    s1 = Spool(path)
    s1.add_many([_env(uuid="persist-me")])
    s1.close()

    s2 = Spool(path)
    assert s2.stats()["samples"] == 1
    assert s2.unsent()[0]["sample_uuid"] == "persist-me"
    s2.close()

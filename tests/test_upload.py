"""Uploader + ADR-29 tests — probe side, no server and no network needed.

`urllib.request.urlopen` is replaced by a fake that plays back scripted
replies, so we can test the hard cases on demand: a server that is down, a
server that rejects the token, a server that acknowledges only part of a
batch. Those are exactly the cases you never see in a happy-path lab test.
"""

from __future__ import annotations

import io
import json
import shutil
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wd_probe.contracts import (
    CaptureKind,
    CapturePoint,
    CaptureSession,
    Envelope,
    SampleType,
    WirelessConfig,
    WirelessMode,
)
from wd_probe.reduce.wifi_tshark import WifiTsharkReducer
from wd_probe.spool import Spool
from wd_probe.upload import Uploader, UploadError

FIXTURES = Path(__file__).parent / "fixtures"
HOPPING_REAL = FIXTURES / "real_wifi_rtl8821au.pcap"
needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")


# ── helpers ──────────────────────────────────────────────────────────────────

def _session() -> CaptureSession:
    return CaptureSession(capture_point=CapturePoint(
        kind=CaptureKind.WIRELESS_MONITOR,
        wireless=WirelessConfig(adapter="test", mode=WirelessMode.LOCKED, channel=6),
    ))


def _spool_with(tmp_path: Path, n: int) -> tuple[Spool, CaptureSession]:
    sp = Spool(tmp_path / "spool.db")
    s = _session()
    sp.save_session(s)
    now = datetime.now(timezone.utc)
    sp.add_many(
        Envelope(session_id=s.id, capture_point_id=s.capture_point.id,
                 sample_type=SampleType.WIFI_FRAME_STAT, ts=now, payload={"i": i})
        for i in range(n)
    )
    return sp, s


class FakeServer:
    """Scripted replacement for urlopen. Each entry in `script` is either an
    int (HTTP error status) or the string "ok" / "partial" / "down"."""

    def __init__(self, script: list) -> None:
        self.script = list(script)
        self.bodies: list[dict] = []

    def __call__(self, req, timeout=None):
        body = json.loads(req.data)
        self.bodies.append(body)
        step = self.script.pop(0) if self.script else "ok"
        uuids = [s["sample_uuid"] for s in body["samples"]]
        if step == "down":
            raise urllib.error.URLError("connection refused")
        if isinstance(step, int):
            raise urllib.error.HTTPError(req.full_url, step, "err", {}, io.BytesIO(b"nope"))
        if step == "partial":
            uuids = uuids[:1]
        return _Resp({"accepted": uuids, "inserted": len(uuids), "duplicates": 0})


class _Resp(io.BytesIO):
    def __init__(self, obj: dict) -> None:
        super().__init__(json.dumps(obj).encode())

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _uploader(sp: Spool, **kw) -> Uploader:
    return Uploader(sp, "http://server", "tok", sleep=lambda s: None, **kw)


# ── uploader behaviour ───────────────────────────────────────────────────────

def test_upload_drains_spool_in_batches(tmp_path, monkeypatch):
    sp, s = _spool_with(tmp_path, 25)
    fake = FakeServer([])
    monkeypatch.setattr("urllib.request.urlopen", fake)
    res = _uploader(sp, batch_size=10).run()
    assert res.samples_sent == 25 and res.batches == 3
    assert sp.stats()["pending_upload"] == 0


def test_every_batch_carries_its_sessions(tmp_path, monkeypatch):
    """The server rejects samples whose session it has never seen, so each
    batch must be self-sufficient."""
    sp, s = _spool_with(tmp_path, 3)
    fake = FakeServer([])
    monkeypatch.setattr("urllib.request.urlopen", fake)
    _uploader(sp).run()
    assert [x["id"] for x in fake.bodies[0]["sessions"]] == [s.id]


def test_temporary_failure_is_retried_then_succeeds(tmp_path, monkeypatch):
    sp, _ = _spool_with(tmp_path, 5)
    monkeypatch.setattr("urllib.request.urlopen", FakeServer(["down", 503, "ok"]))
    res = _uploader(sp).run()
    assert res.retries == 2 and res.samples_sent == 5
    assert sp.stats()["pending_upload"] == 0


def test_bad_token_is_not_retried_and_nothing_is_marked_sent(tmp_path, monkeypatch):
    """401 will fail identically forever. Retrying only hammers the server."""
    sp, _ = _spool_with(tmp_path, 5)
    fake = FakeServer([401])
    monkeypatch.setattr("urllib.request.urlopen", fake)
    with pytest.raises(UploadError, match="401"):
        _uploader(sp).run()
    assert len(fake.bodies) == 1
    assert sp.stats()["pending_upload"] == 5


def test_giving_up_keeps_everything_in_the_spool(tmp_path, monkeypatch):
    sp, _ = _spool_with(tmp_path, 5)
    monkeypatch.setattr("urllib.request.urlopen", FakeServer(["down"] * 10))
    with pytest.raises(UploadError, match="gave up"):
        _uploader(sp, max_retries=3).run()
    assert sp.stats()["pending_upload"] == 5        # store-and-forward: nothing lost


def test_only_server_acknowledged_samples_are_marked_sent(tmp_path, monkeypatch):
    """Mark what the server CONFIRMED, not what we SENT."""
    sp, _ = _spool_with(tmp_path, 5)
    monkeypatch.setattr("urllib.request.urlopen", FakeServer(["partial"]))
    res = _uploader(sp).run()
    assert res.samples_sent == 1 and res.errors
    assert sp.stats()["pending_upload"] == 4


def test_missing_token_fails_before_any_network_call(tmp_path):
    sp, _ = _spool_with(tmp_path, 1)
    with pytest.raises(UploadError, match="token"):
        Uploader(sp, "http://server", "")


# ── ADR-29: the verdict reaches the session ──────────────────────────────────

@needs_tshark
@pytest.mark.skipif(not HOPPING_REAL.exists(), reason="real fixture absent")
def test_verdict_reaches_the_session_not_only_the_sample(tmp_path):
    """The original bug: the reducer concluded "hopping" but wrote that only
    into a sample. The session row — the thing that is persisted, uploaded
    and displayed — still said "locked, valid". Every unit test passed.

    Here: declare LOCKED, reduce a capture that actually hopped, then read the
    session BACK FROM THE SPOOL (not from memory) and check the verdict."""
    s = _session()
    sp = Spool(tmp_path / "spool.db")
    sp.save_session(s)
    sp.add_many(WifiTsharkReducer(mac_salt="t").reduce(HOPPING_REAL, s))
    sp.save_session(s)

    q = json.loads(sp.get_session(s.id)["quality"])
    assert q["hopping_detected"] is True
    assert q["effective_rate_metrics_valid"] is False
    assert q["distinct_freqs"] > 2
    assert "declared locked" in q["suppression_reason"]

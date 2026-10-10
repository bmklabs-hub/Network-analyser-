"""ADR-28 — the server duplicates the Envelope; this file stops it drifting.

Needs wd_probe installed alongside (CI installs both). Skipped otherwise,
loudly, rather than passing vacuously.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

probe = pytest.importorskip("wd_probe.contracts", reason="wd_probe not installed")

from wd_server import schemas  # noqa: E402

from .conftest import AUTH  # noqa: E402


def test_probe_and_server_envelopes_have_not_drifted():
    p = probe.Envelope.model_fields
    s = schemas.Envelope.model_fields
    assert set(p) == set(s), f"field drift: probe-only={set(p) - set(s)}, server-only={set(s) - set(p)}"


def test_sample_type_enums_match():
    assert {t.value for t in probe.SampleType} == {t.value for t in schemas.SampleType}


def test_every_probe_sample_type_is_ingestable(client):
    """Including the wired types nothing emits yet — the day Zeek lands, the
    server must already accept them (ADR-23's falsification test)."""
    cp = probe.CapturePoint(kind=probe.CaptureKind.WIRELESS_MONITOR,
                            wireless=probe.WirelessConfig(adapter="t"))
    sess = probe.CaptureSession(capture_point=cp)
    samples = [
        json.loads(probe.Envelope(
            session_id=sess.id, capture_point_id=cp.id, sample_type=t,
            ts=datetime.now(timezone.utc), payload={"k": 1},
        ).model_dump_json())
        for t in probe.SampleType
    ]
    batch = {"sessions": [json.loads(sess.model_dump_json())], "samples": samples}
    r = client.post("/api/v1/ingest", json=batch, headers=AUTH)
    assert r.status_code == 200, r.text
    assert r.json()["inserted"] == len(probe.SampleType)

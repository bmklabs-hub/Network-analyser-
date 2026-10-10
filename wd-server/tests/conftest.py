from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from wd_server.app import create_app
from wd_server.config import Settings

TOKEN = "lab-token-123"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(db_path=tmp_path / "server.db",
                              probe_tokens={TOKEN: "kali-lab"}))
    with TestClient(app) as c:
        yield c


@pytest.fixture
def closed_client(tmp_path):
    """A server started with NO tokens — must refuse all ingest."""
    app = create_app(Settings(db_path=tmp_path / "server.db", probe_tokens={}))
    with TestClient(app) as c:
        yield c


def session_dict(sid="sess-abc", *, declared_mode="locked", quality=None):
    return {
        "id": sid,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "capture_point": {
            "id": "cp-1", "kind": "wireless_monitor", "site_id": "lab",
            "description": "test", "rate_metrics_valid": declared_mode == "locked",
            "wireless": {"adapter": "wlan1", "mode": declared_mode, "channel": 6},
        },
        "quality": quality if quality is not None else {
            "packets_captured": 100, "loss_pct": 0.0,
            "effective_rate_metrics_valid": True, "hopping_detected": False,
        },
    }


def sample_dict(uuid="u-00000001", sid="sess-abc", **kw):
    d = {
        "sample_uuid": uuid, "session_id": sid, "capture_point_id": "cp-1",
        "sample_type": "wifi_frame_stat",
        "ts": datetime.now(timezone.utc).isoformat(),
        "payload": {"frames_total": 10, "frames_retry": 1, "retry_pct": 10.0},
    }
    d.update(kw)
    return d

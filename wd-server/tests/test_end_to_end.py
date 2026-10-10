"""The smoke test that found the ADR-29 bug — keep it, run it every phase.

Real pcap → real reducer → real spool → real uploader over real HTTP →
real server → real HTML. No mocks anywhere in the chain.

Unit tests check that each box behaves. Only this checks that the boxes are
wired together. When it was first run, all 76 unit tests were green and the
web page still called a 29-frequency capture trustworthy.
"""

from __future__ import annotations

import shutil
import socket
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("wd_probe", reason="wd_probe not installed")
uvicorn = pytest.importorskip("uvicorn")

from wd_probe.contracts import (  # noqa: E402
    CaptureKind, CapturePoint, CaptureSession, WirelessConfig, WirelessMode,
)
from wd_probe.reduce.wifi_tshark import WifiTsharkReducer  # noqa: E402
from wd_probe.spool import Spool  # noqa: E402
from wd_probe.upload import Uploader  # noqa: E402

from wd_server.app import create_app  # noqa: E402
from wd_server.config import Settings  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
HOPPING = FIXTURES / "real_wifi_rtl8821au.pcap"
LOCKED = FIXTURES / "real_wifi_locked_ch6.pcap"

pytestmark = [
    pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed"),
    pytest.mark.skipif(not HOPPING.exists(), reason="real fixtures absent"),
]


@pytest.fixture
def live_server(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    app = create_app(Settings(db_path=tmp_path / "server.db", probe_tokens={"e2e": "kali-lab"}))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", app
    server.should_exit = True
    t.join(timeout=5)


def _capture_reduce_upload(tmp_path, url, pcap: Path, channel: int) -> str:
    cp = CapturePoint(kind=CaptureKind.WIRELESS_MONITOR, description=pcap.name,
                      wireless=WirelessConfig(adapter="wlan1", mode=WirelessMode.LOCKED,
                                              channel=channel))
    s = CaptureSession(capture_point=cp, pcap_path=str(pcap))
    sp = Spool(tmp_path / f"{pcap.stem}.db")
    sp.save_session(s)
    sp.add_many(WifiTsharkReducer(mac_salt="e2e").reduce(pcap, s))
    sp.save_session(s)
    res = Uploader(sp, url, "e2e").run()
    assert res.samples_sent > 0 and sp.stats()["pending_upload"] == 0
    # Upload again: everything is already sent, so nothing moves.
    assert Uploader(sp, url, "e2e").run().samples_sent == 0
    sp.close()
    return s.id


def test_hopping_capture_declared_locked_is_shown_as_untrustworthy(tmp_path, live_server):
    url, app = live_server
    sid = _capture_reduce_upload(tmp_path, url, HOPPING, channel=36)

    import urllib.request
    listing = urllib.request.urlopen(url + "/").read().decode()
    detail = urllib.request.urlopen(f"{url}/sessions/{sid}").read().decode()

    assert sid in listing
    assert "rate metrics suppressed" in listing
    assert "declared locked, data says hopping" in listing
    assert "trustworthy" not in listing
    assert "declared locked" in detail


@pytest.mark.skipif(not LOCKED.exists(), reason="locked fixture absent")
def test_genuinely_locked_capture_is_shown_as_trustworthy(tmp_path, live_server):
    """The complement — over-suppression is also a bug."""
    url, app = live_server
    sid = _capture_reduce_upload(tmp_path, url, LOCKED, channel=6)
    import urllib.request
    detail = urllib.request.urlopen(f"{url}/sessions/{sid}").read().decode()
    assert "trustworthy" in detail
    assert "suppressed" not in detail

"""Preflight tests — run the capture engine's checks with the hardware faked.

Why this file exists: `preflight()` crashed on the first real run with
`AttributeError: 'AdapterInfo' object has no attribute 'monitor_capable'`.
The reducer had 50+ tests; the capture path had none, because it "needs a
radio". It doesn't — it needs `iw`'s *answers*, which we can script.

The lesson: code that is hard to test is not exempt from testing. Fake the
boundary (here: `probe_adapter` and `iw dev <if> info`) and test the logic.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from wd_probe.capabilities import AdapterInfo
from wd_probe.capture import wireless
from wd_probe.capture.wireless import WirelessCaptureEngine
from wd_probe.contracts import WirelessMode


def _fake(monkeypatch, *, present=True, advertised=True, iw_type="monitor"):
    monkeypatch.setattr(wireless.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        wireless, "probe_adapter",
        lambda iface: AdapterInfo(name=iface, present=present, monitor_advertised=advertised),
    )
    real_run = subprocess.run

    def fake_run(cmd, *a, **kw):
        if cmd[:2] == ["iw", "dev"]:
            return SimpleNamespace(stdout=f"Interface wlan1\n\ttype {iw_type}\n\tchannel 6\n",
                                   stderr="", returncode=0)
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(wireless.subprocess, "run", fake_run)


def _engine(**kw):
    return WirelessCaptureEngine(iface="wlan1", channel=6, mode=WirelessMode.LOCKED, **kw)


def test_ready_adapter_passes_preflight(monkeypatch):
    _fake(monkeypatch)
    assert _engine().preflight() == []


def test_adapter_still_in_managed_mode_is_refused_with_the_fix(monkeypatch):
    _fake(monkeypatch, iw_type="managed")
    problems = _engine().preflight()
    assert any("NOT currently in monitor mode" in p for p in problems)
    assert any("iw dev wlan1 set monitor control" in p for p in problems)


def test_adapter_without_monitor_support_is_refused(monkeypatch):
    _fake(monkeypatch, advertised=False)
    assert any("does not advertise monitor mode" in p for p in _engine().preflight())


def test_missing_interface_is_refused(monkeypatch):
    _fake(monkeypatch, present=False)
    assert _engine().preflight() == ["interface wlan1 not found"]


def test_locked_mode_needs_a_channel(monkeypatch):
    _fake(monkeypatch)
    e = WirelessCaptureEngine(iface="wlan1", channel=None, mode=WirelessMode.LOCKED)
    assert any("requires --channel" in p for p in e.preflight())


@pytest.mark.parametrize("field", ["monitor_advertised", "present", "monitor_reliable"])
def test_preflight_only_uses_fields_that_exist(field):
    """Cheap guard against the exact bug: every AdapterInfo field preflight
    relies on must actually exist on the dataclass."""
    assert hasattr(AdapterInfo(name="x"), field)

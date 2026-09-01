# wd-probe

Capture-and-reduce probe for the WiFi-Diagnose platform.
**Phase 1-W** — wireless path working, wired path stubbed behind the same seam.

---

## The one rule this codebase exists to enforce

You are building wireless first because that is the hardware you have. The risk
is that you accidentally build a *wireless pipeline* instead of a *pipeline with
a wireless collector* — and then the wired work becomes a rewrite.

The defence is `src/wd_probe/contracts.py`. Nothing in it mentions 802.11.
Both reducers satisfy the same `Reducer` protocol, and there is a test that
asserts it:

```python
def test_both_reducers_satisfy_the_same_protocol():
    assert isinstance(WifiTsharkReducer(), Reducer)
    assert isinstance(ZeekReducer(), Reducer)
```

If that test ever fails, the seam has drifted and the wired work just became
expensive. Do not delete it.

---

## Layout

```
src/wd_probe/
  contracts.py            ← START HERE. Domain-neutral shapes. The seam.
  capabilities.py            Honest adapter probing: driver, bands, monitor support
  capture/
    base.py                  CaptureEngine protocol — stage 1, must never block
    wireless.py              dumpcap monitor-mode capture + drop accounting
  reduce/
    base.py                  Reducer protocol — stage 2, offline batch
    wifi_tshark.py           802.11 → per-second + per-station rollups
    zeek.py                  wired → conn/dns/ssl.  STUB. Proves the seam.
  spool.py                   SQLite outbox: durable, idempotent, survives kill -9
  cli.py                     capabilities / capture / reduce / sessions / report

tests/
  fixtures/make_fixture.py   Synthetic 802.11 pcap with KNOWN ground truth
  test_wifi_reducer.py       Asserts computed stats == injected stats
  test_contracts_and_spool.py  Asserts the architectural guarantees
```

---

## Install

On Kali, Ubuntu, or Debian:

```bash
sudo apt install -y tshark wireshark-common iw ethtool python3-pip
sudo dpkg-reconfigure wireshark-common      # answer YES: non-root capture
sudo usermod -aG wireshark $USER            # then log out and back in

cd wd-probe
pip install -e ".[dev]"
```

## Verify it works — no radio needed

```bash
python tests/fixtures/make_fixture.py    # regenerate the synthetic pcap
pytest -q                                # 36 tests, all offline
```

That suite runs on any Linux box with `tshark`, including a CI runner with no
wireless hardware anywhere near it. That is deliberate — see §Fixtures below.

## Try it on the fixture

```bash
wd-probe reduce tests/fixtures/wifi_lab.pcap --channel 36
wd-probe sessions
wd-probe report <session-id>
```

You should see station `…` at 20% retries and −78 dBm — the unhappy client
we injected — next to a healthy one at 10% and −52 dBm.

Now run the same file as a *hopping* capture and watch the numbers disappear:

```bash
wd-probe reduce tests/fixtures/wifi_lab.pcap --channel 36 --hopping
wd-probe report <new-session-id>
```

Identical frames, but `retry %` and `airtime %` render as `—`. That is the
hopping guard doing its job.

## Real capture

```bash
wd-probe capabilities                       # what can this adapter actually do?

sudo ip link set wlan1 down
sudo iw dev wlan1 set monitor control
sudo ip link set wlan1 up

wd-probe capture -i wlan1 -c 36 -w 80 -d 120
wd-probe report <session-id>
```

`capture` refuses to start if the adapter is not actually in monitor mode, if
the phy does not advertise monitor support, or if you asked for locked mode
without a channel. Preflight failures cost a second; discovering them after a
20-minute customer-site capture costs the engagement.

---

## Three ideas worth understanding before you extend this

### 1. Capture and reduce are separate stages, on purpose

`dumpcap` writes packets and does nothing else. Zeek and tshark run afterwards,
over closed files. If you dissect while capturing, a CPU spike becomes dropped
packets — and dropped packets are silent corruption, not a slow dashboard.

Because of this split, a CPU shortage produces *analysis lag*, not *data loss*.
Lag is recoverable. Loss is not. This is what makes a 4-core box viable at
1 GbE, and it is the single highest-value decision in the design.

### 2. The hopping guard

A radio that channel-hops sees roughly `dwell_ms / cycle_ms` of any channel —
often about 3%. Retry percentage computed from that has a random denominator.

So `CapturePoint.rate_metrics_valid` is `False` for hopping captures, the flag
travels *inside every payload row*, and `retry_pct` returns `None` rather than
a number. Raw counts are still recorded; only the ratio is suppressed.

Putting the caveat in the data rather than in a README is what stops it getting
lost the first time somebody reads a row in isolation.

### 3. Drop accounting is not optional

`CaptureQuality` records kernel drops, interface drops and estimated drops, and
`is_analyzable()` refuses captures past a loss threshold. A capture that lost
30% of frames produces confident, plausible, wrong analysis.

**A measurement instrument that cannot detect its own miscalibration is worse
than no instrument, because people believe it.**

---

## Fixtures — how to test hardware-dependent code

`tests/fixtures/make_fixture.py` builds an 802.11 pcap with scapy in which we
*chose* the answers: 200 frames from station A with exactly 40 retries, 100
beacons, one deauth in second 7. The tests assert the reducer recovers exactly
those numbers.

Use the same trick for the wired side: commit a small real pcap, assert on the
`conn.log` Zeek produces from it. It is the only practical way to keep
hardware-coupled parsers under test.

> While writing these tests, the ground truth was wrong before the code was —
> the fixture claimed 45 frames in every second, forgetting the deauth made one
> second 46. The test caught it. That is the value: it disagrees with you.

---

## Next

| Step | Where |
|------|-------|
| Uploader + FastAPI ingest | new `wd_probe/upload.py`, new `wd-server` |
| Findings engine (`high_retry_rate`, `deauth_flood`) | new `wd_probe/rules/` — but server-side, per design §6.3 |
| Wired capture | `reduce/zeek.py` — implement, change nothing else |
| Channel hopper | `capture/wireless.py`, survey mode |

The wired step is the one to watch. If implementing `ZeekReducer` requires
edits to `contracts.py`, `spool.py`, or `cli.py`, then the seam was drawn in
the wrong place — and finding that out is worth more than the code.

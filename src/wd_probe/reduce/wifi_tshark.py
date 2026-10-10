"""802.11 reducer — tshark field extraction into per-second rollups.

Why tshark and not scapy: tshark is a mature dissector that already
understands radiotap, every 802.11 subtype, and the vendor quirks. Parsing
radiotap by hand in Python would be slower, buggier, and would teach you
nothing you actually need. Buy the commodity; build the differentiator.

Why `-T fields` and not `-T json`: JSON output for a million frames is
enormous and slow to parse. Tab-separated fields stream, and we only ask for
the twelve fields we actually use.
"""

from __future__ import annotations

import hashlib
import shutil
import statistics
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from wd_probe.contracts import (
    CaptureKind,
    CaptureSession,
    Envelope,
    SampleType,
    WifiFrameStat,
    WifiStationStat,
)
from wd_probe.reduce.base import ReducerError

# ─────────────────────────────────────────────────────────────────────────────
# 802.11 frame type / subtype constants
# ─────────────────────────────────────────────────────────────────────────────
TYPE_MGMT, TYPE_CTRL, TYPE_DATA = 0, 1, 2
SUB_PROBE_REQ, SUB_BEACON, SUB_DISASSOC, SUB_DEAUTH = 4, 8, 10, 12

# The exact fields we pull. Order matters — it defines the column layout.
FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "wlan.fc.type",
    "wlan.fc.subtype",
    "wlan.fc.retry",
    "wlan.ta",
    "wlan.bssid",
    "radiotap.dbm_antsignal",
    "radiotap.channel.freq",
    "wlan_radio.duration",
]

# A genuinely locked capture reports ONE frequency. Two is tolerable — some
# drivers report primary and centre frequency on 40 MHz. More than that and
# the radio moved, whatever the operator believed they configured.
MAX_FREQS_FOR_LOCKED = 2


def freq_to_channel(freq_mhz: int) -> int | None:
    """Map a centre frequency to a channel number."""
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2412) // 5 + 1
    if freq_mhz == 2484:
        return 14
    if 5160 <= freq_mhz <= 5885:
        return (freq_mhz - 5000) // 5
    if 5955 <= freq_mhz <= 7115:          # 6 GHz / Wi-Fi 6E
        return (freq_mhz - 5955) // 5 + 1
    return None


def _hash_mac(mac: str, salt: str) -> str:
    """Pseudonymise a station MAC.

    You are capturing third parties' devices. Hashing preserves every
    correlation you need (same device across time, across capture points)
    while removing the identifier itself. Default-on, opt-out — privacy
    defaults should never require the operator to remember something.
    """
    return hashlib.sha256(f"{salt}{mac.lower()}".encode()).hexdigest()[:16]


def _to_int(raw: str) -> int | None:
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


def _to_bool(raw: str) -> bool:
    return raw.strip().lower() in {"1", "true"}


class _Bucket:
    """Mutable accumulator for one second of frames."""

    __slots__ = (
        "frames", "retry", "mgmt", "ctrl", "data", "unparseable", "beacon",
        "deauth", "disassoc", "probe_req", "airtime_us", "bytes_total",
        "rssis", "stations", "freqs",
    )

    def __init__(self) -> None:
        self.frames = 0
        self.retry = 0
        self.mgmt = 0
        self.ctrl = 0
        self.data = 0
        self.unparseable = 0
        self.beacon = 0
        self.deauth = 0
        self.disassoc = 0
        self.probe_req = 0
        self.airtime_us = 0
        self.bytes_total = 0
        self.rssis: list[int] = []
        self.stations: set[str] = set()
        self.freqs: list[int] = []


class _StationBucket:
    __slots__ = ("frames", "retry", "bytes_total", "airtime_us", "rssis")

    def __init__(self) -> None:
        self.frames = 0
        self.retry = 0
        self.bytes_total = 0
        self.airtime_us = 0
        self.rssis: list[int] = []


class WifiTsharkReducer:
    """Reduce an 802.11 pcap into per-second and per-station Envelopes."""

    name = "wifi_tshark"

    def __init__(self, mac_salt: str = "wd-probe-lab", tshark: str | None = None) -> None:
        self.mac_salt = mac_salt
        self.tshark = tshark or shutil.which("tshark") or "tshark"

    def supports(self, session: CaptureSession) -> bool:
        return session.capture_point.kind is CaptureKind.WIRELESS_MONITOR

    # ── internal ────────────────────────────────────────────────────────────

    def _run_tshark(self, pcap: Path) -> Iterator[list[str]]:
        cmd = [self.tshark, "-r", str(pcap), "-T", "fields",
               "-E", "separator=/t", "-E", "occurrence=f"]
        for f in FIELDS:
            cmd += ["-e", f]

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\n")
            if not line:
                continue
            cols = line.split("\t")
            # pad short rows so downstream indexing is always safe
            if len(cols) < len(FIELDS):
                cols += [""] * (len(FIELDS) - len(cols))
            yield cols

        proc.wait()
        if proc.returncode != 0:
            err = proc.stderr.read() if proc.stderr else ""
            raise ReducerError(f"tshark exited {proc.returncode}: {err.strip()[:400]}")

    # ── public ──────────────────────────────────────────────────────────────

    def reduce(self, pcap: Path, session: CaptureSession) -> Iterator[Envelope]:
        if not pcap.exists():
            raise ReducerError(f"pcap not found: {pcap}")

        cp = session.capture_point
        declared_valid = cp.rate_metrics_valid

        buckets: dict[int, _Bucket] = defaultdict(_Bucket)
        stations: dict[str, _StationBucket] = defaultdict(_StationBucket)
        observed_freqs: set[int] = set()
        total_frames = 0
        total_bytes = 0

        for cols in self._run_tshark(pcap):
            (t_raw, len_raw, type_raw, sub_raw, retry_raw,
             ta_raw, _bssid_raw, rssi_raw, freq_raw, dur_raw) = cols[:10]

            try:
                ts = float(t_raw)
            except ValueError:
                continue

            sec = int(ts)
            b = buckets[sec]

            ftype = _to_int(type_raw)
            fsub = _to_int(sub_raw)
            flen = _to_int(len_raw) or 0
            rssi = _to_int(rssi_raw)
            freq = _to_int(freq_raw)
            dur = _to_int(dur_raw) or 0
            is_retry = _to_bool(retry_raw)

            b.frames += 1
            b.bytes_total += flen
            b.airtime_us += dur
            total_frames += 1
            total_bytes += flen

            if is_retry:
                b.retry += 1
            if rssi is not None:
                b.rssis.append(rssi)
            if freq is not None:
                b.freqs.append(freq)
                observed_freqs.add(freq)

            if ftype == TYPE_MGMT:
                b.mgmt += 1
                if fsub == SUB_BEACON:
                    b.beacon += 1
                elif fsub == SUB_DEAUTH:
                    b.deauth += 1
                elif fsub == SUB_DISASSOC:
                    b.disassoc += 1
                elif fsub == SUB_PROBE_REQ:
                    b.probe_req += 1
            elif ftype == TYPE_CTRL:
                b.ctrl += 1
            elif ftype == TYPE_DATA:
                b.data += 1
            else:
                # no parseable type — malformed/truncated radiotap
                b.unparseable += 1

            if ta_raw:
                h = _hash_mac(ta_raw, self.mac_salt)
                b.stations.add(h)
                s = stations[h]
                s.frames += 1
                s.bytes_total += flen
                s.airtime_us += dur
                if is_retry:
                    s.retry += 1
                if rssi is not None:
                    s.rssis.append(rssi)

        if total_frames == 0:
            raise ReducerError(
                f"{pcap.name} contained no readable 802.11 frames. "
                "Check the adapter was really in monitor mode and the link type "
                "is radiotap (LINKTYPE 127)."
            )

        # ── detect hopping from the DATA, overriding what was declared ──────
        #
        # ADR-19 suppresses rate metrics on hopping captures. Until now that
        # guard fired only when a human remembered to pass --hopping, which
        # means it was not a guard at all — it was a comment. The first real
        # capture arrived declared as "locked" and had visited 29 frequencies
        # across two bands, and the reducer cheerfully published a retry
        # percentage computed over a random sample of time.
        #
        # The radio's actual behaviour is right there in every radiotap
        # header. Measure it. Never take the operator's word for a fact the
        # data already contains.
        detected_hopping = len(observed_freqs) > MAX_FREQS_FOR_LOCKED
        valid = declared_valid and not detected_hopping

        suppression_reason: str | None = None
        if detected_hopping and declared_valid:
            suppression_reason = (
                f"declared locked, but the radio visited {len(observed_freqs)} "
                f"frequencies during the capture — rate metrics suppressed"
            )
        elif not declared_valid:
            suppression_reason = "capture point declared hopping mode"

        # ── emit per-second frame stats ─────────────────────────────────────
        for sec in sorted(buckets):
            b = buckets[sec]
            freq = max(set(b.freqs), key=b.freqs.count) if b.freqs else None
            # On a hopping capture the modal frequency of a one-second bucket
            # is an artefact of the hop schedule, not a property of the link.
            # Reporting it as "the channel" invents a fact.
            report_channel = None
            if not detected_hopping:
                report_channel = (
                    freq_to_channel(freq) if freq
                    else (cp.wireless.channel if cp.wireless else None)
                )
            stat = WifiFrameStat(
                channel=report_channel,
                freq_mhz=freq,
                frames_total=b.frames,
                frames_retry=b.retry,
                frames_mgmt=b.mgmt,
                frames_ctrl=b.ctrl,
                frames_data=b.data,
                frames_unparseable=b.unparseable,
                beacon_count=b.beacon,
                deauth_count=b.deauth,
                disassoc_count=b.disassoc,
                probe_req_count=b.probe_req,
                airtime_us=b.airtime_us,
                bytes_total=b.bytes_total,
                distinct_stations=len(b.stations),
                rssi_min_dbm=min(b.rssis) if b.rssis else None,
                rssi_max_dbm=max(b.rssis) if b.rssis else None,
                rssi_mean_dbm=round(statistics.fmean(b.rssis), 1) if b.rssis else None,
                rate_metrics_valid=valid,
            )
            yield Envelope(
                session_id=session.id,
                capture_point_id=cp.id,
                sample_type=SampleType.WIFI_FRAME_STAT,
                ts=datetime.fromtimestamp(sec, tz=timezone.utc),
                payload=stat.model_dump(),
            )

        # ── emit per-station rollups for the whole session ──────────────────
        window_ts = datetime.fromtimestamp(min(buckets), tz=timezone.utc)
        for mac_hash, s in sorted(stations.items(), key=lambda kv: -kv[1].frames):
            st = WifiStationStat(
                station_mac_hash=mac_hash,
                frames=s.frames,
                frames_retry=s.retry,
                bytes_total=s.bytes_total,
                airtime_us=s.airtime_us,
                rssi_min_dbm=min(s.rssis) if s.rssis else None,
                rssi_max_dbm=max(s.rssis) if s.rssis else None,
                rate_metrics_valid=valid,
            )
            yield Envelope(
                session_id=session.id,
                capture_point_id=cp.id,
                sample_type=SampleType.WIFI_STATION_STAT,
                ts=window_ts,
                payload=st.model_dump(),
            )

        # ── session quality + what we discovered about the capture itself ───
        session.quality.packets_captured = total_frames
        session.quality.bytes_captured = total_bytes
        # ADR-29 — the verdict goes on the session, not only into a sample.
        session.quality.hopping_detected = detected_hopping
        session.quality.effective_rate_metrics_valid = valid
        session.quality.suppression_reason = suppression_reason
        session.quality.distinct_freqs = len(observed_freqs)
        session.quality.frames_unparseable = sum(x.unparseable for x in buckets.values())
        payload = session.quality.model_dump()
        payload.update({
            "observed_freqs_mhz": sorted(observed_freqs),
            "distinct_freqs": len(observed_freqs),
            "frames_unparseable": sum(x.unparseable for x in buckets.values()),
            "declared_rate_metrics_valid": declared_valid,
            "effective_rate_metrics_valid": valid,
            "hopping_detected_from_data": detected_hopping,
            "suppression_reason": suppression_reason,
        })
        yield Envelope(
            session_id=session.id,
            capture_point_id=cp.id,
            sample_type=SampleType.SESSION_QUALITY,
            ts=window_ts,
            payload=payload,
        )

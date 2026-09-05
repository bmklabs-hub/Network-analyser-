"""
Shared contracts for every capture domain.

╔══════════════════════════════════════════════════════════════════════════╗
║  READ THIS FIRST — this file is the whole point of building wireless     ║
║  before wired.                                                            ║
║                                                                           ║
║  Nothing in here mentions 802.11, and nothing in here mentions Ethernet.  ║
║  A wireless collector and a wired collector both produce `Envelope`       ║
║  objects and both describe themselves with a `CapturePoint`.              ║
║                                                                           ║
║  That is the seam. Because it exists, adding the wired collector later    ║
║  is *writing a new module*, not *refactoring the old one*. If you skip    ║
║  this file and let the wireless code define the shapes, then the day the  ║
║  server arrives you will find 802.11 assumptions baked into your spool,   ║
║  your API and your database — and you will rewrite all three.             ║
║                                                                           ║
║  Cost of building this now: about an hour.                                ║
║  Cost of building it later: about three weeks.                            ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class CaptureKind(str, Enum):
    """Where a capture point sits in the world.

    Note that these are *observation points*, not technologies. The analysis
    engine reasons about what a point could physically see, and that depends
    on how it is attached, not on what card is in the machine.
    """
    WIRELESS_MONITOR = "wireless_monitor"
    SPAN = "span"
    RSPAN = "rspan"
    ERSPAN = "erspan"
    TAP = "tap"
    INLINE = "inline"


class WirelessMode(str, Enum):
    """Locked vs hopping. This distinction is not cosmetic.

    LOCKED  — the radio stays on one channel for the whole session. Frame
              counts are complete for that channel, so rate metrics
              (retry %, airtime %) are meaningful.

    HOPPING — the radio cycles channels. You see roughly
              (dwell_ms / cycle_ms) of any given channel, so every rate
              metric has a random denominator and is MEANINGLESS.

    The reducer refuses to mark rate metrics valid on hopping captures.
    """
    LOCKED = "locked"
    HOPPING = "hopping"


class SampleType(str, Enum):
    """Every kind of record the probe can produce, from any domain.

    Wireless types exist today. Wired types are declared now, deliberately,
    even though nothing emits them yet — declaring them proves the envelope
    is domain-neutral and stops the wireless work from quietly claiming the
    whole namespace.
    """
    # wireless — implemented
    WIFI_FRAME_STAT = "wifi_frame_stat"
    WIFI_STATION_STAT = "wifi_station_stat"
    WIFI_EVENT = "wifi_event"

    # wired — declared, not yet implemented (Zeek)
    CONN = "conn"
    DNS = "dns"
    SSL = "ssl"
    DHCP = "dhcp"
    WEIRD = "weird"

    # domain-neutral
    SESSION_QUALITY = "session_quality"


# ─────────────────────────────────────────────────────────────────────────────
# Capture point — "what could this observation point actually see?"
# ─────────────────────────────────────────────────────────────────────────────

class WirelessConfig(BaseModel):
    adapter: str
    driver: str | None = None
    chipset: str | None = None
    mode: WirelessMode = WirelessMode.LOCKED
    channel: int | None = None
    width_mhz: int | None = None
    band: str | None = None            # "2.4" | "5" | "6"
    hop_set: list[int] | None = None   # channels, when mode is HOPPING
    dwell_ms: int | None = None
    location_note: str | None = None


class WiredConfig(BaseModel):
    """Not used yet. Present so the shape of the seam is visible."""
    interface: str
    link_speed_mbps: int | None = None
    direction: str = "both"                  # rx | tx | both
    vlans_expected: list[int] | None = None
    mirror_source: str | None = None
    oversubscription_ratio: float | None = None
    sees_intra_switch_traffic: bool = False


class CapturePoint(BaseModel):
    """An observation point, plus an honest statement of its blind spots.

    Every finding is scoped to the capture point that produced it. A tool
    that cannot say what it was unable to see will eventually report a clean
    bill of health for a network it never observed.
    """
    id: str = Field(default_factory=lambda: f"cp-{uuid.uuid4().hex[:8]}")
    kind: CaptureKind
    site_id: str = "lab"
    description: str = ""
    wireless: WirelessConfig | None = None
    wired: WiredConfig | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rate_metrics_valid(self) -> bool:
        """Can rate-based metrics (retry %, airtime %) be trusted from here?

        False for hopping wireless captures, because the denominator is a
        random sample of time rather than a complete observation.
        """
        if self.kind is CaptureKind.WIRELESS_MONITOR and self.wireless:
            return self.wireless.mode is WirelessMode.LOCKED
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Capture session — one run at one capture point, plus its honesty record
# ─────────────────────────────────────────────────────────────────────────────

class CaptureQuality(BaseModel):
    """Drop accounting. The most under-appreciated table in the system.

    A capture that lost 30% of its packets will produce analysis that is
    confidently, plausibly wrong — TCP flows will look retransmit-heavy,
    retry rates will look low, conversations will look one-sided. Recording
    loss and refusing to analyse past a threshold is what separates an
    instrument from a script that prints numbers.
    """
    packets_captured: int = 0
    bytes_captured: int = 0
    drops_kernel: int = 0          # dumpcap buffer overrun — tune -B
    drops_interface: int = 0       # NIC ring overrun — tune the driver
    drops_estimated: int = 0       # inferred (e.g. SPAN oversubscription)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_drops(self) -> int:
        return self.drops_kernel + self.drops_interface + self.drops_estimated

    @computed_field  # type: ignore[prop-decorator]
    @property
    def loss_pct(self) -> float:
        offered = self.packets_captured + self.total_drops
        return 0.0 if offered == 0 else round(100.0 * self.total_drops / offered, 3)

    def is_analyzable(self, max_loss_pct: float = 1.0) -> bool:
        return self.loss_pct <= max_loss_pct


class CaptureSession(BaseModel):
    id: str = Field(default_factory=lambda: f"sess-{uuid.uuid4().hex[:12]}")
    capture_point: CapturePoint
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    pcap_path: str | None = None
    quality: CaptureQuality = Field(default_factory=CaptureQuality)
    probe_version: str = "0.1.0"
    clock_source: str = "system"
    clock_offset_ms: float | None = None
    notes: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def duration_s(self) -> float | None:
        if self.ended_at is None:
            return None
        return (self.ended_at - self.started_at).total_seconds()


# ─────────────────────────────────────────────────────────────────────────────
# The envelope — the single shape that crosses every boundary
# ─────────────────────────────────────────────────────────────────────────────

class Envelope(BaseModel):
    """One reduced observation, ready to spool and upload.

    Design notes worth internalising:

    * `sample_uuid` is generated by the PROBE, not the server. That is what
      makes upload idempotent: a retried batch upserts harmlessly. Never let
      the server mint IDs for data it did not create.

    * `ts` is always UTC. Correlating a wireless capture against a wired one
      is timestamp matching; a single naive local-time datetime anywhere in
      this pipeline will silently corrupt that.

    * `payload` is a plain dict, not a typed union. The envelope is stable
      infrastructure; payload shapes churn as you learn. Freezing the
      envelope and leaving the payload flexible is what lets you add the
      Zeek types later without touching the spool, the uploader or the API.
    """
    sample_uuid: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    capture_point_id: str
    sample_type: SampleType
    ts: datetime
    payload: dict[str, Any]

    def model_post_init(self, __context: Any) -> None:
        if self.ts.tzinfo is None:
            raise ValueError(
                f"Envelope.ts must be timezone-aware UTC, got naive {self.ts!r}. "
                "Naive timestamps break cross-domain correlation."
            )


# ─────────────────────────────────────────────────────────────────────────────
# Typed payload helpers — convenience, not enforcement
# ─────────────────────────────────────────────────────────────────────────────

class WifiFrameStat(BaseModel):
    """Per-second 802.11 rollup for one capture point."""
    channel: int | None = None
    freq_mhz: int | None = None

    frames_total: int = 0
    frames_retry: int = 0
    frames_mgmt: int = 0
    frames_ctrl: int = 0
    frames_data: int = 0
    # Frames tshark could not assign a type to — truncated radiotap, corrupt
    # headers, frames the dissector rejects. Real captures always contain a
    # few. Counting them explicitly keeps
    #     mgmt + ctrl + data + unparseable == frames_total
    # true, so a reader summing the columns is never quietly short. A rising
    # share of these is itself a signal: bad RF, or a driver mangling headers.
    frames_unparseable: int = 0
    beacon_count: int = 0
    deauth_count: int = 0
    disassoc_count: int = 0
    probe_req_count: int = 0

    airtime_us: int = 0
    bytes_total: int = 0
    distinct_stations: int = 0

    rssi_min_dbm: int | None = None
    rssi_max_dbm: int | None = None
    rssi_mean_dbm: float | None = None

    # Set from CapturePoint.rate_metrics_valid. Travels WITH the data so a
    # consumer can never lose the caveat by reading the row in isolation.
    rate_metrics_valid: bool = True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def retry_pct(self) -> float | None:
        if not self.rate_metrics_valid or self.frames_total == 0:
            return None
        return round(100.0 * self.frames_retry / self.frames_total, 2)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def airtime_busy_pct(self) -> float | None:
        if not self.rate_metrics_valid:
            return None
        return round(min(100.0, self.airtime_us / 10_000.0), 2)  # us in 1 s


class WifiStationStat(BaseModel):
    """Per-transmitter rollup within one window."""
    station_mac_hash: str
    frames: int = 0
    frames_retry: int = 0
    bytes_total: int = 0
    airtime_us: int = 0
    rssi_min_dbm: int | None = None
    rssi_max_dbm: int | None = None
    rate_metrics_valid: bool = True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def retry_pct(self) -> float | None:
        if not self.rate_metrics_valid or self.frames == 0:
            return None
        return round(100.0 * self.frames_retry / self.frames, 2)

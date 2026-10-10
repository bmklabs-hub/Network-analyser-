"""The wire contract, as the SERVER sees it.  ADR-28.

Yes, this duplicates `wd_probe.contracts.Envelope`. Deliberately.

Three ways existed to share the contract:

  ❌ Server imports wd_probe   — wrong dependency direction. The trusted side
                                 must not depend on, or fail to build without,
                                 the untrusted side.
  ⏳ A third wd-common package  — right eventually; premature for six fields.
  ✅ Duplicate + parity test    — chosen.

This is only safe because the envelope is FROZEN (ADR-21): all churn lives in
`payload`, an untyped dict on both sides. Duplicating something stable is
cheap; duplicating something that changes weekly is a bug factory.

The guard is `tests/test_parity.py`. If it fails for a legitimate reason,
that is the signal to extract the shared package — not to delete the test.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class SampleType(str, Enum):
    WIFI_FRAME_STAT = "wifi_frame_stat"
    WIFI_STATION_STAT = "wifi_station_stat"
    WIFI_EVENT = "wifi_event"
    CONN = "conn"
    DNS = "dns"
    SSL = "ssl"
    DHCP = "dhcp"
    WEIRD = "weird"
    SESSION_QUALITY = "session_quality"


class Envelope(BaseModel):
    sample_uuid: str = Field(min_length=8, max_length=64)
    session_id: str
    capture_point_id: str
    sample_type: SampleType
    ts: datetime
    payload: dict[str, Any]

    @field_validator("ts")
    @classmethod
    def _must_be_aware(cls, v: datetime) -> datetime:
        # The server re-checks what the probe already checks. Never assume the
        # other side of a network boundary obeyed the contract.
        if v.tzinfo is None:
            raise ValueError("ts must be timezone-aware (UTC)")
        return v


class SessionIn(BaseModel):
    """A capture session as uploaded. capture_point and quality stay dicts:
    the server stores them, and reads only the few fields it displays."""
    id: str
    started_at: datetime
    ended_at: datetime | None = None
    capture_point: dict[str, Any]
    quality: dict[str, Any] = Field(default_factory=dict)
    pcap_path: str | None = None
    probe_version: str | None = None
    notes: str = ""


class IngestBatch(BaseModel):
    probe_version: str | None = None
    sessions: list[SessionIn] = Field(default_factory=list)
    samples: list[Envelope] = Field(default_factory=list, max_length=5000)


class IngestResult(BaseModel):
    accepted: list[str]          # every sample UUID the server now holds
    inserted: int                # new this time
    duplicates: int              # already held — a retried batch, harmless
    sessions_upserted: int

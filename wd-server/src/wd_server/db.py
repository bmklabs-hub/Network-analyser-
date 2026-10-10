"""Server storage — SQLite for Phase 2.  ADR-05.

The plan is Postgres + Timescale with Row-Level Security (ADR-12) before the
first paying customer. SQLite is the deliberate stepping stone, and the
schema is written so that move is mechanical:

  * EVERY table carries `tenant_id` from day one, even though it is always
    "default" today.
  * EVERY primary key includes `tenant_id`. Two customers' probes could, in
    principle, produce the same UUID or session id. Scoping the key by tenant
    means one customer's data can never collide with — or be silently
    "deduplicated" into — another's.
  * EVERY query in this file filters by tenant. When RLS arrives it becomes a
    second, database-enforced lock on a door that is already locked.

Idempotency is the same trick as the probe spool: `INSERT OR IGNORE` on the
probe-generated UUID. A retried batch upserts harmlessly.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wd_server.schemas import Envelope, SessionIn

SCHEMA = """
CREATE TABLE IF NOT EXISTS capture_session (
    tenant_id        TEXT NOT NULL,
    id               TEXT NOT NULL,
    probe_id         TEXT NOT NULL,
    started_at       TEXT NOT NULL,
    ended_at         TEXT,
    capture_point    TEXT NOT NULL,     -- JSON, as uploaded
    quality          TEXT NOT NULL,     -- JSON, includes the ADR-29 verdict
    probe_version    TEXT,
    notes            TEXT,
    first_seen_at    TEXT NOT NULL,
    last_updated_at  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS sample (
    tenant_id        TEXT NOT NULL,
    sample_uuid      TEXT NOT NULL,
    session_id       TEXT NOT NULL,
    capture_point_id TEXT NOT NULL,
    sample_type      TEXT NOT NULL,
    ts               TEXT NOT NULL,
    payload          TEXT NOT NULL,     -- JSON
    received_at      TEXT NOT NULL,
    probe_id         TEXT NOT NULL,
    PRIMARY KEY (tenant_id, sample_uuid)
);

CREATE INDEX IF NOT EXISTS idx_sample_session
    ON sample(tenant_id, session_id, sample_type, ts);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # FastAPI runs sync endpoints in a thread pool, so one connection is
        # shared across threads behind a lock. Fine at Phase 2 volumes; the
        # Postgres move replaces this with a proper connection pool.
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ── ingest ──────────────────────────────────────────────────────────────

    def ingest(
        self, tenant_id: str, probe_id: str,
        sessions: list[SessionIn], samples: list[Envelope],
    ) -> tuple[int, int]:
        """Store one batch atomically. Returns (inserted, duplicates).

        Atomic matters: if the server dies halfway, the probe receives no
        acknowledgement, retries, and the whole batch lands again. Partial
        writes plus a retry would still be correct thanks to idempotency —
        but "correct by two mechanisms" is better than by one.
        """
        now = _now()
        with self._lock, self.conn:
            for s in sessions:
                self.conn.execute(
                    """INSERT INTO capture_session
                         (tenant_id, id, probe_id, started_at, ended_at, capture_point,
                          quality, probe_version, notes, first_seen_at, last_updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(tenant_id, id) DO UPDATE SET
                          ended_at        = excluded.ended_at,
                          quality         = excluded.quality,
                          notes           = excluded.notes,
                          last_updated_at = excluded.last_updated_at""",
                    (
                        tenant_id, s.id, probe_id,
                        s.started_at.isoformat(),
                        s.ended_at.isoformat() if s.ended_at else None,
                        json.dumps(s.capture_point), json.dumps(s.quality),
                        s.probe_version, s.notes, now, now,
                    ),
                )
            before = self.conn.total_changes
            self.conn.executemany(
                """INSERT OR IGNORE INTO sample
                     (tenant_id, sample_uuid, session_id, capture_point_id,
                      sample_type, ts, payload, received_at, probe_id)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                [
                    (tenant_id, e.sample_uuid, e.session_id, e.capture_point_id,
                     e.sample_type.value, e.ts.isoformat(),
                     json.dumps(e.payload, default=str), now, probe_id)
                    for e in samples
                ],
            )
            inserted = self.conn.total_changes - before
        return inserted, len(samples) - inserted

    def known_session_ids(self, tenant_id: str, ids: set[str]) -> set[str]:
        if not ids:
            return set()
        marks = ",".join("?" * len(ids))
        with self._lock:
            rows = self.conn.execute(
                f"SELECT id FROM capture_session WHERE tenant_id=? AND id IN ({marks})",
                (tenant_id, *ids),
            ).fetchall()
        return {r["id"] for r in rows}

    # ── reads (for the web pages) ───────────────────────────────────────────

    def list_sessions(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """SELECT s.*, (SELECT COUNT(*) FROM sample x
                                WHERE x.tenant_id = s.tenant_id
                                  AND x.session_id = s.id) AS sample_count
                   FROM capture_session s
                   WHERE s.tenant_id = ?
                   ORDER BY s.started_at DESC LIMIT ?""",
                (tenant_id, limit),
            ).fetchall()
        return [_session_view(r) for r in rows]

    def get_session(self, tenant_id: str, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            r = self.conn.execute(
                """SELECT s.*, (SELECT COUNT(*) FROM sample x
                                WHERE x.tenant_id = s.tenant_id
                                  AND x.session_id = s.id) AS sample_count
                   FROM capture_session s WHERE s.tenant_id = ? AND s.id = ?""",
                (tenant_id, session_id),
            ).fetchone()
        return _session_view(r) if r else None

    def samples(
        self, tenant_id: str, session_id: str, sample_type: str, limit: int = 2000,
    ) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """SELECT ts, payload FROM sample
                   WHERE tenant_id=? AND session_id=? AND sample_type=?
                   ORDER BY ts LIMIT ?""",
                (tenant_id, session_id, sample_type, limit),
            ).fetchall()
        return [{"ts": r["ts"], **json.loads(r["payload"])} for r in rows]

    def close(self) -> None:
        self.conn.close()


def _session_view(r: sqlite3.Row) -> dict[str, Any]:
    """Shape a session row for display, deriving the trust verdict.

    The verdict is read from the SESSION's quality (ADR-29). `None` means the
    capture was never reduced — shown as "unknown", never as "valid".
    """
    cp = json.loads(r["capture_point"])
    q = json.loads(r["quality"])
    w = cp.get("wireless") or {}
    declared_valid = cp.get("rate_metrics_valid", True)
    effective = q.get("effective_rate_metrics_valid")
    loss = q.get("loss_pct", 0.0) or 0.0

    if effective is None:
        verdict, verdict_class = "not reduced", "warn"
    elif not effective:
        verdict, verdict_class = "rate metrics suppressed", "bad"
    elif loss > 1.0:
        verdict, verdict_class = f"loss {loss}% — unreliable", "bad"
    else:
        verdict, verdict_class = "trustworthy", "good"

    return {
        "id": r["id"],
        "probe_id": r["probe_id"],
        "started_at": r["started_at"],
        "ended_at": r["ended_at"],
        "kind": cp.get("kind"),
        "site_id": cp.get("site_id"),
        "description": cp.get("description", ""),
        "declared_mode": w.get("mode"),
        "declared_channel": w.get("channel"),
        "declared_valid": declared_valid,
        "effective_valid": effective,
        "hopping_detected": q.get("hopping_detected", False),
        "overridden": bool(declared_valid and effective is False),
        "suppression_reason": q.get("suppression_reason"),
        "distinct_freqs": q.get("distinct_freqs"),
        "frames": q.get("packets_captured", 0),
        "frames_unparseable": q.get("frames_unparseable", 0),
        "loss_pct": loss,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "sample_count": r["sample_count"],
        "last_updated_at": r["last_updated_at"],
    }

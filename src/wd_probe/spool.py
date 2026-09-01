"""Durable local spool — SQLite.

Design v0.3 §4.2 stage 5, and the reason requirement N1 exists: the probe must
keep working when the network is broken, because a broken network is the
entire premise of the product.

The pattern is the **outbox**: write locally, mark sent on acknowledgement,
prune later. You already know it as store-and-forward.

Three properties that matter, none of them accidental:

  * `sample_uuid` is a PRIMARY KEY, so re-inserting the same sample is a
    no-op. Retrying an upload batch can never duplicate data.
  * `sent_at` is nullable. NULL means "still owed to the server". The upload
    queue is just `WHERE sent_at IS NULL` — no separate queue to keep in sync.
  * Rows survive `kill -9`, a flat battery, and a yanked power cable. A
    Python list does not.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from wd_probe.contracts import CaptureSession, Envelope, SampleType

SCHEMA = """
CREATE TABLE IF NOT EXISTS session (
    id              TEXT PRIMARY KEY,
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    capture_point   TEXT NOT NULL,      -- JSON
    quality         TEXT NOT NULL,      -- JSON
    pcap_path       TEXT,
    probe_version   TEXT,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS sample (
    sample_uuid      TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL,
    capture_point_id TEXT NOT NULL,
    sample_type      TEXT NOT NULL,
    ts               TEXT NOT NULL,
    payload          TEXT NOT NULL,     -- JSON
    created_at       TEXT NOT NULL,
    sent_at          TEXT,
    FOREIGN KEY (session_id) REFERENCES session(id)
);

CREATE INDEX IF NOT EXISTS idx_sample_unsent  ON sample(sent_at) WHERE sent_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sample_session ON sample(session_id, sample_type, ts);
"""


class Spool:
    def __init__(self, path: Path | str = "~/.wd-probe/spool.db") -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        # WAL lets the reducer write while the CLI reads, without blocking.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ── sessions ────────────────────────────────────────────────────────────

    def save_session(self, s: CaptureSession) -> None:
        self.conn.execute(
            """INSERT INTO session (id, started_at, ended_at, capture_point,
                                    quality, pcap_path, probe_version, notes)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                   ended_at=excluded.ended_at,
                   quality=excluded.quality,
                   pcap_path=excluded.pcap_path,
                   notes=excluded.notes""",
            (
                s.id,
                s.started_at.isoformat(),
                s.ended_at.isoformat() if s.ended_at else None,
                s.capture_point.model_dump_json(),
                s.quality.model_dump_json(),
                s.pcap_path,
                s.probe_version,
                s.notes,
            ),
        )
        self.conn.commit()

    def list_sessions(self, limit: int = 20) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM session ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()

    def get_session(self, session_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM session WHERE id = ?", (session_id,)
        ).fetchone()

    # ── samples ─────────────────────────────────────────────────────────────

    def add_many(self, envelopes: Iterable[Envelope], batch: int = 500) -> int:
        """Insert envelopes. Returns the number newly stored (duplicates ignored)."""
        now = datetime.now(timezone.utc).isoformat()
        inserted = 0
        buf: list[tuple] = []

        def flush() -> int:
            if not buf:
                return 0
            before = self.conn.total_changes
            self.conn.executemany(
                """INSERT OR IGNORE INTO sample
                   (sample_uuid, session_id, capture_point_id, sample_type,
                    ts, payload, created_at, sent_at)
                   VALUES (?,?,?,?,?,?,?,NULL)""",
                buf,
            )
            self.conn.commit()
            n = self.conn.total_changes - before
            buf.clear()
            return n

        for e in envelopes:
            buf.append((
                e.sample_uuid, e.session_id, e.capture_point_id,
                e.sample_type.value, e.ts.isoformat(),
                json.dumps(e.payload, default=str), now,
            ))
            if len(buf) >= batch:
                inserted += flush()
        inserted += flush()
        return inserted

    def unsent(self, limit: int = 1000) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM sample WHERE sent_at IS NULL ORDER BY ts LIMIT ?", (limit,)
        ).fetchall()

    def mark_sent(self, uuids: Iterable[str]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.executemany(
            "UPDATE sample SET sent_at = ? WHERE sample_uuid = ?",
            [(now, u) for u in uuids],
        )
        self.conn.commit()

    def samples(
        self, session_id: str, sample_type: SampleType | None = None
    ) -> Iterator[sqlite3.Row]:
        if sample_type:
            q = ("SELECT * FROM sample WHERE session_id=? AND sample_type=? ORDER BY ts",
                 (session_id, sample_type.value))
        else:
            q = ("SELECT * FROM sample WHERE session_id=? ORDER BY ts", (session_id,))
        yield from self.conn.execute(*q)

    def stats(self) -> dict[str, int]:
        row = self.conn.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN sent_at IS NULL THEN 1 ELSE 0 END) AS pending
               FROM sample"""
        ).fetchone()
        sess = self.conn.execute("SELECT COUNT(*) AS n FROM session").fetchone()
        return {
            "sessions": sess["n"] or 0,
            "samples": row["total"] or 0,
            "pending_upload": row["pending"] or 0,
        }

    def close(self) -> None:
        self.conn.close()

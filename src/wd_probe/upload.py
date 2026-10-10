"""Uploader — drains the spool to wd-server.  Design v0.3 §4.2 stage 5, ADR-08.

How it works, in one breath:

    take up to N unsent samples from the spool
      → attach the sessions they belong to
      → POST them as ONE JSON batch over HTTPS
      → server answers with the sample UUIDs it now holds
      → mark exactly those as sent
      → repeat until the spool is empty

Why it is shaped like this:

  * **Stateless batches, not a socket.** The network is broken — that is the
    premise of the product. A persistent connection turns the uploader into a
    reconnection state machine; a batch POST either worked or it didn't.

  * **Idempotent by construction.** Every sample carries a UUID the PROBE
    generated, and the server upserts on it. If the reply is lost after the
    server stored the batch, the retry is harmless. That is why it is safe to
    retry blindly.

  * **Only mark what the server confirmed.** We mark the UUIDs the server
    *returned*, not the ones we *sent*. If those differ, something is wrong,
    and the difference stays in the spool to be retried rather than vanishing.

  * **Retry what is temporary, stop on what is permanent.** A timeout or a
    5xx might fix itself — back off and retry. A 401 (bad token) or 422 (we
    sent something the server rejects) will fail identically forever, so
    retrying just hammers the server. Stop and tell the human.

Standard library only (`urllib`), so the probe gains no new dependency.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

from wd_probe import __version__
from wd_probe.spool import Spool

PERMANENT_STATUSES = {400, 401, 403, 404, 413, 422}


class UploadError(RuntimeError):
    """Raised for failures that retrying will not fix."""


@dataclass
class UploadResult:
    batches: int = 0
    samples_sent: int = 0
    duplicates: int = 0
    retries: int = 0
    errors: list[str] = field(default_factory=list)


class Uploader:
    def __init__(
        self,
        spool: Spool,
        server_url: str,
        token: str,
        batch_size: int = 500,
        max_retries: int = 5,
        timeout_s: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,   # injectable for tests
    ) -> None:
        if not token:
            raise UploadError("No probe token. Set WD_PROBE_TOKEN or pass --token.")
        self.spool = spool
        self.url = server_url.rstrip("/") + "/api/v1/ingest"
        self.token = token
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.timeout_s = timeout_s
        self.sleep = sleep

    # ── public ──────────────────────────────────────────────────────────────

    def run(self) -> UploadResult:
        result = UploadResult()
        while True:
            rows = self.spool.unsent(limit=self.batch_size)
            if not rows:
                return result
            body = self._build_batch(rows)
            reply = self._post_with_retry(body, result)
            accepted = reply.get("accepted", [])
            self.spool.mark_sent(accepted)
            result.batches += 1
            result.samples_sent += len(accepted)
            result.duplicates += int(reply.get("duplicates", 0))
            if len(accepted) < len(rows):
                # The server stored fewer than we sent. Don't loop forever on
                # the same rows — surface it and stop.
                missing = len(rows) - len(accepted)
                result.errors.append(
                    f"server acknowledged {len(accepted)} of {len(rows)} samples; "
                    f"{missing} remain in the spool"
                )
                return result

    # ── internals ───────────────────────────────────────────────────────────

    def _build_batch(self, rows: list) -> dict:
        session_ids = sorted({r["session_id"] for r in rows})
        sessions = []
        for sid in session_ids:
            s = self.spool.get_session(sid)
            if s is None:
                continue
            sessions.append({
                "id": s["id"],
                "started_at": s["started_at"],
                "ended_at": s["ended_at"],
                "capture_point": json.loads(s["capture_point"]),
                "quality": json.loads(s["quality"]),
                "pcap_path": s["pcap_path"],
                "probe_version": s["probe_version"],
                "notes": s["notes"] or "",
            })
        samples = [{
            "sample_uuid": r["sample_uuid"],
            "session_id": r["session_id"],
            "capture_point_id": r["capture_point_id"],
            "sample_type": r["sample_type"],
            "ts": r["ts"],
            "payload": json.loads(r["payload"]),
        } for r in rows]
        return {"probe_version": __version__, "sessions": sessions, "samples": samples}

    def _post_with_retry(self, body: dict, result: UploadResult) -> dict:
        data = json.dumps(body, default=str).encode()
        delay = 1.0
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(
                self.url, data=data, method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.token}",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                detail = e.read().decode(errors="replace")[:300]
                if e.code in PERMANENT_STATUSES:
                    raise UploadError(f"HTTP {e.code} — will not retry: {detail}") from e
                err = f"HTTP {e.code}: {detail}"
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                err = f"network: {e}"

            if attempt == self.max_retries:
                raise UploadError(f"gave up after {attempt + 1} attempts — last error: {err}")
            result.retries += 1
            self.sleep(delay)
            delay = min(delay * 2, 60.0)       # exponential backoff, capped
        raise AssertionError("unreachable")
